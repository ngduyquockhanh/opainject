//
//  SimpleDebugger.m
//  SimpleDebugger
//

#include "SimpleDebugger.h"

#if EMG_ENABLE_MACH_APIS

#import <pthread.h>
#import <mach/mach.h>
#import <os/log.h>
#import <mach-o/dyld_images.h>
#import <stdlib.h>
#import <string.h>
#import <libkern/OSCacheControl.h>

#include "mach_messages.h"
#include "emg_vm_protect.h"
#include <mach/exception.h>
#include <mach/arm/thread_state.h>
#include <mach/vm_machine_attribute.h>
#define PAGE_SIZE1 16384

// ARM64 BRK #0 instruction
// Big-endian notation: 0xD4200000
// Little-endian (iOS ARM64): 0x000020D4
#define ARM64_BREAK_INSTRUCTION 0xD4200000
#define MAX_BREAKPOINTS 256
#define GET_PC(state) ((uint64_t)arm_thread_state64_get_pc(state))

// Breakpoint entry
typedef struct {
    vm_address_t address;
    uint32_t originalInstruction;
    bool active;
} BreakpointEntry;

// SimpleDebugger structure
struct SimpleDebugger {
    mach_port_t targetTask;
    bool isRemote;
    mach_port_t exceptionPort;
    pthread_t serverThread;
    pthread_mutex_t mutex;
    pthread_mutex_t instructionMutex;
    
    // Callbacks
    ExceptionCallback exceptionCallback;
    void* exceptionContext;
    BadAccessCallback badAccessCallback;
    void* badAccessContext;
    
    // Breakpoints
    BreakpointEntry breakpoints[MAX_BREAKPOINTS];
    int breakpointCount;
    
    // For tracking single-step
    vm_address_t lastBreakpointPC;
};

// Forward declarations
static void* exceptionServerWrapper(void* arg);
static void* exceptionServer(SimpleDebugger* debugger);
static void continueFromBreak(SimpleDebugger* debugger,
                             mach_port_t thread, 
                             bool removeBreak,
                             MachExceptionMessage exceptionMessage, 
                             arm_thread_state64_t state, 
                             mach_msg_type_number_t state_count);
static uint32_t setInstructionInternal(SimpleDebugger* debugger,
                                       vm_address_t address, 
                                       uint32_t newInst);
static void protectPageRemote(SimpleDebugger* debugger,
                             vm_address_t address, 
                             vm_size_t size, 
                             vm_prot_t newProtection);
static bool suspendAllThreads(SimpleDebugger* debugger,
                             thread_act_array_t* threads, 
                             mach_msg_type_number_t* thread_count);
static void resumeAllThreads(SimpleDebugger* debugger,
                            thread_act_array_t threads, 
                            mach_msg_type_number_t thread_count);
static void setSingleStep(thread_t thread, bool enable);
static BreakpointEntry* findBreakpoint(SimpleDebugger* debugger, vm_address_t address);
static int findBreakpointIndex(SimpleDebugger* debugger, vm_address_t address);

// Constructor - local process
SimpleDebugger* SimpleDebugger_create(void) {
    return SimpleDebugger_createWithTask(mach_task_self());
}

// Constructor - remote process
SimpleDebugger* SimpleDebugger_createWithTask(mach_port_t remoteTask) {
    SimpleDebugger* debugger = (SimpleDebugger*)calloc(1, sizeof(SimpleDebugger));
    if (!debugger) return NULL;
    
    debugger->targetTask = remoteTask;
    debugger->isRemote = (remoteTask != mach_task_self());
    debugger->exceptionPort = MACH_PORT_NULL;
    debugger->lastBreakpointPC = 0;
    
    pthread_mutex_init(&debugger->mutex, NULL);
    pthread_mutex_init(&debugger->instructionMutex, NULL);
    
    // Verify task port
    pid_t pid;
    kern_return_t kr = pid_for_task(remoteTask, &pid);
    if (kr != KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Invalid remote task port: %s", 
               mach_error_string(kr));
        debugger->targetTask = MACH_PORT_NULL;
    } else {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Initialized for PID: %d (remote: %d)", 
               pid, debugger->isRemote);
    }
    
    return debugger;
}

// Destructor
void SimpleDebugger_destroy(SimpleDebugger* debugger) {
    if (!debugger) return;
    
    if (debugger->exceptionPort != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), debugger->exceptionPort);
    }
    
    pthread_mutex_destroy(&debugger->mutex);
    pthread_mutex_destroy(&debugger->instructionMutex);
    
    free(debugger);
}

// Setters/Getters
void SimpleDebugger_setTargetTask(SimpleDebugger* debugger, mach_port_t task) {
    if (!debugger) return;
    
    pthread_mutex_lock(&debugger->instructionMutex);
    debugger->targetTask = task;
    debugger->isRemote = (task != mach_task_self());
    pthread_mutex_unlock(&debugger->instructionMutex);
    
    pid_t pid;
    if (pid_for_task(task, &pid) == KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Target task changed to PID: %d", pid);
    }
}

mach_port_t SimpleDebugger_getTargetTask(SimpleDebugger* debugger) {
    return debugger ? debugger->targetTask : MACH_PORT_NULL;
}

bool SimpleDebugger_isRemoteDebugging(SimpleDebugger* debugger) {
    return debugger ? debugger->isRemote : false;
}

// Start debugging
bool SimpleDebugger_startDebugging(SimpleDebugger* debugger) {
    if (!debugger || debugger->targetTask == MACH_PORT_NULL) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Invalid debugger or target task");
        return false;
    }
    
    // Allocate exception port
    kern_return_t kr = mach_port_allocate(mach_task_self(), 
                                         MACH_PORT_RIGHT_RECEIVE, 
                                         &debugger->exceptionPort);
    if (kr != KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Failed to allocate exception port: %s", 
               mach_error_string(kr));
        return false;
    }
    
    kr = mach_port_insert_right(mach_task_self(), 
                               debugger->exceptionPort, 
                               debugger->exceptionPort, 
                               MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Failed to insert right: %s", 
               mach_error_string(kr));
        return false;
    }
    
    // Set exception ports on target task
    kr = task_set_exception_ports(
        debugger->targetTask,
        EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS,
        debugger->exceptionPort,
        EXCEPTION_DEFAULT,
        ARM_THREAD_STATE64);
    
    if (kr != KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Failed to set exception ports: %s", 
               mach_error_string(kr));
        return false;
    }
    
    // Start exception server thread
    pthread_mutex_lock(&debugger->mutex);
    pthread_create(&debugger->serverThread, NULL, exceptionServerWrapper, debugger);
    pthread_mutex_lock(&debugger->mutex); // Wait for server to start
    
    pid_t pid;
    if (pid_for_task(debugger->targetTask, &pid) == KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Debugging started for PID: %d", pid);
    }
    
    return true;
}

// Set callbacks
void SimpleDebugger_setExceptionCallback(SimpleDebugger* debugger, 
                                         ExceptionCallback callback,
                                         void* context) {
    if (!debugger) return;
    debugger->exceptionCallback = callback;
    debugger->exceptionContext = context;
}

void SimpleDebugger_setBadAccessCallback(SimpleDebugger* debugger,
                                         BadAccessCallback callback,
                                         void* context) {
    if (!debugger) return;
    debugger->badAccessCallback = callback;
    debugger->badAccessContext = context;
}

// Memory operations
bool SimpleDebugger_readMemory(SimpleDebugger* debugger,
                               vm_address_t address, 
                               void* buffer, 
                               vm_size_t size) {
    if (!debugger) return false;
    
    if (debugger->isRemote) {
        vm_size_t readSize = size;
        kern_return_t kr = vm_read_overwrite(debugger->targetTask, 
                                            address, 
                                            size, 
                                            (vm_address_t)buffer, 
                                            &readSize);
        if (kr != KERN_SUCCESS) {
            os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Failed to read remote memory at 0x%llx: %s", 
                   (unsigned long long)address, mach_error_string(kr));
            return false;
        }
        return readSize == size;
    } else {
        memcpy(buffer, (void*)address, size);
        return true;
    }
}

bool SimpleDebugger_writeMemory(SimpleDebugger* debugger,
                                vm_address_t address, 
                                const void* buffer, 
                                vm_size_t size) {
    if (!debugger) return false;
    
    if (debugger->isRemote) {
        kern_return_t kr = vm_write(debugger->targetTask, 
                                   address, 
                                   (vm_offset_t)buffer, 
                                   size);
        if (kr != KERN_SUCCESS) {
            os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Failed to write remote memory at 0x%llx: %s",
                   (unsigned long long)address, mach_error_string(kr));
            return false;
        }
        return true;
    } else {
        memcpy((void*)address, buffer, size);
        return true;
    }
}

// Set breakpoint
void SimpleDebugger_setBreakpoint(SimpleDebugger* debugger, vm_address_t address) {
    if (!debugger) return;
    
    pthread_mutex_lock(&debugger->instructionMutex);
    
    // Check if already exists
    if (findBreakpoint(debugger, address) != NULL) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Breakpoint already exists at 0x%llx", 
               (unsigned long long)address);
        pthread_mutex_unlock(&debugger->instructionMutex);
        return;
    }
    
    if (debugger->breakpointCount >= MAX_BREAKPOINTS) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Maximum breakpoints reached");
        pthread_mutex_unlock(&debugger->instructionMutex);
        return;
    }
    
    uint32_t instruction = setInstructionInternal(debugger, address, ARM64_BREAK_INSTRUCTION);
    
    debugger->breakpoints[debugger->breakpointCount].address = address;
    debugger->breakpoints[debugger->breakpointCount].originalInstruction = instruction;
    debugger->breakpoints[debugger->breakpointCount].active = true;
    debugger->breakpointCount++;
    
    os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Breakpoint set at 0x%llx (original instruction: 0x%x)", 
           (unsigned long long)address, instruction);
    os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Writing breakpoint instruction 0x%x at 0x%llx", 
           ARM64_BREAK_INSTRUCTION, (unsigned long long)address);
    
    // Verify breakpoint was written correctly
    uint32_t verifyInst = 0;
    if (SimpleDebugger_readMemory(debugger, address, &verifyInst, sizeof(uint32_t))) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Verified breakpoint at 0x%llx: 0x%x (expected 0x%x)", 
               (unsigned long long)address, verifyInst, ARM64_BREAK_INSTRUCTION);
    } else {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] FAILED to verify breakpoint at 0x%llx", 
               (unsigned long long)address);
    }
    
    // Disassemble the original instruction
    os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Original instruction at 0x%llx was: 0x%x", 
           (unsigned long long)address, instruction);
    // Instruction 0xd503237f analysis:
    // High byte 0xd5 = hints/barriers/sync ops group
    // Exact meaning depends on full decoding
    
    pthread_mutex_unlock(&debugger->instructionMutex);
}

// Remove breakpoint
void SimpleDebugger_removeBreakpoint(SimpleDebugger* debugger, vm_address_t address) {
    if (!debugger) return;
    
    pthread_mutex_lock(&debugger->instructionMutex);
    
    int index = findBreakpointIndex(debugger, address);
    if (index >= 0) {
        // Restore original instruction
        setInstructionInternal(debugger, address, 
                             debugger->breakpoints[index].originalInstruction);
        
        // Mark as inactive
        debugger->breakpoints[index].active = false;
        
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Breakpoint removed at 0x%llx", 
               (unsigned long long)address);
    }
    
    pthread_mutex_unlock(&debugger->instructionMutex);
}

// Function hooking
int SimpleDebugger_hookFunction(SimpleDebugger* debugger,
                                void* originalFunc, 
                                void* newFunc) {
    if (!debugger) return -1;
    
    uintptr_t addr = (uintptr_t)newFunc;
    uint8_t reg = 9;
    
    for (int shift = 0; shift <= 48; shift += 16) {
        uint16_t imm16 = (addr >> shift) & 0xFFFF;
        
        uint32_t inst;
        if (shift == 0) {
            inst = 0xD2800000 | (imm16 << 5) | reg;
        } else {
            uint32_t shift_enc = (shift / 16) << 21;
            inst = 0xF2800000 | shift_enc | (imm16 << 5) | reg;
        }
        setInstructionInternal(debugger, (vm_address_t)originalFunc + 4 * (shift/16), inst);
    }
    
    setInstructionInternal(debugger, (vm_address_t)originalFunc + (4 * 4), 0xD61F0120);
    return 0;
}

// Helper: Find breakpoint
static BreakpointEntry* findBreakpoint(SimpleDebugger* debugger, vm_address_t address) {
    for (int i = 0; i < debugger->breakpointCount; i++) {
        if (debugger->breakpoints[i].address == address && 
            debugger->breakpoints[i].active) {
            return &debugger->breakpoints[i];
        }
    }
    return NULL;
}

static int findBreakpointIndex(SimpleDebugger* debugger, vm_address_t address) {
    for (int i = 0; i < debugger->breakpointCount; i++) {
        if (debugger->breakpoints[i].address == address && 
            debugger->breakpoints[i].active) {
            return i;
        }
    }
    return -1;
}

// Helper: Suspend all threads
static bool suspendAllThreads(SimpleDebugger* debugger,
                             thread_act_array_t* threads, 
                             mach_msg_type_number_t* thread_count) {
    if (task_threads(debugger->targetTask, threads, thread_count) != KERN_SUCCESS) {
        *thread_count = 0;
        return false;
    }
    
    thread_t myThread = mach_thread_self();
    for (mach_msg_type_number_t i = 0; i < *thread_count; i++) {
        if (!debugger->isRemote && (*threads)[i] == myThread) {
            continue;
        }
        thread_suspend((*threads)[i]);
    }
    return true;
}

// Helper: Resume all threads
static void resumeAllThreads(SimpleDebugger* debugger,
                            thread_act_array_t threads, 
                            mach_msg_type_number_t thread_count) {
    thread_t myThread = mach_thread_self();
    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        if (!debugger->isRemote && threads[i] == myThread) {
            continue;
        }
        thread_resume(threads[i]);
    }
    
    vm_size_t size = thread_count * sizeof(thread_t);
    vm_deallocate(mach_task_self(), (vm_address_t)threads, size);
}

// Helper: Protect page
static void protectPageRemote(SimpleDebugger* debugger,
                             vm_address_t address, 
                             vm_size_t size, 
                             vm_prot_t newProtection) {
    kern_return_t result = vm_protect(debugger->targetTask, address, size, 0, newProtection);
    
    if (result != KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] error calling vm_protect: %s", 
               mach_error_string(result));
    }
}

// Helper: Set instruction
static uint32_t setInstructionInternal(SimpleDebugger* debugger,
                                       vm_address_t address, 
                                       uint32_t newInst) {
    uint32_t instruction = 0;
    
    if (!SimpleDebugger_readMemory(debugger, address, &instruction, sizeof(uint32_t))) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Failed to read instruction at 0x%llx", 
               (unsigned long long)address);
        return 0;
    }
    
    vm_address_t page_addr = address & ~(PAGE_SIZE1 - 1);

    thread_act_array_t threads;
    mach_msg_type_number_t thread_count;
    
    if (!suspendAllThreads(debugger, &threads, &thread_count)) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Failed to suspend threads");
        return instruction;
    }
    
    protectPageRemote(debugger, address, 1, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    
    if (!SimpleDebugger_writeMemory(debugger, address, &newInst, sizeof(uint32_t))) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Failed to write instruction at 0x%llx", 
               (unsigned long long)address);
    }
    
    // Synchronize instruction cache after modifying code
    if (debugger->isRemote) {
        kern_return_t kr = vm_protect(debugger->targetTask, page_addr, PAGE_SIZE1, 
                                     FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
        if (kr != KERN_SUCCESS) {
            os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Failed to flush remote cache: %s", 
                   mach_error_string(kr));
        }
        
        // Additional flush attempt via protection toggle
        vm_protect(debugger->targetTask, page_addr, PAGE_SIZE1, 
                  FALSE, VM_PROT_NONE);
        vm_protect(debugger->targetTask, page_addr, PAGE_SIZE1, 
                  FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

        vm_machine_attribute(
            debugger->targetTask,
            page_addr,
            PAGE_SIZE,
            MATTR_CACHE,
            MATTR_VAL_CACHE_FLUSH
        );
         
        
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Cache flushed for remote process at 0x%llx", 
               (unsigned long long)address);
    } else {
        // For local process, invalidate instruction cache
        sys_icache_invalidate((void*)address, sizeof(uint32_t));
    }
    
    protectPageRemote(debugger, address, 1, VM_PROT_READ | VM_PROT_EXECUTE);
    
    resumeAllThreads(debugger, threads, thread_count);
    
    return instruction;
}

// Helper: Single step
static void setSingleStep(thread_t thread, bool enable) {
    arm_debug_state64_t dbg = {0};
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    
    kern_return_t kr = thread_get_state(thread,
                                       ARM_DEBUG_STATE64,
                                       (thread_state_t)&dbg,
                                       &count);
    if (kr != KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Failed to get debug state: %s", 
               mach_error_string(kr));
        return;
    }
    
    if (enable) {
        dbg.__mdscr_el1 |= 1ULL;
    } else {
        dbg.__mdscr_el1 &= ~1ULL;
    }
    
    kr = thread_set_state(thread,
                         ARM_DEBUG_STATE64,
                         (thread_state_t)&dbg,
                         ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Failed to set debug state: %s", 
               mach_error_string(kr));
    }
}

// Exception server wrapper
static void* exceptionServerWrapper(void* arg) {
    return exceptionServer((SimpleDebugger*)arg);
}

// Exception server
static void* exceptionServer(SimpleDebugger* debugger) {
    MachExceptionMessage exceptionMessage = {{0}};
    
    os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Exception server started");
    
    pthread_mutex_unlock(&debugger->mutex);
    
    while (true) {
        kern_return_t kr = mach_msg(&exceptionMessage.header,
                                   MACH_RCV_MSG,
                                   0,
                                   sizeof(exceptionMessage),
                                   debugger->exceptionPort,
                                   MACH_MSG_TIMEOUT_NONE,
                                   MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Error receiving message: %s", 
                   mach_error_string(kr));
            continue;
        }

        
        mach_port_t thread = exceptionMessage.thread.name;
        arm_thread_state64_t state;
        mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
        
        kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &state_count);
        if (kr != KERN_SUCCESS) {
            os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Error getting thread state: %s", 
                   mach_error_string(kr));
            continue;
        }
        
        vm_address_t pc = GET_PC(state);
        uint32_t instAtPC = 0;
        if (SimpleDebugger_readMemory(debugger, pc, &instAtPC, sizeof(uint32_t))) {
            os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Instruction at PC 0x%llx: 0x%x", 
                (unsigned long long)pc, instAtPC);
        }

        // DEBUG: Check breakpoint address
        if (debugger->breakpointCount > 0) {
            os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Breakpoint set at: 0x%llx", 
                (unsigned long long)debugger->breakpoints[0].address);
        }

        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Exception received: type %d at PC 0x%llx code[0]=0x%llx",
            exceptionMessage.exception,
            (unsigned long long)pc,
            (unsigned long long)exceptionMessage.code[0]);
        

        if (exceptionMessage.exception == EXC_BREAKPOINT) {
            os_log(OS_LOG_DEFAULT, "[SimpleDebugger] EXC_BREAKPOINT detected!");
            pthread_mutex_lock(&debugger->instructionMutex);
            
            BreakpointEntry* bp = findBreakpoint(debugger, pc);
            
            if (bp) {
                os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Breakpoint found at 0x%llx", (unsigned long long)pc);
                if (debugger->exceptionCallback) {
                    os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Calling exception callback");
                    bool removeBreak = false;
                    debugger->exceptionCallback(debugger->exceptionContext, 
                                              thread, state, &removeBreak);
                    continueFromBreak(debugger, thread, removeBreak, 
                                    exceptionMessage, state, state_count);
                } else {
                    os_log(OS_LOG_DEFAULT, "[SimpleDebugger] No exception callback set");
                    continueFromBreak(debugger, thread, false, 
                                    exceptionMessage, state, state_count);
                }
            } else {
                os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Breakpoint NOT found at PC 0x%llx", (unsigned long long)pc);
                continueFromBreak(debugger, thread, false, 
                                exceptionMessage, state, state_count);
            }
            
            pthread_mutex_unlock(&debugger->instructionMutex);
        } else {
            os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Non-breakpoint exception (type: %d) at PC 0x%llx", 
                   exceptionMessage.exception, (unsigned long long)pc);
            if (debugger->badAccessCallback) {
                debugger->badAccessCallback(debugger->badAccessContext, thread, state);
            }
            continueFromBreak(debugger, thread, false, 
                            exceptionMessage, state, state_count);
        }
    }
    
    return NULL;
}

// Continue from break
static void continueFromBreak(SimpleDebugger* debugger,
                             mach_port_t thread, 
                             bool removeBreak,
                             MachExceptionMessage exceptionMessage, 
                             arm_thread_state64_t state, 
                             mach_msg_type_number_t state_count) {
    vm_address_t pc = GET_PC(state);
    
    BreakpointEntry* bp = findBreakpoint(debugger, pc);
    if (bp) {
        // Hit a breakpoint - restore original instruction
        uint32_t orig = bp->originalInstruction;
        setInstructionInternal(debugger, pc, orig);
        
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Restored original instruction at 0x%llx: 0x%x", 
               (unsigned long long)pc, orig);
        
        if (removeBreak) {
            bp->active = false;
            os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Breakpoint removed at 0x%llx", 
                   (unsigned long long)pc);
        } else {
            // Save this PC and enable single-step
            debugger->lastBreakpointPC = pc;
            setSingleStep(thread, true);
        }
    } else {
        // This is single-step callback - re-enable the breakpoint
        if (debugger->lastBreakpointPC != 0) {
            BreakpointEntry* prevBp = findBreakpoint(debugger, debugger->lastBreakpointPC);
            
            if (prevBp) {
                setInstructionInternal(debugger, debugger->lastBreakpointPC, 
                                     ARM64_BREAK_INSTRUCTION);
                os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Re-enabled breakpoint at 0x%llx", 
                       (unsigned long long)debugger->lastBreakpointPC);
            }
            
            debugger->lastBreakpointPC = 0;
        }
        
        setSingleStep(thread, false);
    }
    
    // Send reply to kernel
    MachReplyMessage replyMessage = {{0}};
    replyMessage.header = exceptionMessage.header;
    replyMessage.header.msgh_bits = MACH_MSGH_BITS(
        MACH_MSGH_BITS_REMOTE(exceptionMessage.header.msgh_bits), 0);
    replyMessage.header.msgh_local_port = MACH_PORT_NULL;
    replyMessage.header.msgh_size = sizeof(replyMessage);
    replyMessage.NDR = exceptionMessage.NDR;
    replyMessage.returnCode = KERN_SUCCESS;
    replyMessage.header.msgh_id = exceptionMessage.header.msgh_id + 100;
    
    kern_return_t kr = mach_msg(&replyMessage.header,
                               MACH_SEND_MSG,
                               sizeof(replyMessage),
                               0,
                               MACH_PORT_NULL,
                               MACH_MSG_TIMEOUT_NONE,
                               MACH_PORT_NULL);
    
    if (kr != KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "[SimpleDebugger] Error sending reply: %s", 
               mach_error_string(kr));
    }
}

#endif // EMG_ENABLE_MACH_APIS