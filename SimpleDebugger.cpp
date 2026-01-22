//
//  SimpleDebugger.cpp
//  SimpleDebugger
//
//  Created by Noah Martin on 10/9/24.
//

#include "SimpleDebugger.h"

#if EMG_ENABLE_MACH_APIS

#import <pthread.h>
#import <mutex>
#import <mach/mach.h>
#import <libgen.h>
#import <os/log.h>
#import <mach-o/dyld_images.h>

#include "mach_messages.h"
#include "emg_vm_protect.h"

#include <mach/exception.h>
#include <mach/arm/thread_state.h>

#define GET_PC(state) static_cast<unsigned long long>(arm_thread_state64_get_pc(state))

// Constructor mặc định - debug current process
SimpleDebugger::SimpleDebugger() 
    : targetTask(mach_task_self()), 
      isRemote(false),
      exceptionPort(MACH_PORT_NULL) {
    os_log(OS_LOG_DEFAULT, "SimpleDebugger initialized for current process");
}

// Constructor mới - debug remote process
SimpleDebugger::SimpleDebugger(mach_port_t remoteTask) 
    : targetTask(remoteTask),
      isRemote(true), 
      exceptionPort(MACH_PORT_NULL) {
    // Verify task port is valid
    pid_t pid;
    kern_return_t kr = pid_for_task(remoteTask, &pid);
    if (kr != KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "Invalid remote task port: %s", mach_error_string(kr));
        targetTask = MACH_PORT_NULL;
    } else {
        os_log(OS_LOG_DEFAULT, "SimpleDebugger initialized for remote PID: %d", pid);
    }
}

void SimpleDebugger::setTargetTask(mach_port_t task) {
    std::lock_guard<std::mutex> lock(instructionMutex);
    targetTask = task;
    isRemote = (task != mach_task_self());
    
    pid_t pid;
    if (pid_for_task(task, &pid) == KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "Target task changed to PID: %d", pid);
    }
}

mach_port_t SimpleDebugger::getTargetTask() const {
    return targetTask;
}

bool SimpleDebugger::isRemoteDebugging() const {
    return isRemote;
}

void replace_image_notifier(enum dyld_image_mode mode, uint32_t infoCount, const struct dyld_image_info info[]) { }

bool SimpleDebugger::startDebugging() {
    if (targetTask == MACH_PORT_NULL) {
        os_log(OS_LOG_DEFAULT, "Invalid target task");
        return false;
    }

    // Chỉ set dyld notifier nếu đang debug local process
    if (!isRemote) {
        struct task_dyld_info dyld_info;
        mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
        task_info(targetTask, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
        struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
        infos->notification = replace_image_notifier;
    }

    // Allocate exception port trong CURRENT process (debugger process)
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exceptionPort) != KERN_SUCCESS) {
        return false;
    }

    if (mach_port_insert_right(mach_task_self(), exceptionPort, exceptionPort, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        return false;
    }

    // Set exception ports cho TARGET process
    if (task_set_exception_ports(
        targetTask,  // ← Sử dụng targetTask thay vì mach_task_self()
        // Register for EXC_MASK_BAD_ACCESS to catch cases where a thread
        // is trying to access a page that we are in the middle of changing.
        // It temporarily has execute permissions removed so could trigger this.
        // When it is triggered we should ignore it and retry the original instruction.
        EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS,
        exceptionPort,
        EXCEPTION_DEFAULT,
        ARM_THREAD_STATE64) != KERN_SUCCESS) {
        return false;
    }

    m.lock();
    pthread_create(&serverThread, nullptr, &SimpleDebugger::exceptionServerWrapper, this);
    // Prevent returning until the server thread has started
    m.lock();
    
    pid_t pid;
    if (pid_for_task(targetTask, &pid) == KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "Debugging started for PID: %d (remote: %d)", pid, isRemote);
    }
    
    return true;
}

void SimpleDebugger::setExceptionCallback(ExceptionCallback callback) {
    exceptionCallback = std::move(callback);
}

void SimpleDebugger::setBadAccessCallback(BadAccessCallback callback) {
    badAccessCallback = std::move(callback);
}

#define ARM64_BREAK_INSTRUCTION 0xD4200000

bool SimpleDebugger::readMemory(vm_address_t address, void* buffer, vm_size_t size) {
    if (isRemote) {
        vm_size_t readSize = size;
        kern_return_t kr = vm_read_overwrite(targetTask, address, size, 
                                             (vm_address_t)buffer, &readSize);
        if (kr != KERN_SUCCESS) {
            os_log(OS_LOG_DEFAULT, "Failed to read remote memory at 0x%llx: %s", 
                   (unsigned long long)address, mach_error_string(kr));
            return false;
        }
        return readSize == size;
    } else {
        // Local process - direct memory access
        memcpy(buffer, (void*)address, size);
        return true;
    }
}

bool SimpleDebugger::writeMemory(vm_address_t address, const void* buffer, vm_size_t size) {
    if (isRemote) {
        kern_return_t kr = vm_write(targetTask, address, (vm_offset_t)buffer, size);
        if (kr != KERN_SUCCESS) {
            os_log(OS_LOG_DEFAULT, "Failed to write remote memory at 0x%llx: %s",
                   (unsigned long long)address, mach_error_string(kr));
            return false;
        }
        return true;
    } else {
        // Local process - direct memory access
        memcpy((void*)address, buffer, size);
        return true;
    }
}

void SimpleDebugger::protectPageRemote(vm_address_t address, vm_size_t size, vm_prot_t newProtection) {
    kern_return_t result = emg_vm_protect(targetTask, address, size, 0, newProtection);

    if (result != KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "error calling vm_protect on task: %s (response value: %d)",
               mach_error_string(result), result);
    }
}

bool SimpleDebugger::suspendAllThreads(thread_act_array_t* threads, mach_msg_type_number_t* thread_count) {
    if (task_threads(targetTask, threads, thread_count) != KERN_SUCCESS) {
        *thread_count = 0;
        return false;
    }
    
    thread_t myThread = mach_thread_self();
    for (mach_msg_type_number_t i = 0; i < *thread_count; i++) {
        // Không suspend current thread nếu đang debug local process
        if (!isRemote && (*threads)[i] == myThread) {
            continue;
        }
        thread_suspend((*threads)[i]);
    }
    return true;
}

void SimpleDebugger::resumeAllThreads(thread_act_array_t threads, mach_msg_type_number_t thread_count) {
    thread_t myThread = mach_thread_self();
    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        // Skip current thread nếu đang debug local process
        if (!isRemote && threads[i] == myThread) {
            continue;
        }
        thread_resume(threads[i]);
    }
    
    vm_size_t size = thread_count * sizeof(thread_t);
    vm_deallocate(mach_task_self(), (vm_address_t)threads, size);
}

uint32_t SimpleDebugger::setInstructionInternal(vm_address_t address, uint32_t newInst) {
    uint32_t instruction = 0;
    
    // Đọc instruction hiện tại
    if (!readMemory(address, &instruction, sizeof(uint32_t))) {
        os_log(OS_LOG_DEFAULT, "Failed to read instruction at 0x%llx", (unsigned long long)address);
        return 0;
    }
    
    thread_act_array_t threads;
    mach_msg_type_number_t thread_count;
    
    if (!suspendAllThreads(&threads, &thread_count)) {
        os_log(OS_LOG_DEFAULT, "Failed to suspend threads");
        return instruction;
    }
    
    // Change memory protection
    protectPageRemote(address, 1, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    
    // Write new instruction
    if (!writeMemory(address, &newInst, sizeof(uint32_t))) {
        os_log(OS_LOG_DEFAULT, "Failed to write instruction at 0x%llx", (unsigned long long)address);
    }
    
    // Restore memory protection
    protectPageRemote(address, 1, VM_PROT_READ | VM_PROT_EXECUTE);
    
    // Resume threads
    resumeAllThreads(threads, thread_count);
    
    return instruction;
}

int SimpleDebugger::hookFunction(void *originalFunc, void *newFunc) {
    uintptr_t addr = reinterpret_cast<uintptr_t>(newFunc);
    uint8_t reg = 9;
    
    for (int shift = 0; shift <= 48; shift += 16) {
        uint16_t imm16 = (addr >> shift) & 0xFFFF;

        uint32_t inst;
        if (shift == 0) {
            // First instruction: MOVZ
            inst = 0xD2800000 | (imm16 << 5) | reg;
        } else {
            // Subsequent instructions: MOVK
            uint32_t shift_enc = (shift / 16) << 21;
            inst = 0xF2800000 | shift_enc | (imm16 << 5) | reg;
        }
        setInstructionInternal((vm_address_t)originalFunc + 4 * (shift/16), inst);
    }
    
    // Branch to X9
    setInstructionInternal((vm_address_t)originalFunc + (4 * 4), 0xD61F0120);
    return 0;
}

void SimpleDebugger::setBreakpoint(vm_address_t address) {
    std::lock_guard<std::mutex> lock(instructionMutex);
    
    uint32_t instruction = setInstructionInternal(address, ARM64_BREAK_INSTRUCTION);
    originalInstruction.insert({address, instruction});
    
    os_log(OS_LOG_DEFAULT, "Breakpoint set at 0x%llx (saved instruction: 0x%x)", 
           (unsigned long long)address, instruction);
}

SimpleDebugger::~SimpleDebugger() {
    // TODO: Handle stopping the exception server
    if (exceptionPort != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), exceptionPort);
    }
}

void* SimpleDebugger::exceptionServerWrapper(void* arg) {
    return static_cast<SimpleDebugger*>(arg)->exceptionServer();
}

void* SimpleDebugger::exceptionServer() {
    MachExceptionMessage exceptionMessage = {{0}};

    os_log(OS_LOG_DEFAULT, "Exception server started");

    m.unlock();
    while (true) {
        kern_return_t kr = mach_msg(&exceptionMessage.header,
                                    MACH_RCV_MSG,
                                    0,
                                    sizeof(exceptionMessage),
                                    exceptionPort,
                                    MACH_MSG_TIMEOUT_NONE,
                                    MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            os_log(OS_LOG_DEFAULT, "Error receiving message: %s", mach_error_string(kr));
            continue;
        }
        
        mach_port_t thread = exceptionMessage.thread.name;
        arm_thread_state64_t state;
        mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;

        kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &state_count);
        if (kr != KERN_SUCCESS) {
            os_log(OS_LOG_DEFAULT, "Error getting thread state: %s", mach_error_string(kr));
            continue;
        }

        if (exceptionMessage.exception == EXC_BREAKPOINT) {
            std::lock_guard<std::mutex> lock(instructionMutex);
            
            if (exceptionCallback && originalInstruction.find(GET_PC(state)) != originalInstruction.end()) {
                exceptionCallback(thread, state, [this, thread, exceptionMessage, state, state_count](bool removeBreak) {
                    continueFromBreak(thread, removeBreak, exceptionMessage, state, state_count);
                });
            } else {
                continueFromBreak(thread, false, exceptionMessage, state, state_count);
            }
        } else {
            os_log(OS_LOG_DEFAULT, "Not breakpoint message (exception type: %d)", exceptionMessage.exception);
            if (badAccessCallback) {
                badAccessCallback(thread, state);
            }
            continueFromBreak(thread, false, exceptionMessage, state, state_count);
        }
    }

    return nullptr;
}

static void setSingleStep(thread_t thread, bool enable) {
    arm_debug_state64_t dbg = {};
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;

    kern_return_t kr = thread_get_state(thread,
                                        ARM_DEBUG_STATE64,
                                        (thread_state_t)&dbg,
                                        &count);
    if (kr != KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "Failed to get debug state: %s", mach_error_string(kr));
        return;
    }

    // MDSCR_EL1.SS is bit 0 on ARMv8 (single-step enable).
    if (enable) {
        dbg.__mdscr_el1 |= 1ULL;
        os_log(OS_LOG_DEFAULT, "Single-step enabled");
    } else {
        dbg.__mdscr_el1 &= ~1ULL;
        os_log(OS_LOG_DEFAULT, "Single-step disabled");
    }

    kr = thread_set_state(thread,
                         ARM_DEBUG_STATE64,
                         (thread_state_t)&dbg,
                         ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        os_log(OS_LOG_DEFAULT, "Failed to set debug state: %s", mach_error_string(kr));
    }
}

void SimpleDebugger::continueFromBreak(mach_port_t thread, bool removeBreak, 
                                       MachExceptionMessage exceptionMessage, 
                                       arm_thread_state64_t state, 
                                       mach_msg_type_number_t state_count) {
    auto pc = GET_PC(state);
    
    // Lock để protect originalInstruction map
    std::lock_guard<std::mutex> lock(instructionMutex);
    
    auto it = originalInstruction.find(pc);
    if (it != originalInstruction.end()) {
        // Restore original instruction
        uint32_t orig = it->second;
        setInstructionInternal(pc, orig);
        
        os_log(OS_LOG_DEFAULT, "Restored original instruction at 0x%llx: 0x%x", 
               (unsigned long long)pc, orig);

        if (removeBreak) {
            originalInstruction.erase(it);
            os_log(OS_LOG_DEFAULT, "Breakpoint removed at 0x%llx", (unsigned long long)pc);
        } else {
            // Enable single-step để execute instruction gốc
            setSingleStep(thread, true);
        }
    } else {
        // This is expected to be called on single step callback
        // Re-enable the breakpoint at previous instruction
        if (pc >= 4) {
            vm_address_t prevPC = pc - 4;
            auto prevIt = originalInstruction.find(prevPC);
            
            if (prevIt != originalInstruction.end()) {
                // Re-set breakpoint
                setInstructionInternal(prevPC, ARM64_BREAK_INSTRUCTION);
                os_log(OS_LOG_DEFAULT, "Re-enabled breakpoint at 0x%llx after single-step", 
                       (unsigned long long)prevPC);
            }
        }
        
        // Disable single step
        setSingleStep(thread, false);
    }

    // Send reply to kernel
    MachReplyMessage replyMessage = {{0}};

    replyMessage.header = exceptionMessage.header;
    replyMessage.header.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(exceptionMessage.header.msgh_bits), 0);
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
        os_log(OS_LOG_DEFAULT, "Error sending reply: %s", mach_error_string(kr));
    }
}

#endif