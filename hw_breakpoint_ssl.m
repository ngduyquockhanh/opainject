/*
 * Hardware Breakpoint-based SSL_write Interceptor
 * 
 * This implementation uses ARM64 hardware debug registers to set breakpoints
 * on SSL_write without modifying any code, avoiding instruction cache issues.
 * 
 * Technique:
 * 1. Set hardware breakpoint using ARM_DEBUG_STATE64
 * 2. Install Mach exception handler for EXC_BREAKPOINT
 * 3. When breakpoint hits, read x1 (buffer) and x2 (size)
 * 4. Dump plaintext SSL data
 * 5. Advance PC by 4 bytes and resume execution
 */

#include "hw_breakpoint_ssl.h"
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Global state for exception handling
static task_t g_target_task = MACH_PORT_NULL;
static mach_port_t g_exception_port = MACH_PORT_NULL;
static pthread_t g_exception_thread;
static bool g_running = false;
static uint64_t g_ssl_write_breakpoint_addr = 0;

// Maximum buffer size to dump (prevent huge allocations)
#define MAX_DUMP_SIZE 16384

// =============================================================================
// MARK: - Helper Functions
// =============================================================================

// Dump buffer contents as hex + ASCII
static void dump_buffer(const uint8_t* buffer, size_t size) {
    printf("\n=== SSL_write Plaintext Data (%zu bytes) ===\n", size);
    
    size_t dump_size = (size > MAX_DUMP_SIZE) ? MAX_DUMP_SIZE : size;
    
    for (size_t i = 0; i < dump_size; i += 16) {
        // Hex dump
        printf("%04zx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < dump_size) {
                printf("%02x ", buffer[i + j]);
            } else {
                printf("   ");
            }
        }
        
        printf(" | ");
        
        // ASCII dump
        for (size_t j = 0; j < 16; j++) {
            if (i + j < dump_size) {
                uint8_t c = buffer[i + j];
                printf("%c", (c >= 32 && c < 127) ? c : '.');
            }
        }
        printf("\n");
    }
    
    if (size > MAX_DUMP_SIZE) {
        printf("... (%zu more bytes truncated)\n", size - MAX_DUMP_SIZE);
    }
    printf("===========================================\n\n");
    fflush(stdout);
}

// Set hardware breakpoint on a thread
static kern_return_t set_hardware_breakpoint(thread_act_t thread, uint64_t address) {
    arm_debug_state64_t debug_state;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    
    // Get current debug state
    kern_return_t kr = thread_get_state(thread, ARM_DEBUG_STATE64,
                                        (thread_state_t)&debug_state, &count);
    if (kr != KERN_SUCCESS) {
        printf("[ERROR] Failed to get debug state: %s\n", mach_error_string(kr));
        return kr;
    }
    
    // Configure hardware breakpoint (BRP0 - Breakpoint Register Pair 0)
    // BCR = Breakpoint Control Register
    // BVR = Breakpoint Value Register
    
    // Enable breakpoint 0
    debug_state.__bvr[0] = address;  // Breakpoint address
    
    // BCR configuration:
    // Bit 0: Enable (1)
    // Bits 1-2: PMC (Privilege Mode Control) = 11b (any mode)
    // Bits 5-8: BAS (Byte Address Select) = 1111b (match all 4 bytes)
    // Bits 20-21: BT (Breakpoint Type) = 00b (unlinked instruction address match)
    debug_state.__bcr[0] = 0x1E5; // 0b111100101 = enabled, all bytes, any mode
    
    // Set the debug state
    kr = thread_set_state(thread, ARM_DEBUG_STATE64,
                         (thread_state_t)&debug_state, ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("[ERROR] Failed to set debug state: %s\n", mach_error_string(kr));
        return kr;
    }
    
    printf("[+] Hardware breakpoint set on thread 0x%x at address 0x%llx\n",
           thread, address);
    
    return KERN_SUCCESS;
}

// Clear hardware breakpoint on a thread
static kern_return_t clear_hardware_breakpoint(thread_act_t thread) {
    arm_debug_state64_t debug_state;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    
    kern_return_t kr = thread_get_state(thread, ARM_DEBUG_STATE64,
                                        (thread_state_t)&debug_state, &count);
    if (kr != KERN_SUCCESS) {
        return kr;
    }
    
    // Disable breakpoint 0
    debug_state.__bcr[0] = 0;  // Disable
    debug_state.__bvr[0] = 0;
    
    kr = thread_set_state(thread, ARM_DEBUG_STATE64,
                         (thread_state_t)&debug_state, ARM_DEBUG_STATE64_COUNT);
    
    return kr;
}

// =============================================================================
// MARK: - Exception Handler
// =============================================================================

// Handle breakpoint exceptions
static void handle_breakpoint_exception(
    thread_act_t thread,
    exception_type_t exception,
    mach_exception_data_t code_data,
    mach_msg_type_number_t code_count
) {
    kern_return_t kr;
    
    // Get thread state to read registers
    arm_thread_state64_t thread_state;
    mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
    
    kr = thread_get_state(thread, ARM_THREAD_STATE64,
                         (thread_state_t)&thread_state, &state_count);
    if (kr != KERN_SUCCESS) {
        printf("[ERROR] Failed to get thread state: %s\n", mach_error_string(kr));
        return;
    }
    
    uint64_t pc = __darwin_arm_thread_state64_get_pc(thread_state);
    
    // Verify this is our SSL_write breakpoint
    if (pc != g_ssl_write_breakpoint_addr) {
        printf("[INFO] Breakpoint at 0x%llx (not our target, skipping)\n", pc);
        // Advance PC and continue
        __darwin_arm_thread_state64_set_pc_fptr(thread_state, (void*)(pc + 4));
        thread_set_state(thread, ARM_THREAD_STATE64,
                        (thread_state_t)&thread_state, ARM_THREAD_STATE64_COUNT);
        return;
    }
    
    // Extract SSL_write arguments from ARM64 registers
    // x0 = SSL* (SSL context)
    // x1 = const void *buf (plaintext buffer)
    // x2 = int len (buffer size)
    
    uint64_t ssl_ptr = thread_state.__x[0];
    uint64_t buf_ptr = thread_state.__x[1];
    uint64_t buf_len = thread_state.__x[2];
    
    printf("\n[BREAKPOINT HIT] SSL_write called!\n");
    printf("  PC:  0x%llx\n", pc);
    printf("  X0 (SSL*):     0x%llx\n", ssl_ptr);
    printf("  X1 (buf*):     0x%llx\n", buf_ptr);
    printf("  X2 (len):      %llu\n", buf_len);
    
    // Read buffer contents from remote process
    if (buf_ptr && buf_len > 0 && buf_len < 1024 * 1024) {  // Sanity check
        size_t read_size = (buf_len > MAX_DUMP_SIZE) ? MAX_DUMP_SIZE : buf_len;
        uint8_t* buffer = malloc(read_size);
        
        if (buffer) {
            vm_size_t bytes_read = 0;
            kr = vm_read_overwrite(g_target_task, buf_ptr, read_size,
                                  (vm_address_t)buffer, &bytes_read);
            
            if (kr == KERN_SUCCESS && bytes_read > 0) {
                dump_buffer(buffer, bytes_read);
            } else {
                printf("[ERROR] Failed to read buffer: %s\n", mach_error_string(kr));
            }
            
            free(buffer);
        }
    } else {
        printf("[WARNING] Invalid buffer pointer or size\n");
    }
    
    // Advance PC by 4 bytes to skip the breakpoint instruction
    // This allows execution to continue normally
    __darwin_arm_thread_state64_set_pc_fptr(thread_state, (void*)(pc + 4));
    
    // Update thread state
    kr = thread_set_state(thread, ARM_THREAD_STATE64,
                         (thread_state_t)&thread_state, ARM_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("[ERROR] Failed to update thread state: %s\n", mach_error_string(kr));
    }
    
    printf("[+] Resuming execution at 0x%llx\n", pc + 4);
}

// Exception handler thread main loop
static void* exception_handler_thread(void* arg) {
    kern_return_t kr;
    
    printf("[+] Exception handler thread started\n");
    
    while (g_running) {
        // Receive exception message
        struct {
            mach_msg_header_t head;
            mach_msg_body_t msgh_body;
            mach_msg_port_descriptor_t thread;
            mach_msg_port_descriptor_t task;
            NDR_record_t NDR;
            exception_type_t exception;
            mach_msg_type_number_t code_count;
            int64_t code[2];
            int flavor;
            mach_msg_type_number_t old_state_count;
            natural_t old_state[ARM_THREAD_STATE64_COUNT];
        } msg;
        
        kr = mach_msg(&msg.head,
                     MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT,
                     0,
                     sizeof(msg),
                     g_exception_port,
                     100,  // 100ms timeout
                     MACH_PORT_NULL);
        
        if (kr == MACH_RCV_TIMED_OUT) {
            continue;  // Normal timeout, continue loop
        }
        
        if (kr != KERN_SUCCESS) {
            if (g_running) {
                printf("[ERROR] mach_msg receive failed: %s\n", mach_error_string(kr));
            }
            continue;
        }
        
        // Extract exception information
        thread_act_t thread = msg.thread.name;
        exception_type_t exception = msg.exception;
        
        printf("\n[EXCEPTION] Type: %d, Thread: 0x%x\n", exception, thread);
        
        // Handle the exception
        if (exception == EXC_BREAKPOINT) {
            handle_breakpoint_exception(thread, exception,
                                       (mach_exception_data_t)msg.code,
                                       msg.code_count);
        }
        
        // Send reply to resume thread
        struct {
            mach_msg_header_t head;
            NDR_record_t NDR;
            kern_return_t ret_code;
            int flavor;
            mach_msg_type_number_t new_state_count;
            natural_t new_state[ARM_THREAD_STATE64_COUNT];
        } reply;
        
        reply.head = msg.head;
        reply.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(msg.head.msgh_bits), 0);
        reply.head.msgh_size = sizeof(reply);
        reply.head.msgh_remote_port = msg.head.msgh_remote_port;
        reply.head.msgh_local_port = MACH_PORT_NULL;
        reply.head.msgh_id = msg.head.msgh_id + 100;
        
        reply.NDR = NDR_record;
        reply.ret_code = KERN_SUCCESS;
        reply.flavor = ARM_THREAD_STATE64;
        reply.new_state_count = ARM_THREAD_STATE64_COUNT;
        
        // Get updated thread state
        mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
        thread_get_state(thread, ARM_THREAD_STATE64,
                        (thread_state_t)reply.new_state, &state_count);
        
        kr = mach_msg(&reply.head,
                     MACH_SEND_MSG,
                     reply.head.msgh_size,
                     0,
                     MACH_PORT_NULL,
                     MACH_MSG_TIMEOUT_NONE,
                     MACH_PORT_NULL);
        
        if (kr != KERN_SUCCESS) {
            printf("[ERROR] Failed to send reply: %s\n", mach_error_string(kr));
        }
    }
    
    printf("[+] Exception handler thread exiting\n");
    return NULL;
}

// =============================================================================
// MARK: - Public API
// =============================================================================

kern_return_t init_ssl_breakpoint_hook(task_t task, uint64_t ssl_write_addr) {
    kern_return_t kr;
    
    g_target_task = task;
    g_ssl_write_breakpoint_addr = ssl_write_addr + 0x1C;  // Offset after prologue
    
    printf("[+] Initializing SSL_write breakpoint hook\n");
    printf("    Target task: 0x%x\n", task);
    printf("    SSL_write address: 0x%llx\n", ssl_write_addr);
    printf("    Breakpoint address: 0x%llx\n", g_ssl_write_breakpoint_addr);
    
    // Allocate exception port
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                           &g_exception_port);
    if (kr != KERN_SUCCESS) {
        printf("[ERROR] Failed to allocate exception port: %s\n",
               mach_error_string(kr));
        return kr;
    }
    
    // Add send right to exception port
    kr = mach_port_insert_right(mach_task_self(), g_exception_port,
                                g_exception_port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        printf("[ERROR] Failed to insert right: %s\n", mach_error_string(kr));
        return kr;
    }
    
    // Set exception port for target task
    kr = task_set_exception_ports(
        task,
        EXC_MASK_BREAKPOINT,
        g_exception_port,
        EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
        ARM_THREAD_STATE64
    );
    
    if (kr != KERN_SUCCESS) {
        printf("[ERROR] Failed to set exception ports: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), g_exception_port);
        return kr;
    }
    
    printf("[+] Exception port configured\n");
    
    // Set hardware breakpoint on all existing threads
    thread_act_array_t thread_list;
    mach_msg_type_number_t thread_count;
    
    kr = task_threads(task, &thread_list, &thread_count);
    if (kr == KERN_SUCCESS) {
        printf("[+] Setting breakpoints on %d existing threads\n", thread_count);
        
        for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
            set_hardware_breakpoint(thread_list[i], g_ssl_write_breakpoint_addr);
            mach_port_deallocate(mach_task_self(), thread_list[i]);
        }
        
        vm_deallocate(mach_task_self(), (vm_offset_t)thread_list,
                     thread_count * sizeof(thread_act_t));
    }
    
    // Start exception handler thread
    g_running = true;
    if (pthread_create(&g_exception_thread, NULL, exception_handler_thread, NULL) != 0) {
        printf("[ERROR] Failed to create exception handler thread\n");
        g_running = false;
        return KERN_FAILURE;
    }
    
    printf("[+] SSL_write breakpoint hook initialized successfully\n");
    printf("[+] Waiting for SSL_write calls...\n\n");
    
    return KERN_SUCCESS;
}

void cleanup_ssl_breakpoint_hook(void) {
    if (!g_running) {
        return;
    }
    
    printf("\n[+] Cleaning up breakpoint hook\n");
    
    g_running = false;
    
    // Wait for exception handler thread to exit
    pthread_join(g_exception_thread, NULL);
    
    // Clear breakpoints on all threads
    if (g_target_task != MACH_PORT_NULL) {
        thread_act_array_t thread_list;
        mach_msg_type_number_t thread_count;
        
        if (task_threads(g_target_task, &thread_list, &thread_count) == KERN_SUCCESS) {
            for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
                clear_hardware_breakpoint(thread_list[i]);
                mach_port_deallocate(mach_task_self(), thread_list[i]);
            }
            
            vm_deallocate(mach_task_self(), (vm_offset_t)thread_list,
                         thread_count * sizeof(thread_act_t));
        }
    }
    
    // Cleanup exception port
    if (g_exception_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), g_exception_port);
        g_exception_port = MACH_PORT_NULL;
    }
    
    printf("[+] Cleanup complete\n");
}
