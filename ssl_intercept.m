/*
 * SSL Interception using SimpleDebugger
 * 
 * This uses SimpleDebugger's hardware breakpoint functionality to intercept
 * SSL_write calls and dump plaintext data without modifying any code.
 */

#include "ssl_intercept.h"
#include "SimpleDebugger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>

// Define ContinueCallback as a function pointer type
typedef void (*ContinueCallback)(bool shouldRemoveBreakpoint);

static SimpleDebugger* g_debugger = NULL;
static task_t g_target_task = MACH_PORT_NULL;
static uint64_t g_ssl_write_addr = 0;

#define MAX_DUMP_SIZE 16384

// Dump buffer contents as hex + ASCII
static void dump_ssl_buffer(const uint8_t* buffer, size_t size) {
    printf("\n╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║ SSL_write Plaintext Data (%zu bytes)                                 \n", size);
    printf("╠═══════════════════════════════════════════════════════════════════════╣\n");
    
    size_t dump_size = (size > MAX_DUMP_SIZE) ? MAX_DUMP_SIZE : size;
    
    for (size_t i = 0; i < dump_size; i += 16) {
        printf("║ %04zx: ", i);
        
        // Hex dump
        for (size_t j = 0; j < 16; j++) {
            if (i + j < dump_size) {
                printf("%02x ", buffer[i + j]);
            } else {
                printf("   ");
            }
        }
        
        printf(" │ ");
        
        // ASCII dump
        for (size_t j = 0; j < 16; j++) {
            if (i + j < dump_size) {
                uint8_t c = buffer[i + j];
                printf("%c", (c >= 32 && c < 127) ? c : '.');
            } else {
                printf(" ");
            }
        }
        printf(" ║\n");
    }
    
    if (size > MAX_DUMP_SIZE) {
        printf("║ ... (%zu more bytes truncated)                                        ║\n",
               size - MAX_DUMP_SIZE);
    }
    
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n\n");
    fflush(stdout);
}

// Exception callback - called when breakpoint is hit
// Update ssl_exception_callback to match ExceptionCallback parameter order
static void ssl_exception_callback(
    void* context,
    mach_port_t thread,
    arm_thread_state64_t state,
    bool* removeBreak
) {
    uint64_t pc = arm_thread_state64_get_pc(state);

    // Add debug logs to confirm callback execution
    printf("[DEBUG] ssl_exception_callback triggered\n");
    printf("[DEBUG] PC: 0x%llx\n", pc);
    printf("[DEBUG] SSL_write address: 0x%llx\n", g_ssl_write_addr);
    printf("[DEBUG] Breakpoint address: 0x%llx\n", g_ssl_write_addr + 0x1C);

    // Verify this is our SSL_write breakpoint
    if (pc != g_ssl_write_addr + 0x1C) { 
        printf("[INFO] Breakpoint at 0x%llx (not SSL_write, continuing)\n", pc);
        *removeBreak = false;  // Continue without removing breakpoint
        return;
    }

    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("🔴 SSL_write BREAKPOINT HIT!\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Extract SSL_write arguments from ARM64 registers
    uint64_t ssl_ptr = state.__x[21];  // X21 = SSL*
    uint64_t buf_ptr = state.__x[20];  // X20 = buf*
    uint64_t buf_len = state.__x[19];  // X19 = len

    printf("Thread:        0x%x\n", thread);
    printf("PC:            0x%llx (SSL_write + 0x%llx)\n", pc, pc - g_ssl_write_addr);
    printf("SSL Context:   0x%llx (X21)\n", ssl_ptr);
    printf("Buffer:        0x%llx (X20)\n", buf_ptr);
    printf("Size:          %llu bytes (X19)\n", buf_len);

    // Read buffer contents from remote process
    if (buf_ptr && buf_len > 0 && buf_len < 10 * 1024 * 1024) {
        size_t read_size = (buf_len > MAX_DUMP_SIZE) ? MAX_DUMP_SIZE : buf_len;
        uint8_t* buffer = (uint8_t*)malloc(read_size);

        if (buffer) {
            vm_size_t bytes_read = 0;
            kern_return_t kr = vm_read_overwrite(g_target_task, buf_ptr, read_size,
                                                 (vm_address_t)buffer, &bytes_read);

            if (kr == KERN_SUCCESS && bytes_read > 0) {
                dump_ssl_buffer(buffer, bytes_read);
            } else {
                printf("❌ Failed to read buffer: %s\n", mach_error_string(kr));
            }

            free(buffer);
        } else {
            printf("❌ Failed to allocate memory for buffer dump\n");
        }
    } else {
        printf("⚠️  Invalid buffer pointer or size\n");
    }

    printf("✅ Continuing execution...\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    // Continue execution without removing breakpoint
    *removeBreak = false;
}

// Initialize SSL interception
bool start_ssl_interception(task_t task, uint64_t ssl_write_addr) {
    printf("\n╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║          SSL_write Interception with SimpleDebugger                   ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n\n");
    
    g_target_task = task;
    g_ssl_write_addr = ssl_write_addr;
    
    // Create debugger for remote task
    g_debugger = SimpleDebugger_createWithTask(task);
    if (!g_debugger) {
        printf("❌ Failed to create SimpleDebugger\n");
        return false;
    }
    
    printf("✓ SimpleDebugger created for remote task\n");
    
    // Set exception callback
    SimpleDebugger_setExceptionCallback(g_debugger, ssl_exception_callback, NULL);
    printf("✓ Exception callback registered\n");
    
    // Start debugging (sets up exception ports)
    if (!SimpleDebugger_startDebugging(g_debugger)) {
        printf("❌ Failed to start debugging\n");
        SimpleDebugger_destroy(g_debugger);
        g_debugger = NULL;
        return false;
    }
    
    printf("✓ Exception ports configured\n");
    
    // Set hardware breakpoint at SSL_write + 0x1C
    // This is after the function prologue where:
    // - X0, X1, X2 have been saved to X21, X20, X19
    // - Stack frame is set up
    // - We can safely read arguments
    uint64_t breakpoint_addr = ssl_write_addr + 0x1C;
    
    SimpleDebugger_setBreakpoint(g_debugger, breakpoint_addr);
    
    printf("✓ Hardware breakpoint set at 0x%llx (SSL_write + 0x1C)\n", breakpoint_addr);
    printf("\n🎯 Interception active! Waiting for SSL_write calls...\n");
    printf("   (No code modification - using ARM debug registers)\n\n");
    
    return true;
}

// Stop SSL interception
void stop_ssl_interception(void) {
    if (g_debugger) {
        printf("\n🛑 Stopping SSL interception...\n");
        SimpleDebugger_destroy(g_debugger);
        g_debugger = NULL;
        printf("✓ Cleanup complete\n");
    }
}
