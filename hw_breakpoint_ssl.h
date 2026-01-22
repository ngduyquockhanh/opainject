#ifndef HW_BREAKPOINT_SSL_H
#define HW_BREAKPOINT_SSL_H

#include <mach/mach.h>
#include <stdbool.h>

// Initialize hardware breakpoint-based SSL_write interception
// Parameters:
//   task: target process task port
//   ssl_write_addr: address of SSL_write function in remote process
// Returns: kern_return_t status
kern_return_t init_ssl_breakpoint_hook(task_t task, uint64_t ssl_write_addr);

// Stop the breakpoint hook and cleanup
void cleanup_ssl_breakpoint_hook(void);

#endif // HW_BREAKPOINT_SSL_H
