#ifndef SSL_INTERCEPT_H
#define SSL_INTERCEPT_H

#include <mach/mach.h>
#include <stdbool.h>

// Initialize SSL_write interception using SimpleDebugger
// Parameters:
//   task: target process task port
//   ssl_write_addr: address of SSL_write function in remote process
// Returns: true if success, false if fail
bool start_ssl_interception(task_t task, uint64_t ssl_write_addr);

// Stop SSL interception and cleanup
void stop_ssl_interception(void);

#endif // SSL_INTERCEPT_H
