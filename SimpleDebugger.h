//
//  SimpleDebugger.h
//  SimpleDebugger
//
//  Created by Noah Martin on 10/9/24.
//

#ifndef SimpleDebugger_h
#define SimpleDebugger_h

#include <mach/mach.h>
#include <mach/arm/thread_state.h>
#include <stdbool.h>

#if TARGET_OS_TV || TARGET_OS_WATCH || !(defined(__arm64__) || defined(__aarch64__))
  #define EMG_ENABLE_MACH_APIS 0
#else
  #define EMG_ENABLE_MACH_APIS 1
#endif

#if EMG_ENABLE_MACH_APIS

#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointer
typedef struct SimpleDebugger SimpleDebugger;

// Callback types
typedef void (*ExceptionCallback)(void* context, 
                                  mach_port_t thread, 
                                  arm_thread_state64_t state,
                                  bool* removeBreak);

typedef void (*BadAccessCallback)(void* context,
                                  mach_port_t thread, 
                                  arm_thread_state64_t state);

// Constructor/Destructor
SimpleDebugger* SimpleDebugger_create(void);
SimpleDebugger* SimpleDebugger_createWithTask(mach_port_t remoteTask);
void SimpleDebugger_destroy(SimpleDebugger* debugger);

// Setters/Getters
void SimpleDebugger_setTargetTask(SimpleDebugger* debugger, mach_port_t task);
mach_port_t SimpleDebugger_getTargetTask(SimpleDebugger* debugger);
bool SimpleDebugger_isRemoteDebugging(SimpleDebugger* debugger);

// Core debugging functions
bool SimpleDebugger_startDebugging(SimpleDebugger* debugger);
void SimpleDebugger_setExceptionCallback(SimpleDebugger* debugger, 
                                         ExceptionCallback callback,
                                         void* context);
void SimpleDebugger_setBadAccessCallback(SimpleDebugger* debugger,
                                         BadAccessCallback callback,
                                         void* context);
void SimpleDebugger_setBreakpoint(SimpleDebugger* debugger, vm_address_t address);
void SimpleDebugger_removeBreakpoint(SimpleDebugger* debugger, vm_address_t address);

// Memory operations
bool SimpleDebugger_readMemory(SimpleDebugger* debugger,
                               vm_address_t address, 
                               void* buffer, 
                               vm_size_t size);
bool SimpleDebugger_writeMemory(SimpleDebugger* debugger,
                                vm_address_t address, 
                                const void* buffer, 
                                vm_size_t size);

// Function hooking
int SimpleDebugger_hookFunction(SimpleDebugger* debugger,
                                void* originalFunc, 
                                void* newFunc);

#ifdef __cplusplus
}
#endif

#endif // EMG_ENABLE_MACH_APIS
#endif // SimpleDebugger_h