// Hook Objective-C method in remote process using ROP, similar to hookM
// Returns 1 if success, 0 if fail

// === SSLKillSwitch ROP Hooks (Full) ===
#include <mach/mach.h>
#include <string.h>
#import <stdio.h>
#import <unistd.h>
#import <stdlib.h>
#import <dlfcn.h>
#import <errno.h>
#import <string.h>
#import <limits.h>
#import <pthread.h>
#import <pthread_spis.h>
#import <mach/mach.h>
#import <mach/error.h>
#import <mach-o/getsect.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/reloc.h>
#import <mach-o/dyld_images.h>
#import <sys/utsname.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#include <libkern/OSCacheControl.h>

#import "pac.h"
#import "dyld.h"
#import "sandbox.h"
#import "CoreSymbolication.h"
#import "task_utils.h"
#import "thread_utils.h"
#import "arm64.h"
#include <mach/vm_map.h>

// Hook Objective-C method in remote process using ROP, similar to hookM
// Monitor ssl_write using breakpoint + monitor thread
// Returns 1 if success, 0 if fail

#include <mach/mach.h>
#include <string.h>
#import <stdio.h>
#import <unistd.h>
#import <stdlib.h>
#import <dlfcn.h>
#import <errno.h>
#import <string.h>
#import <limits.h>
#import <pthread.h>
#import <pthread_spis.h>
#import <mach/mach.h>
#import <mach/error.h>
#import <mach-o/getsect.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/reloc.h>
#import <mach-o/dyld_images.h>
#import <sys/utsname.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#include <libkern/OSCacheControl.h>

#import "pac.h"
#import "dyld.h"
#import "sandbox.h"
#import "CoreSymbolication.h"
#import "task_utils.h"
#import "thread_utils.h"
#import "arm64.h"
#include <mach/vm_map.h>

// ============ SSL Write Monitor ============

typedef struct {
    task_t task;
    uint64_t ssl_write_addr;
    bool running;
    pthread_mutex_t lock;
    uint64_t call_count;
} ssl_monitor_state_t;

ssl_monitor_state_t *g_ssl_monitor = NULL;

// Monitor thread - chờ breakpoint hit
void* ssl_monitor_thread(void *arg) {
    ssl_monitor_state_t *state = (ssl_monitor_state_t *)arg;
    
    printf("[ssl_monitor_thread] Started monitoring\n");
    
    while (state->running) {
        thread_t *threads;
        mach_msg_type_number_t thread_count;
        
        // Get all threads
        kern_return_t kr = task_threads(state->task, &threads, &thread_count);
        if (kr != KERN_SUCCESS) {
            usleep(50000);
            continue;
        }
        
        for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
            // Suspend thread to safely read state
            thread_suspend(threads[i]);
            
            arm_thread_state64_t thread_state;
            mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
            
            kr = thread_get_state(threads[i], ARM_THREAD_STATE64,
                                 (thread_state_t)&thread_state, &state_count);
            
            if (kr == KERN_SUCCESS) {
                // Check if PC at breakpoint (ssl_write)
                uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(thread_state);
                
                if (pc == state->ssl_write_addr) {
                    pthread_mutex_lock(&state->lock);
                    state->call_count++;
                    uint64_t call_num = state->call_count;
                    pthread_mutex_unlock(&state->lock);
                    
                    printf("\n");
                    printf("╔════════════════════════════════════════╗\n");
                    printf("║  ssl_write INTERCEPTED (#%lld)         ║\n", call_num);
                    printf("╚════════════════════════════════════════╝\n");
                    
                    // Read arguments from registers
                    uint64_t ssl_ptr = thread_state.__x[0];      // x0 = SSL*
                    uint64_t buf_ptr = thread_state.__x[1];      // x1 = buf
                    uint32_t buf_len = thread_state.__x[2];      // x2 = len
                    
                    printf("[+] Thread ID: %d\n", threads[i]);
                    printf("[+] x0 (SSL*):  0x%llx\n", ssl_ptr);
                    printf("[+] x1 (buf):   0x%llx\n", buf_ptr);
                    printf("[+] x2 (len):   %d (0x%x)\n", buf_len, buf_len);
                    
                    // Read buffer content from remote process
                    if (buf_len > 0 && buf_len < 0x1000000) {
                        uint8_t *buf_data = malloc(buf_len);
                        vm_size_t actual_size = buf_len;
                        
                        kr = vm_read_overwrite(state->task, buf_ptr, buf_len,
                                              (vm_address_t)buf_data, &actual_size);
                        
                        if (kr == KERN_SUCCESS && actual_size > 0) {
                            // Print hex dump
                            printf("\n[HEX] Buffer content (first %zu bytes):\n", 
                                   actual_size > 200 ? 200 : actual_size);
                            for (vm_size_t j = 0; j < actual_size && j < 200; j++) {
                                printf("%02x ", buf_data[j]);
                                if ((j + 1) % 16 == 0) printf("\n");
                            }
                            printf("\n");
                            
                            // Print ASCII dump
                            printf("\n[ASCII] Readable content:\n");
                            for (vm_size_t j = 0; j < actual_size && j < 200; j++) {
                                uint8_t c = buf_data[j];
                                if (c >= 32 && c < 127) {
                                    printf("%c", c);
                                } else {
                                    printf(".");
                                }
                            }
                            printf("\n");
                        } else if (kr != KERN_SUCCESS) {
                            printf("[ERROR] Failed to read buffer: %s\n", mach_error_string(kr));
                        }
                        
                        free(buf_data);
                    } else {
                        printf("[!] Buffer length invalid or too large: %d\n", buf_len);
                    }
                    
                    printf("\n");
                }
            }
            
            // Resume thread
            thread_resume(threads[i]);
        }
        
        vm_deallocate(mach_task_self(), (vm_address_t)threads,
                     thread_count * sizeof(thread_t));
        
        usleep(50000);  // Poll every 50ms
    }
    
    printf("[ssl_monitor_thread] Monitor stopped\n");
    return NULL;
}

// Setup ssl_write monitoring
void start_ssl_write_monitor(task_t task, uint64_t ssl_write_addr) {
    printf("[*] Starting ssl_write monitor at 0x%llx\n", ssl_write_addr);
    
    // Allocate monitor state
    g_ssl_monitor = malloc(sizeof(ssl_monitor_state_t));
    g_ssl_monitor->task = task;
    g_ssl_monitor->ssl_write_addr = ssl_write_addr;
    g_ssl_monitor->running = true;
    g_ssl_monitor->call_count = 0;
    pthread_mutex_init(&g_ssl_monitor->lock, NULL);
    
    // Set breakpoint at ssl_write (replace first instruction with BRK #0)
    uint8_t brk_instr[] = {0x00, 0x00, 0x20, 0xd4};  // BRK #0 instruction
    
    kern_return_t kr = vm_write(task, ssl_write_addr, (vm_offset_t)brk_instr, sizeof(brk_instr));
    if (kr != KERN_SUCCESS) {
        printf("[ERROR] Failed to set breakpoint: %s\n", mach_error_string(kr));
        free(g_ssl_monitor);
        g_ssl_monitor = NULL;
        return;
    }
    
    printf("[+] Breakpoint set at 0x%llx\n", ssl_write_addr);
    
    // Start monitor thread
    pthread_t monitor_tid;
    int pthread_kr = pthread_create(&monitor_tid, NULL, ssl_monitor_thread, g_ssl_monitor);
    if (pthread_kr != 0) {
        printf("[ERROR] Failed to create monitor thread: %d\n", pthread_kr);
        free(g_ssl_monitor);
        g_ssl_monitor = NULL;
        return;
    }
    
    printf("[+] Monitor thread created (tid: %p)\n", (void*)monitor_tid);

    printf("[+] ssl_write monitoring active!\n");
}

// Stop monitoring
void stop_ssl_write_monitor() {
    if (g_ssl_monitor) {
        printf("[*] Stopping ssl_write monitor...\n");
        g_ssl_monitor->running = false;
        usleep(200000);
        
        pthread_mutex_destroy(&g_ssl_monitor->lock);
        printf("[+] Monitor stopped. Total calls: %lld\n", g_ssl_monitor->call_count);
        
        free(g_ssl_monitor);
        g_ssl_monitor = NULL;
    }
}

void monitorSSLWriteInTarget(task_t task, pid_t pid, vm_address_t allImageInfoAddr)
{
	printf("[monitorSSLWriteInTarget] Starting SSL write monitoring\n");

	// Find libboringssl
	vm_address_t libBorringSSL = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/libboringssl.dylib");
	if (!libBorringSSL) {
		printf("[ERROR] Failed to find libboringssl.dylib\n");
		return;
	}

	// Find ssl_write function
	uint64_t sslWriteAddr = remoteDlSym(task, libBorringSSL, "_SSL_write");
	if (!sslWriteAddr) {
		printf("[ERROR] Failed to find SSL_write\n");
		return;
	}

	printf("[+] libboringssl found at 0x%lx\n", libBorringSSL);
	printf("[+] SSL_write found at 0x%llx\n", sslWriteAddr);

	// Start monitoring
	start_ssl_write_monitor(task, sslWriteAddr);

	printf("[+] Monitor is running! Press Ctrl+C to stop...\n");
	printf("[+] Any calls to ssl_write will be intercepted and logged\n");
}


vm_address_t writeStringToTask(task_t task, const char* string, size_t* lengthOut)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_address_t remoteString = (vm_address_t)NULL;
	size_t stringLen = strlen(string)+1;

	kr = vm_allocate(task, &remoteString, stringLen, VM_FLAGS_ANYWHERE);
	if(kr != KERN_SUCCESS)
	{
		printf("ERROR: Unable to memory for string %s: %s\n", string, mach_error_string(kr));
		return 0;
	}

	kr = vm_protect(task, remoteString, stringLen, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	if(kr != KERN_SUCCESS)
	{
		vm_deallocate(task, remoteString, stringLen);
		printf("ERROR: Failed to make string %s read/write: %s.\n", string, mach_error_string(kr));
		return kr;
	}

	kr = vm_write(task, remoteString, (vm_address_t)string, stringLen);
	if(kr != KERN_SUCCESS)
	{
		vm_deallocate(task, remoteString, stringLen);
		printf("ERROR: Failed to write string %s to memory: %s\n", string, mach_error_string(kr));
		return kr;
	}

	if(lengthOut)
	{
		*lengthOut = stringLen;
	}

	return remoteString;
}

void findRopLoop(task_t task, vm_address_t allImageInfoAddr)
{
	uint32_t inst = CFSwapInt32(0x00000014);
	ropLoop = (uint64_t)scanLibrariesForMemory(task, allImageInfoAddr, (char*)&inst, sizeof(inst), 4);
}

// Create an infinitely spinning pthread in target process
kern_return_t createRemotePthread(task_t task, vm_address_t allImageInfoAddr, thread_act_t* remotePthreadOut)
{
	kern_return_t kr = KERN_SUCCESS;

#if __arm64e__
	// GET ANY VALID THREAD STATE
	mach_msg_type_number_t validThreadStateCount = ARM_THREAD_STATE64_COUNT;
	struct arm_unified_thread_state validThreadState;
	thread_act_array_t allThreadsForFindingValid;
	mach_msg_type_number_t threadCountForFindingValid;
	kr = task_threads(task, &allThreadsForFindingValid, &threadCountForFindingValid);
	if(kr != KERN_SUCCESS || threadCountForFindingValid == 0)
	{
		printf("[createRemotePthread] ERROR: failed to get threads in task: %s\n", mach_error_string(kr));
		if (kr == KERN_SUCCESS) return 1;
		return kr;
	}
	kr = thread_get_state(allThreadsForFindingValid[0], ARM_THREAD_STATE64, (thread_state_t)&validThreadState.ts_64, &validThreadStateCount);
	if(kr != KERN_SUCCESS )
	{
		printf("[createRemotePthread] ERROR: failed to get valid thread state: %s\n", mach_error_string(kr));
		return kr;
	}
	vm_deallocate(mach_task_self(), (vm_offset_t)allThreadsForFindingValid, sizeof(thread_act_array_t) * threadCountForFindingValid);
#endif

	// GATHER OFFSETS
	__unused vm_address_t libSystemPthreadAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_pthread.dylib");

	uint64_t mainThread = 0;
	if (@available(iOS 12, *)) {
		// TODO: maybe instead of this, allocate our own pthread object?
		// kinda worried about side effects here, but as long our thread doesn't
		// somehow trigger pthread_main_thread modifications, it should be fine
		uint64_t pthread_main_thread_np = remoteDlSym(task, libSystemPthreadAddr, "_pthread_main_thread_np");

		uint32_t instructions[2];
		kr = task_read(task, pthread_main_thread_np, &instructions[0], sizeof(instructions));
		if (kr != KERN_SUCCESS) {
			printf("ERROR: Failed to find main thread (1/3)\n");
			return kr;
		}

		uint64_t _main_thread_ptr = 0;
		if (!decode_adrp_ldr(instructions[0], instructions[1], pthread_main_thread_np, &_main_thread_ptr)) {
			printf("ERROR: Failed to find main thread (2/3)\n");
			return 1;
		}

		kr = task_read(task, _main_thread_ptr, &mainThread, sizeof(mainThread));
		if (kr != KERN_SUCCESS) {
			printf("ERROR: Failed to find main thread (3/3)\n");
			return kr;
		}
	}
	uint64_t _pthread_set_self = remoteDlSym(task, libSystemPthreadAddr, "__pthread_set_self");

	// ALLOCATE STACK
	vm_address_t remoteStack64 = (vm_address_t)NULL;
	kr = vm_allocate(task, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);
	if(kr != KERN_SUCCESS)
	{
		printf("[createRemotePthread] ERROR: Unable to allocate stack memory: %s\n", mach_error_string(kr));
		return kr;
	}

	kr = vm_protect(task, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	if(kr != KERN_SUCCESS)
	{
		vm_deallocate(task, remoteStack64, STACK_SIZE);
		printf("[createRemotePthread] ERROR: Failed to make remote stack writable: %s.\n", mach_error_string(kr));
		return kr;
	}

	thread_act_t bootstrapThread = 0;
	struct arm_unified_thread_state bootstrapThreadState;
	memset(&bootstrapThreadState, 0, sizeof(struct arm_unified_thread_state));

	// spawn pthread to infinite loop
	bootstrapThreadState.ash.flavor = ARM_THREAD_STATE64;
	bootstrapThreadState.ash.count = ARM_THREAD_STATE64_COUNT;
#if __arm64e__
	bootstrapThreadState.ts_64.__opaque_flags = validThreadState.ts_64.__opaque_flags;
#endif
	uint64_t sp = (remoteStack64 + (STACK_SIZE / 2));
	__unused uint64_t x2 = ropLoop;
#if __arm64e__
	if (!(bootstrapThreadState.ts_64.__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH)) {
		x2 = (uint64_t)make_sym_callable((void*)x2);
	}
#endif
	__darwin_arm_thread_state64_set_sp(bootstrapThreadState.ts_64, (void*)sp);
	__darwin_arm_thread_state64_set_pc_fptr(bootstrapThreadState.ts_64, make_sym_callable((void*)_pthread_set_self));
	__darwin_arm_thread_state64_set_lr_fptr(bootstrapThreadState.ts_64, make_sym_callable((void*)ropLoop)); //when done, go to infinite loop
	bootstrapThreadState.ts_64.__x[0] = mainThread;

	//printThreadState_state(bootstrapThreadState);

	kr = thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&bootstrapThreadState.ts_64, ARM_THREAD_STATE64_COUNT, &bootstrapThread);
	if(kr != KERN_SUCCESS)
	{
		printf("[createRemotePthread] ERROR: Failed to create running thread: %s.\n", mach_error_string(kr));
		return kr;
	}

	printf("[createRemotePthread] Created bootstrap thread... now waiting on finish\n");

	struct arm_unified_thread_state outState;
	kr = wait_for_thread(bootstrapThread, ropLoop, &outState);
	if(kr != KERN_SUCCESS)
	{
		printf("[createRemotePthread] ERROR: failed to wait for bootstrap thread: %s\n", mach_error_string(kr));
		return kr;
	}

	printf("[createRemotePthread] Bootstrap done!\n");

	if(remotePthreadOut) *remotePthreadOut = bootstrapThread;

	return kr;
}

kern_return_t arbCall(task_t task, thread_act_t targetThread, uint64_t* retOut, bool willReturn, vm_address_t funcPtr, int numArgs, ...)
{
	kern_return_t kr = KERN_SUCCESS;
	if(numArgs > 8)
	{
		printf("[arbCall] ERROR: Only 8 arguments are supported by arbCall\n");
		return -2;
	}
	if(!targetThread)
	{
		printf("[arbCall] ERROR: targetThread == null\n");
		return -3;
	}

	va_list ap;
	va_start(ap, numArgs);

	// suspend target thread
	thread_suspend(targetThread);

	// backup states of target thread

	mach_msg_type_number_t origThreadStateCount = ARM_THREAD_STATE64_COUNT;
	struct arm_unified_thread_state origThreadState;
	kr = thread_get_state(targetThread, ARM_THREAD_STATE64, (thread_state_t)&origThreadState.ts_64, &origThreadStateCount);
	if(kr != KERN_SUCCESS)
	{
		thread_resume(targetThread);
		printf("[arbCall] ERROR: failed to save original state of target thread: %s\n", mach_error_string(kr));
		return kr;
	}

	struct arm64_thread_full_state* origThreadFullState = thread_save_state_arm64(targetThread);
	if(!origThreadFullState)
	{
		thread_resume(targetThread);
		printf("[arbCall] ERROR: failed to backup original state of target thread\n");
		return kr;
	}

	// prepare target thread for arbitary call

	// allocate stack
	vm_address_t remoteStack = (vm_address_t)NULL;
	kr = vm_allocate(task, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);
	if(kr != KERN_SUCCESS)
	{
		free(origThreadFullState);
		thread_resume(targetThread);
		printf("[arbCall] ERROR: Unable to allocate stack memory: %s\n", mach_error_string(kr));
		return kr;
	}

	// make stack read / write
	kr = vm_protect(task, remoteStack, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	if(kr != KERN_SUCCESS)
	{
		free(origThreadFullState);
		vm_deallocate(task, remoteStack, STACK_SIZE);
		thread_resume(targetThread);
		printf("[arbCall] ERROR: Failed to make remote stack writable: %s.\n", mach_error_string(kr));
		return kr;
	}

	// abort any existing syscalls by target thread, thanks to Linus Henze for this suggestion :P
	thread_abort(targetThread);

	// set state for arb call
	struct arm_unified_thread_state newState = origThreadState;
	uint64_t sp = remoteStack + (STACK_SIZE / 2);
	__darwin_arm_thread_state64_set_sp(newState.ts_64, (void*)sp);
	__darwin_arm_thread_state64_set_pc_fptr(newState.ts_64, make_sym_callable((void*)funcPtr));
	__darwin_arm_thread_state64_set_lr_fptr(newState.ts_64, make_sym_callable((void*)ropLoop));

	// write arguments into registers
	for (int i = 0; i < numArgs; i++)
	{
		newState.ts_64.__x[i] = va_arg(ap, uint64_t);
	}

	kr = thread_set_state(targetThread, ARM_THREAD_STATE64, (thread_state_t)&newState.ts_64, ARM_THREAD_STATE64_COUNT);
	if(kr != KERN_SUCCESS)
	{
		free(origThreadFullState);
		vm_deallocate(task, remoteStack, STACK_SIZE);
		thread_resume(targetThread);
		printf("[arbCall] ERROR: failed to set state for thread: %s\n", mach_error_string(kr));
		return kr;
	}

	printf("[arbCall] Set thread state for arbitary call\n");
	//printThreadState(targetThread);

	thread_act_array_t cachedThreads;
	mach_msg_type_number_t cachedThreadCount;
	kr = task_threads(task, &cachedThreads, &cachedThreadCount);
	if (kr != KERN_SUCCESS) return kr;

	suspend_threads_except_for(cachedThreads, cachedThreadCount, targetThread);

	// perform arbitary call
	thread_resume(targetThread);
	printf("[arbCall] Started thread, waiting for it to finish...\n");

	// wait for arbitary call to finish (or not)
	struct arm_unified_thread_state outState;
	if (willReturn)
	{
		kr = wait_for_thread(targetThread, ropLoop, &outState);
		if(kr != KERN_SUCCESS)
		{
			free(origThreadFullState);
			printf("[arbCall] ERROR: failed to wait for thread to finish: %s\n", mach_error_string(kr));
			return kr;
		}

		// extract return value from state if needed
		if(retOut)
		{
			*retOut = outState.ts_64.__x[0];
		}
	}
	else
	{
		kr = wait_for_thread(targetThread, 0, &outState);
		printf("[arbCall] pthread successfully did not return with code %d (%s)\n", kr, mach_error_string(kr));
	}

	resume_threads_except_for(cachedThreads, cachedThreadCount, targetThread);

	vm_deallocate(mach_task_self(), (vm_offset_t)cachedThreads, sizeof(thread_act_array_t) * cachedThreadCount);

	// release fake stack as it's no longer needed
	vm_deallocate(task, remoteStack, STACK_SIZE);

	if (willReturn)
	{
		// suspend target thread
		thread_suspend(targetThread);
		thread_abort(targetThread);

		// restore states of target thread to what they were before the arbitary call
		bool restoreSuccess = thread_restore_state_arm64(targetThread, origThreadFullState);
		if(!restoreSuccess)
		{
			printf("[arbCall] ERROR: failed to revert to old thread state\n");
			return kr;
		}

		// resume thread again, process should continue executing as before
		//printThreadState(targetThread);
		thread_resume(targetThread);
	}

	return kr;
}

void prepareForMagic(task_t task, vm_address_t allImageInfoAddr)
{
	// FIND INFINITE LOOP ROP GADGET
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		findRopLoop(task, allImageInfoAddr);
	});
	printf("[prepareForMagic] done, ropLoop: 0x%llX\n", ropLoop);
}

bool sandboxFixup(task_t task, thread_act_t pthread, pid_t pid, const char* dylibPath, vm_address_t allImageInfoAddr)
{
	int readExtensionNeeded = sandbox_check(pid, "file-read-data", SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, dylibPath);
	int executableExtensionNeeded = sandbox_check(pid, "file-map-executable", SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, dylibPath);

	int retval = 0;
	vm_address_t libSystemSandboxAddr = 0;
	uint64_t sandbox_extension_consumeAddr = 0;
	if (readExtensionNeeded || executableExtensionNeeded) {
		libSystemSandboxAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_sandbox.dylib");
		sandbox_extension_consumeAddr = remoteDlSym(task, libSystemSandboxAddr, "_sandbox_extension_consume");
		printf("[sandboxFixup] applying sandbox extension(s)! sandbox_extension_consume: 0x%llX\n", sandbox_extension_consumeAddr);
	}

	if (readExtensionNeeded) {
		char* extString = sandbox_extension_issue_file(APP_SANDBOX_READ, dylibPath, 0);
		size_t remoteExtStringSize = 0;
		vm_address_t remoteExtString = writeStringToTask(task, (const char*)extString, &remoteExtStringSize);
		if(remoteExtString)
		{
			int64_t readExtensionRet = 0;
			arbCall(task, pthread, (uint64_t*)&readExtensionRet, true, sandbox_extension_consumeAddr, 1, remoteExtString);
			vm_deallocate(task, remoteExtString, remoteExtStringSize);

			printf("[sandboxFixup] sandbox_extension_consume returned %lld for read extension\n", (int64_t)readExtensionRet);
			retval |= (readExtensionRet <= 0);
		}
	}
	else {
		printf("[sandboxFixup] read extension not needed, skipping...\n");
	}

	if (executableExtensionNeeded) {
		char* extString = sandbox_extension_issue_file("com.apple.sandbox.executable", dylibPath, 0);
		size_t remoteExtStringSize = 0;
		vm_address_t remoteExtString = writeStringToTask(task, (const char*)extString, &remoteExtStringSize);
		if(remoteExtString)
		{
			int64_t executableExtensionRet = 0;
			arbCall(task, pthread, (uint64_t*)&executableExtensionRet, true, sandbox_extension_consumeAddr, 1, remoteExtString);
			vm_deallocate(task, remoteExtString, remoteExtStringSize);

			printf("[sandboxFixup] sandbox_extension_consume returned %lld for executable extension\n", (int64_t)executableExtensionRet);
			retval |= (executableExtensionRet <= 0);
		}
	}
	else {
		printf("[sandboxFixup] executable extension not needed, skipping...\n");
	}

	return retval == 0;
}

void injectDylibViaRop(task_t task, pid_t pid, const char* dylibPath, vm_address_t allImageInfoAddr)
{
	prepareForMagic(task, allImageInfoAddr);

	thread_act_t pthread = 0;
	kern_return_t kr = createRemotePthread(task, allImageInfoAddr, &pthread);
	if(kr != KERN_SUCCESS) return;

	sandboxFixup(task, pthread, pid, dylibPath, allImageInfoAddr);

	printf("[injectDylibViaRop] Preparation done, now injecting!\n");

	vm_address_t libBorringSSL = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/libboringssl.dylib");
	uint64_t sslWriteAddr = remoteDlSym(task, libBorringSSL, "_SSL_write");

	printf("[injectDylibViaRop] boringSSL found at 0x%llX, SSL_write at 0x%llX\n", (unsigned long long)libBorringSSL, (unsigned long long)sslWriteAddr);

	monitorSSLWriteInTarget(task, pid, allImageInfoAddr);
	// // FIND OFFSETS
	// vm_address_t libDyldAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libdyld.dylib");
	// uint64_t dlopenAddr = remoteDlSym(task, libDyldAddr, "_dlopen_from");
	// uint64_t dlerrorAddr = remoteDlSym(task, libDyldAddr, "_dlerror");

	// vm_address_t libDyldTextStart = 0, libDyldTextEnd = 0;

	// printf("[injectDylibViaRop] dlopen: 0x%llX, dlerror: 0x%llX\n", (unsigned long long)dlopenAddr, (unsigned long long)dlerrorAddr);

	// // CALL DLOPEN
	// size_t remoteDylibPathSize = 0;
	// vm_address_t remoteDylibPath = writeStringToTask(task, (const char*)dylibPath, &remoteDylibPathSize);
	// if(remoteDylibPath)
	// {
	// 	void* dlopenRet;
	// 	// Prepare addressInCaller for dlopen_from (third argument)
	// 	void* addressInCaller = NULL; // Set as needed, e.g., NULL or a valid address
	// 	arbCall(task, pthread, (uint64_t*)&dlopenRet, true, dlopenAddr, 3, remoteDylibPath, RTLD_NOW, addressInCaller);
	// 	vm_deallocate(task, remoteDylibPath, remoteDylibPathSize);

	// 	if (dlopenRet) {
	// 		printf("[injectDylibViaRop] dlopen succeeded, library handle: %p\n", dlopenRet);

	// 	}
	// 	else {
	// 		uint64_t remoteErrorString = 0;
	// 		arbCall(task, pthread, (uint64_t*)&remoteErrorString, true, dlerrorAddr, 0);
	// 		char *errorString = task_copy_string(task, remoteErrorString);
	// 		printf("[injectDylibViaRop] dlopen failed, error:\n%s\n", errorString);
	// 		free(errorString);
	// 	}
	// }

	thread_terminate(pthread);
}