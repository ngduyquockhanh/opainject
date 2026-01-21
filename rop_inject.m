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

	// // === SIMPLE APPROACH: Make SSL_write return immediately (SSL Kill Switch) ===
	// if (sslWriteAddr) {
	// 	printf("[DEBUG] Patching SSL_write to return immediately (no crash test)\n");
		
	// 	// Simple patch: Make SSL_write return without doing anything
	// 	// This is safer than trampoline approach for testing
		
	// 	thread_act_array_t threads;
	// 	mach_msg_type_number_t thread_count;
	// 	kr = task_threads(task, &threads, &thread_count);
	// 	if (kr == KERN_SUCCESS) {
	// 		for (int i = 0; i < thread_count; i++) {
	// 			thread_suspend(threads[i]);
	// 		}
	// 	}
		
	// 	// Save original bytes first
	// 	uint32_t original_bytes[4] = {0};
	// 	vm_size_t read_size = 16;
	// 	kr = vm_read_overwrite(task, sslWriteAddr, 16, 
	// 	                      (vm_address_t)original_bytes, &read_size);
	// 	if (kr == KERN_SUCCESS) {
	// 		printf("[DEBUG] Original: %08X %08X %08X %08X\n", 
	// 		       original_bytes[0], original_bytes[1], 
	// 		       original_bytes[2], original_bytes[3]);
	// 	}
		
	// 	// Make writable
	// 	kr = vm_protect(task, sslWriteAddr, 16, FALSE,
	// 	               VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
	// 	if (kr == KERN_SUCCESS) {
	// 		// Patch to: return original SSL_write result without modification
	// 		// Just preserve the function - NO HOOK for now
	// 		uint32_t nop_patch[4];
			
	// 		// Keep original function intact - just testing if patching works
	// 		// Option 1: NOP (test only)
	// 		// nop_patch[0] = 0xD503201F; // NOP
	// 		// nop_patch[1] = 0xD503201F; // NOP
	// 		// nop_patch[2] = 0xD503201F; // NOP
	// 		// nop_patch[3] = 0xD503201F; // NOP
			
	// 		// Option 2: Keep original - NO PATCH (safest)
	// 		nop_patch[0] = original_bytes[0];
	// 		nop_patch[1] = original_bytes[1];
	// 		nop_patch[2] = original_bytes[2];
	// 		nop_patch[3] = original_bytes[3];
			
	// 		kr = vm_write(task, sslWriteAddr, (vm_offset_t)nop_patch, 16);
	// 		if (kr == KERN_SUCCESS) {
	// 			printf("[DEBUG] SSL_write preserved (no modification)\n");
	// 		} else {
	// 			printf("[DEBUG] ERROR: Failed to write: %s\n", mach_error_string(kr));
	// 		}
			
	// 		// Restore executable
	// 		vm_protect(task, sslWriteAddr, 16, FALSE,
	// 		          VM_PROT_READ | VM_PROT_EXECUTE);
	// 	}
		
	// 	// Resume threads
	// 	if (thread_count > 0) {
	// 		for (int i = 0; i < thread_count; i++) {
	// 			thread_resume(threads[i]);
	// 		}
	// 		vm_deallocate(mach_task_self(), (vm_offset_t)threads,
	// 		             sizeof(thread_act_array_t) * thread_count);
	// 	}
		
	// 	printf("[DEBUG] Test complete - app should run normally without hook\n");
	// }

	// === HOOK SSL_write với trampoline ===
	if (sslWriteAddr) {
		printf("[DEBUG] Hooking SSL_write to log buffer content\n");
		
		// 1. Suspend all threads
		thread_act_array_t threads;
		mach_msg_type_number_t thread_count;
		kr = task_threads(task, &threads, &thread_count);
		if (kr == KERN_SUCCESS) {
			for (int i = 0; i < thread_count; i++) {
				thread_suspend(threads[i]);
			}
		}
		
		// 2. Save original instructions (we'll overwrite first 16 bytes)
		uint32_t original_insns[4] = {0};
		vm_size_t read_size = 16;
		kr = vm_read_overwrite(task, sslWriteAddr, 16,
							(vm_address_t)original_insns, &read_size);
		if (kr != KERN_SUCCESS) {
			printf("[DEBUG] ERROR: Failed to read original: %s\n", mach_error_string(kr));
			goto cleanup;
		}
		
		printf("[DEBUG] Original bytes: %08X %08X %08X %08X\n",
			original_insns[0], original_insns[1],
			original_insns[2], original_insns[3]);
		
		// 3. Allocate memory for hook handler + trampoline
		vm_address_t hookRegion = 0;
		size_t hookRegionSize = 4096; // 1 page
		kr = vm_allocate(task, &hookRegion, hookRegionSize, VM_FLAGS_ANYWHERE);
		if (kr != KERN_SUCCESS) {
			printf("[DEBUG] ERROR: Failed to allocate hook region: %s\n", mach_error_string(kr));
			goto cleanup;
		}
		
		kr = vm_protect(task, hookRegion, hookRegionSize, FALSE,
					VM_PROT_READ | VM_PROT_WRITE);
		if (kr != KERN_SUCCESS) {
			printf("[DEBUG] ERROR: Failed to make hook region writable: %s\n", mach_error_string(kr));
			vm_deallocate(task, hookRegion, hookRegionSize);
			goto cleanup;
		}
		
		// 4. Build hook shellcode
		// Layout:
		// [0x000] Hook handler code
		// [0x200] Trampoline (original instructions + jump back)
		// [0x400] Buffer storage area
		
		uint32_t hookCode[128] = {0}; // 512 bytes for hook
		int idx = 0;
		
		// Hook handler:
		// Save all registers
		hookCode[idx++] = 0xA9BF7BFD; // stp x29, x30, [sp, #-16]!
		hookCode[idx++] = 0xA9BF73FB; // stp x27, x28, [sp, #-16]!
		hookCode[idx++] = 0xA9BF6BF9; // stp x25, x26, [sp, #-16]!
		hookCode[idx++] = 0xA9BF63F7; // stp x23, x24, [sp, #-16]!
		hookCode[idx++] = 0xA9BF5BF5; // stp x21, x22, [sp, #-16]!
		hookCode[idx++] = 0xA9BF53F3; // stp x19, x20, [sp, #-16]!
		hookCode[idx++] = 0xA9BF4FF1; // stp x17, x18, [sp, #-16]!
		hookCode[idx++] = 0xA9BF47EF; // stp x15, x16, [sp, #-16]!
		hookCode[idx++] = 0xA9BF3FED; // stp x13, x14, [sp, #-16]!
		hookCode[idx++] = 0xA9BF37EB; // stp x11, x12, [sp, #-16]!
		hookCode[idx++] = 0xA9BF2FE9; // stp x9, x10, [sp, #-16]!
		hookCode[idx++] = 0xA9BF27E7; // stp x7, x8, [sp, #-16]!
		hookCode[idx++] = 0xA9BF1FE5; // stp x5, x6, [sp, #-16]!
		hookCode[idx++] = 0xA9BF17E3; // stp x3, x4, [sp, #-16]!
		hookCode[idx++] = 0xA9BF0FE1; // stp x1, x2, [sp, #-16]!
		hookCode[idx++] = 0xA9BF07E0; // stp x0, xzr, [sp, #-16]!
		
		// Log arguments: x0=SSL*, x1=buf*, x2=len
		// Store them in our buffer area (hookRegion + 0x400)
		uint64_t storageArea = hookRegion + 0x400;
		
		// x3 = storage address (we'll compute this with ADRP+ADD)
		int64_t pageOffset = (storageArea >> 12) - (sslWriteAddr >> 12);
		uint32_t adrp_x3 = 0x90000003 | ((pageOffset & 0x3) << 29) | (((pageOffset >> 2) & 0x7FFFF) << 5);
		hookCode[idx++] = adrp_x3; // adrp x3, storage_page
		
		uint32_t pageRemainder = storageArea & 0xFFF;
		hookCode[idx++] = 0x91000063 | (pageRemainder << 10); // add x3, x3, #page_remainder
		
		// Store x0, x1, x2 to storage
		hookCode[idx++] = 0xF9000060; // str x0, [x3]      // SSL*
		hookCode[idx++] = 0xF9000461; // str x1, [x3, #8]  // buf*
		hookCode[idx++] = 0xF9000862; // str x2, [x3, #16] // len
		
		// Restore all registers
		hookCode[idx++] = 0xA8C107E0; // ldp x0, xzr, [sp], #16
		hookCode[idx++] = 0xA8C10FE1; // ldp x1, x2, [sp], #16
		hookCode[idx++] = 0xA8C117E3; // ldp x3, x4, [sp], #16
		hookCode[idx++] = 0xA8C11FE5; // ldp x5, x6, [sp], #16
		hookCode[idx++] = 0xA8C127E7; // ldp x7, x8, [sp], #16
		hookCode[idx++] = 0xA8C12FE9; // ldp x9, x10, [sp], #16
		hookCode[idx++] = 0xA8C137EB; // ldp x11, x12, [sp], #16
		hookCode[idx++] = 0xA8C13FED; // ldp x13, x14, [sp], #16
		hookCode[idx++] = 0xA8C147EF; // ldp x15, x16, [sp], #16
		hookCode[idx++] = 0xA8C14FF1; // ldp x17, x18, [sp], #16
		hookCode[idx++] = 0xA8C153F3; // ldp x19, x20, [sp], #16
		hookCode[idx++] = 0xA8C15BF5; // ldp x21, x22, [sp], #16
		hookCode[idx++] = 0xA8C163F7; // ldp x23, x24, [sp], #16
		hookCode[idx++] = 0xA8C16BF9; // ldp x25, x26, [sp], #16
		hookCode[idx++] = 0xA8C173FB; // ldp x27, x28, [sp], #16
		hookCode[idx++] = 0xA8C17BFD; // ldp x29, x30, [sp], #16
		
		// Jump to trampoline (hookRegion + 0x200)
		uint64_t trampolineAddr = hookRegion + 0x200;
		int64_t trampolineOffset = (trampolineAddr - (hookRegion + idx * 4)) / 4;
		hookCode[idx++] = 0x14000000 | (trampolineOffset & 0x3FFFFFF); // b trampoline
		
		// 5. Build trampoline at offset 0x200
		uint32_t trampoline[8] = {0};
		int tidx = 0;
		
		// Copy original 4 instructions
		trampoline[tidx++] = original_insns[0];
		trampoline[tidx++] = original_insns[1];
		trampoline[tidx++] = original_insns[2];
		trampoline[tidx++] = original_insns[3];
		
		// Jump back to SSL_write + 16
		uint64_t returnAddr = sslWriteAddr + 16;
		// Load address to x16 then branch
		uint64_t offset_to_return = returnAddr - trampolineAddr;
		
		// Use absolute jump with movk sequence
		trampoline[tidx++] = 0xD2800010 | (((returnAddr >> 0) & 0xFFFF) << 5);  // movz x16, #imm
		trampoline[tidx++] = 0xF2A00010 | (((returnAddr >> 16) & 0xFFFF) << 5); // movk x16, #imm, lsl #16
		trampoline[tidx++] = 0xF2C00010 | (((returnAddr >> 32) & 0xFFFF) << 5); // movk x16, #imm, lsl #32
		trampoline[tidx++] = 0xD61F0200; // br x16
		
		// 6. Write hook code
		kr = vm_write(task, hookRegion, (vm_offset_t)hookCode, sizeof(hookCode));
		if (kr != KERN_SUCCESS) {
			printf("[DEBUG] ERROR: Failed to write hook code: %s\n", mach_error_string(kr));
			vm_deallocate(task, hookRegion, hookRegionSize);
			goto cleanup;
		}
		
		// 7. Write trampoline
		kr = vm_write(task, trampolineAddr, (vm_offset_t)trampoline, sizeof(trampoline));
		if (kr != KERN_SUCCESS) {
			printf("[DEBUG] ERROR: Failed to write trampoline: %s\n", mach_error_string(kr));
			vm_deallocate(task, hookRegion, hookRegionSize);
			goto cleanup;
		}
		
		// 8. Make hook region executable
		kr = vm_protect(task, hookRegion, hookRegionSize, FALSE,
					VM_PROT_READ | VM_PROT_EXECUTE);
		if (kr != KERN_SUCCESS) {
			printf("[DEBUG] ERROR: Failed to make hook executable: %s\n", mach_error_string(kr));
			vm_deallocate(task, hookRegion, hookRegionSize);
			goto cleanup;
		}
		
		// 9. Patch SSL_write to jump to our hook
		uint32_t jumpPatch[4];
		
		// Build jump instruction to hookRegion
		// movz x16, #imm
		jumpPatch[0] = 0xD2800010 | (((hookRegion >> 0) & 0xFFFF) << 5);
		// movk x16, #imm, lsl #16
		jumpPatch[1] = 0xF2A00010 | (((hookRegion >> 16) & 0xFFFF) << 5);
		// movk x16, #imm, lsl #32
		jumpPatch[2] = 0xF2C00010 | (((hookRegion >> 32) & 0xFFFF) << 5);
		// br x16
		jumpPatch[3] = 0xD61F0200;
		
		kr = vm_protect(task, sslWriteAddr, 16, FALSE,
					VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
		if (kr == KERN_SUCCESS) {
			kr = vm_write(task, sslWriteAddr, (vm_offset_t)jumpPatch, 16);
			if (kr == KERN_SUCCESS) {
				printf("[DEBUG] SSL_write hooked successfully!\n");
				printf("[DEBUG] Hook at: 0x%llX\n", hookRegion);
				printf("[DEBUG] Storage at: 0x%llX\n", storageArea);
			}
			vm_protect(task, sslWriteAddr, 16, FALSE,
					VM_PROT_READ | VM_PROT_EXECUTE);
		}
		
	cleanup:
		// 10. Resume threads
		if (thread_count > 0) {
			for (int i = 0; i < thread_count; i++) {
				thread_resume(threads[i]);
			}
			vm_deallocate(mach_task_self(), (vm_offset_t)threads,
						sizeof(thread_act_array_t) * thread_count);
		}
		
		// 11. Monitor thread - đọc storage area định kỳ
		if (kr == KERN_SUCCESS) {
			printf("[DEBUG] Starting monitor thread...\n");
			
			dispatch_queue_t monitorQueue = dispatch_queue_create("ssl.monitor", NULL);
			dispatch_async(monitorQueue, ^{
				while (1) {
					sleep(1); // Check every second
					
					uint64_t args[3] = {0};
					vm_size_t read_sz = sizeof(args);
					kern_return_t kr = vm_read_overwrite(task, storageArea, sizeof(args),
														(vm_address_t)args, &read_sz);
					
					if (kr == KERN_SUCCESS && args[1] != 0) { // buf* không null
						printf("\n[SSL_WRITE CALLED]\n");
						printf("  SSL*:   0x%016llX\n", args[0]);
						printf("  buf*:   0x%016llX\n", args[1]);
						printf("  length: %lld bytes\n", args[2]);
						
						// Read buffer content
						if (args[2] > 0 && args[2] < 16384) {
							char *buf = malloc(args[2] + 1);
							if (buf) {
								vm_size_t buf_read = args[2];
								kr = vm_read_overwrite(task, args[1], args[2],
													(vm_address_t)buf, &buf_read);
								if (kr == KERN_SUCCESS) {
									buf[args[2]] = '\0';
									printf("\n=== BUFFER CONTENT ===\n");
									printf("%.*s\n", (int)args[2], buf);
									printf("======================\n\n");
									
									// Hex dump
									printf("Hex: ");
									for (int i = 0; i < args[2] && i < 64; i++) {
										printf("%02X ", (unsigned char)buf[i]);
									}
									printf("\n\n");
								}
								free(buf);
							}
						}
						
						// Clear storage để detect call mới
						uint64_t zeros[3] = {0};
						vm_write(task, storageArea, (vm_offset_t)zeros, sizeof(zeros));
					}
				}
			});
		}
	}
	
	/* TRAMPOLINE HOOK - DISABLED (causes crash due to stack frame corruption)
	// The issue: copying function prologue breaks stack management
	// SSL_write starts with:
	//   PACIBSP           - PAC authentication  
	//   SUB SP, SP, #0x40 - allocate stack frame
	//   STP ...           - save registers
	// When we copy these to trampoline and jump back, stack is corrupted
	*/
	
	thread_terminate(pthread);
}