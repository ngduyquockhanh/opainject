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

// Thêm function này vào trước injectDylibViaRop
kern_return_t hookSSLWrite(task_t task, thread_act_t pthread, uint64_t sslWriteAddr, vm_address_t allImageInfoAddr)
{
    kern_return_t kr = KERN_SUCCESS;
    
    // 1. Backup original instructions (first 16 bytes = 4 instructions)
    uint32_t originalInsts[4];
    kr = task_read(task, sslWriteAddr, originalInsts, sizeof(originalInsts));
    if (kr != KERN_SUCCESS) {
        printf("[hookSSLWrite] ERROR: Failed to read original instructions: %s\n", mach_error_string(kr));
        return kr;
    }
    
    printf("[hookSSLWrite] Original instructions backed up\n");
    
    // 2. Allocate memory for hook shellcode
    vm_address_t hookShellcode = (vm_address_t)NULL;
    size_t shellcodeSize = 0x2000; // 8KB
    kr = vm_allocate(task, &hookShellcode, shellcodeSize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("[hookSSLWrite] ERROR: Failed to allocate hook memory: %s\n", mach_error_string(kr));
        return kr;
    }
    
    kr = vm_protect(task, hookShellcode, shellcodeSize, TRUE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(task, hookShellcode, shellcodeSize);
        printf("[hookSSLWrite] ERROR: Failed to make hook memory writable: %s\n", mach_error_string(kr));
        return kr;
    }
    
    // 3. Get printf address for logging
    vm_address_t libSystemCAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_c.dylib");
    uint64_t printfAddr = remoteDlSym(task, libSystemCAddr, "_printf");
    
    printf("[hookSSLWrite] printf at 0x%llX\n", printfAddr);
    
    // 4. Create format strings in remote process
    const char* formatStr = "[SSL_write HOOK] ssl=%p, buf=%p, num=%d, data=%.256s\n";
    size_t formatStrSize = 0;
    vm_address_t remoteFormatStr = writeStringToTask(task, formatStr, &formatStrSize);
    
    // 5. Build hook shellcode
    uint64_t hookAddr = hookShellcode;
    uint64_t trampolineAddr = hookShellcode + 0x1000; // Trampoline ở offset 0x1000
    
    // Calculate branch offset from SSL_write to hook
    int64_t branchOffset = ((int64_t)hookAddr - (int64_t)sslWriteAddr) / 4;
    if (branchOffset > 0x1FFFFFF || branchOffset < -0x2000000) {
        printf("[hookSSLWrite] ERROR: Branch offset too large: %lld\n", branchOffset);
        vm_deallocate(task, hookShellcode, shellcodeSize);
        vm_deallocate(task, remoteFormatStr, formatStrSize);
        return KERN_FAILURE;
    }
    
    // Hook shellcode ARM64 instructions
    uint32_t hookCode[64];
    int idx = 0;
    
    // Save registers we'll use
    hookCode[idx++] = 0xa9bf7bfd; // stp x29, x30, [sp, #-0x10]!
    hookCode[idx++] = 0xa9bf73fb; // stp x27, x28, [sp, #-0x10]!
    hookCode[idx++] = 0xa9bf6bf9; // stp x25, x26, [sp, #-0x10]!
    hookCode[idx++] = 0xa9bf63f7; // stp x23, x24, [sp, #-0x10]!
    hookCode[idx++] = 0xa9bf5bf5; // stp x21, x22, [sp, #-0x10]!
    hookCode[idx++] = 0xa9bf53f3; // stp x19, x20, [sp, #-0x10]!
    
    // Backup SSL_write arguments (x0, x1, x2)
    hookCode[idx++] = 0xaa0003f3; // mov x19, x0 (ssl)
    hookCode[idx++] = 0xaa0103f4; // mov x20, x1 (buf)
    hookCode[idx++] = 0xaa0203f5; // mov x21, x2 (num)
    
    // Load format string address into x0
    // movz x0, #lower16(remoteFormatStr)
    hookCode[idx++] = 0xd2800000 | ((remoteFormatStr & 0xFFFF) << 5); // movz x0, #imm
    // movk x0, #bits[16:31], lsl #16
    hookCode[idx++] = generate_movk(0, (remoteFormatStr >> 16) & 0xFFFF, 16);
    // movk x0, #bits[32:47], lsl #32
    hookCode[idx++] = generate_movk(0, (remoteFormatStr >> 32) & 0xFFFF, 32);
    // movk x0, #bits[48:63], lsl #48
    hookCode[idx++] = generate_movk(0, (remoteFormatStr >> 48) & 0xFFFF, 48);
    
    // Setup printf arguments: x0=format, x1=ssl, x2=buf, x3=num, x4=buf (for %s)
    hookCode[idx++] = 0xaa1303e1; // mov x1, x19 (ssl)
    hookCode[idx++] = 0xaa1403e2; // mov x2, x20 (buf)
    hookCode[idx++] = 0xaa1503e3; // mov x3, x21 (num)
    hookCode[idx++] = 0xaa1403e4; // mov x4, x20 (buf for string)
    
    // Load printf address and call it
    // movz x9, #lower16(printfAddr)
    hookCode[idx++] = 0xd2800009 | ((printfAddr & 0xFFFF) << 5);
    hookCode[idx++] = generate_movk(9, (printfAddr >> 16) & 0xFFFF, 16);
    hookCode[idx++] = generate_movk(9, (printfAddr >> 32) & 0xFFFF, 32);
    hookCode[idx++] = generate_movk(9, (printfAddr >> 48) & 0xFFFF, 48);
    hookCode[idx++] = 0xd63f0120; // blr x9
    
    // Restore original arguments
    hookCode[idx++] = 0xaa1303e0; // mov x0, x19
    hookCode[idx++] = 0xaa1403e1; // mov x1, x20
    hookCode[idx++] = 0xaa1503e2; // mov x2, x21
    
    // Restore registers
    hookCode[idx++] = 0xa8c153f3; // ldp x19, x20, [sp], #0x10
    hookCode[idx++] = 0xa8c15bf5; // ldp x21, x22, [sp], #0x10
    hookCode[idx++] = 0xa8c163f7; // ldp x23, x24, [sp], #0x10
    hookCode[idx++] = 0xa8c16bf9; // ldp x25, x26, [sp], #0x10
    hookCode[idx++] = 0xa8c173fb; // ldp x27, x28, [sp], #0x10
    hookCode[idx++] = 0xa8c17bfd; // ldp x29, x30, [sp], #0x10
    
    // Jump to trampoline (which has original instructions + jump back)
    int64_t toTrampoline = ((int64_t)trampolineAddr - (int64_t)(hookAddr + idx * 4)) / 4;
    hookCode[idx++] = 0x14000000 | (toTrampoline & 0x3FFFFFF); // b trampoline
    
    // Write hook shellcode to remote process
    kr = vm_write(task, hookShellcode, (vm_address_t)hookCode, idx * sizeof(uint32_t));
    if (kr != KERN_SUCCESS) {
        printf("[hookSSLWrite] ERROR: Failed to write hook code: %s\n", mach_error_string(kr));
        vm_deallocate(task, hookShellcode, shellcodeSize);
        vm_deallocate(task, remoteFormatStr, formatStrSize);
        return kr;
    }
    
    // 6. Build trampoline (original instructions + jump back to SSL_write+16)
    uint32_t trampolineCode[8];
    int tIdx = 0;
    
    // Copy original 4 instructions
    trampolineCode[tIdx++] = originalInsts[0];
    trampolineCode[tIdx++] = originalInsts[1];
    trampolineCode[tIdx++] = originalInsts[2];
    trampolineCode[tIdx++] = originalInsts[3];
    
    // Load address of SSL_write+16 and jump there
    uint64_t returnAddr = sslWriteAddr + 16;
    // movz x16, #lower16
    trampolineCode[tIdx++] = 0xd2800010 | ((returnAddr & 0xFFFF) << 5);
    trampolineCode[tIdx++] = generate_movk(16, (returnAddr >> 16) & 0xFFFF, 16);
    trampolineCode[tIdx++] = generate_movk(16, (returnAddr >> 32) & 0xFFFF, 32);
    trampolineCode[tIdx++] = generate_movk(16, (returnAddr >> 48) & 0xFFFF, 48);
    trampolineCode[tIdx++] = generate_br(16); // br x16
    
    kr = vm_write(task, trampolineAddr, (vm_address_t)trampolineCode, tIdx * sizeof(uint32_t));
    if (kr != KERN_SUCCESS) {
        printf("[hookSSLWrite] ERROR: Failed to write trampoline: %s\n", mach_error_string(kr));
        vm_deallocate(task, hookShellcode, shellcodeSize);
        vm_deallocate(task, remoteFormatStr, formatStrSize);
        return kr;
    }
    
    // 7. Patch SSL_write to jump to our hook
    uint32_t patchInsts[4];
    patchInsts[0] = 0x14000000 | (branchOffset & 0x3FFFFFF); // b hook
    patchInsts[1] = 0xd503201f; // nop
    patchInsts[2] = 0xd503201f; // nop
    patchInsts[3] = 0xd503201f; // nop
    
    // Make SSL_write writable
    kr = vm_protect(task, sslWriteAddr, 16, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        printf("[hookSSLWrite] ERROR: Failed to make SSL_write writable: %s\n", mach_error_string(kr));
        vm_deallocate(task, hookShellcode, shellcodeSize);
        vm_deallocate(task, remoteFormatStr, formatStrSize);
        return kr;
    }
    
    // Write patch
    kr = vm_write(task, sslWriteAddr, (vm_address_t)patchInsts, sizeof(patchInsts));
    if (kr != KERN_SUCCESS) {
        printf("[hookSSLWrite] ERROR: Failed to patch SSL_write: %s\n", mach_error_string(kr));
        vm_deallocate(task, hookShellcode, shellcodeSize);
        vm_deallocate(task, remoteFormatStr, formatStrSize);
        return kr;
    }
    
    // Restore execute permission
    kr = vm_protect(task, sslWriteAddr, 16, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    
    // 8. Invalidate instruction cache
    vm_address_t libSystemKernelAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_kernel.dylib");
    uint64_t sys_icache_invalidate = remoteDlSym(task, libSystemKernelAddr, "_sys_icache_invalidate");
    
    if (sys_icache_invalidate) {
        arbCall(task, pthread, NULL, true, sys_icache_invalidate, 2, sslWriteAddr, 16);
        arbCall(task, pthread, NULL, true, sys_icache_invalidate, 2, hookShellcode, shellcodeSize);
    }
    
    printf("[hookSSLWrite] ✓ SSL_write hooked successfully!\n");
    printf("[hookSSLWrite]   Hook shellcode at: 0x%llX\n", (unsigned long long)hookShellcode);
    printf("[hookSSLWrite]   Trampoline at: 0x%llX\n", (unsigned long long)trampolineAddr);
    
    return KERN_SUCCESS;
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

	// Hook SSL_write to log buffer contents
    kr = hookSSLWrite(task, pthread, sslWriteAddr, allImageInfoAddr);
    if (kr != KERN_SUCCESS) {
        printf("[injectDylibViaRop] Failed to hook SSL_write\n");
    }

    // Don't terminate pthread yet - we need it for the hook to work
    // thread_terminate(pthread);
    printf("[injectDylibViaRop] Hook installed, keeping pthread alive for logging...\n");
	
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