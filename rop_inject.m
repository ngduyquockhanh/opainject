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

#import "pac.h"
#import "dyld.h"
#import "sandbox.h"
#import "CoreSymbolication.h"
#import "task_utils.h"
#import "thread_utils.h"
#import "arm64.h"


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

// void injectDylibViaRop(task_t task, pid_t pid, const char* dylibPath, vm_address_t allImageInfoAddr)
// {
// 	prepareForMagic(task, allImageInfoAddr);

// 	thread_act_t pthread = 0;
// 	kern_return_t kr = createRemotePthread(task, allImageInfoAddr, &pthread);
// 	if(kr != KERN_SUCCESS) return;

// 	sandboxFixup(task, pthread, pid, dylibPath, allImageInfoAddr);

// 	printf("[injectDylibViaRop] Preparation done, now injecting!\n");

// 	// FIND OFFSETS
// 	vm_address_t libDyldAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libdyld.dylib");
// 	uint64_t dlopenAddr = remoteDlSym(task, libDyldAddr, "_dlopen");
// 	uint64_t dlerrorAddr = remoteDlSym(task, libDyldAddr, "_dlerror");

// 	printf("[injectDylibViaRop] dlopen: 0x%llX, dlerror: 0x%llX\n", (unsigned long long)dlopenAddr, (unsigned long long)dlerrorAddr);

// 	// CALL DLOPEN
// 	size_t remoteDylibPathSize = 0;
// 	vm_address_t remoteDylibPath = writeStringToTask(task, (const char*)dylibPath, &remoteDylibPathSize);
// 	if(remoteDylibPath)
// 	{
// 		void* dlopenRet;
// 		arbCall(task, pthread, (uint64_t*)&dlopenRet, true, dlopenAddr, 2, remoteDylibPath, RTLD_NOW);
// 		vm_deallocate(task, remoteDylibPath, remoteDylibPathSize);

// 		if (dlopenRet) {
// 			printf("[injectDylibViaRop] dlopen succeeded, library handle: %p\n", dlopenRet);

// 			sleep(1); 
// 			printf("[injectDylibViaRop] Checking if dylib loaded...\n");
// 			vm_address_t myDylibBase = getRemoteImageAddress(task, allImageInfoAddr, dylibPath);
// 			printf("[injectDylibViaRop] myDylibBase: 0x%llx\n", myDylibBase);
			
// 			if (myDylibBase) {
// 				uint64_t myFuncAddr = remoteDlSym(task, myDylibBase, "_my_entrypoint");
// 				if (myFuncAddr) {
// 					uint64_t result = 0;
// 					arbCall(task, pthread, &result, true, myFuncAddr, 0);
// 					printf("[injectDylibViaRop] Called my_entrypoint! Result: %llu\n", result);
// 				} else {
// 					printf("[injectDylibViaRop] Could not find my_entrypoint symbol.\n");
// 				}
// 			} else {
// 				printf("[injectDylibViaRop] Could not find base address of injected dylib.\n");
// 			}
// 		}
// 		else {
// 			uint64_t remoteErrorString = 0;
// 			arbCall(task, pthread, (uint64_t*)&remoteErrorString, true, dlerrorAddr, 0);
// 			char *errorString = task_copy_string(task, remoteErrorString);
// 			printf("[injectDylibViaRop] dlopen failed, error:\n%s\n", errorString);
// 			free(errorString);
// 		}
// 	}

// 	thread_terminate(pthread);
// }


// Helper: Write a stub that returns 0 (errSecSuccess) for OSStatus functions
vm_address_t writeReturnZeroStub(task_t task) {
	uint32_t stub[] = { 0x52800000, 0xd65f03c0 }; // mov w0, #0; ret
	vm_address_t remoteStub = 0;
	kern_return_t kr = vm_allocate(task, &remoteStub, sizeof(stub), VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) return 0;
	kr = vm_protect(task, remoteStub, sizeof(stub), FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
	if (kr != KERN_SUCCESS) return 0;
	kr = vm_write(task, remoteStub, (vm_address_t)stub, sizeof(stub));
	if (kr != KERN_SUCCESS) return 0;
	return remoteStub;
}

// Helper: Write a stub that returns 1 (true/YES)
vm_address_t writeReturnOneStub(task_t task) {
	uint32_t stub[] = { 0x52800020, 0xd65f03c0 }; // mov w0, #1; ret
	vm_address_t remoteStub = 0;
	kern_return_t kr = vm_allocate(task, &remoteStub, sizeof(stub), VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) return 0;
	kr = vm_protect(task, remoteStub, sizeof(stub), FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
	if (kr != KERN_SUCCESS) return 0;
	kr = vm_write(task, remoteStub, (vm_address_t)stub, sizeof(stub));
	if (kr != KERN_SUCCESS) return 0;
	return remoteStub;
}

// Patch a C function in the target process to always return 0
void hookCFunctionReturnZero(task_t task, thread_act_t pthread, vm_address_t allImageInfoAddr, const char* libPath, const char* symName) {
	vm_address_t libAddr = getRemoteImageAddress(task, allImageInfoAddr, libPath);
	if (!libAddr) {
		printf("[-] Could not find %s\n", libPath);
		return;
	}
	uint64_t funcAddr = remoteDlSym(task, libAddr, symName);
	if (!funcAddr) {
		printf("[-] Could not find symbol %s\n", symName);
		return;
	}
	vm_address_t stub = writeReturnZeroStub(task);
	if (!stub) {
		printf("[-] Could not allocate stub\n");
		return;
	}
	uint32_t branch = 0x14000000 | (((stub - funcAddr) >> 2) & 0x3FFFFFF);
	vm_write(task, funcAddr, (vm_address_t)&branch, sizeof(branch));
	printf("[+] Patched %s to always return 0\n", symName);
}

// Patch a C function in the target process to always return 1 (true/YES)
void hookCFunctionReturnOne(task_t task, thread_act_t pthread, vm_address_t allImageInfoAddr, const char* libPath, const char* symName) {
	vm_address_t libAddr = getRemoteImageAddress(task, allImageInfoAddr, libPath);
	if (!libAddr) {
		printf("[-] Could not find %s\n", libPath);
		return;
	}
	uint64_t funcAddr = remoteDlSym(task, libAddr, symName);
	if (!funcAddr) {
		printf("[-] Could not find symbol %s\n", symName);
		return;
	}
	vm_address_t stub = writeReturnOneStub(task);
	if (!stub) {
		printf("[-] Could not allocate stub\n");
		return;
	}
	uint32_t branch = 0x14000000 | (((stub - funcAddr) >> 2) & 0x3FFFFFF);
	vm_write(task, funcAddr, (vm_address_t)&branch, sizeof(branch));
	printf("[+] Patched %s to always return 1\n", symName);
}

// Helper: Write a stub for Objective-C methods that disables pinning
vm_address_t writeObjCBypassStub(task_t task) {
	uint32_t stub[] = { 0xd65f03c0 }; // ret
	vm_address_t remoteStub = 0;
	kern_return_t kr = vm_allocate(task, &remoteStub, sizeof(stub), VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) return 0;
	kr = vm_protect(task, remoteStub, sizeof(stub), FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
	if (kr != KERN_SUCCESS) return 0;
	kr = vm_write(task, remoteStub, (vm_address_t)stub, sizeof(stub));
	if (kr != KERN_SUCCESS) return 0;
	return remoteStub;
}

// Patch an Objective-C instance method to a stub
void hookObjCMethodBypass(task_t task, thread_act_t pthread, vm_address_t allImageInfoAddr, const char* className, const char* selName) {
	vm_address_t libObjcAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/libobjc.A.dylib");
	uint64_t objc_getClassAddr = remoteDlSym(task, libObjcAddr, "_objc_getClass");
	uint64_t sel_registerNameAddr = remoteDlSym(task, libObjcAddr, "_sel_registerName");
	uint64_t class_getInstanceMethodAddr = remoteDlSym(task, libObjcAddr, "_class_getInstanceMethod");
	uint64_t method_setImplementationAddr = remoteDlSym(task, libObjcAddr, "_method_setImplementation");

	size_t classLen, selLen;
	vm_address_t remoteClassName = writeStringToTask(task, className, &classLen);
	vm_address_t remoteSelName = writeStringToTask(task, selName, &selLen);

	uint64_t classPtr = 0;
	arbCall(task, pthread, &classPtr, true, objc_getClassAddr, 1, remoteClassName);
	uint64_t selPtr = 0;
	arbCall(task, pthread, &selPtr, true, sel_registerNameAddr, 1, remoteSelName);
	uint64_t methodPtr = 0;
	arbCall(task, pthread, &methodPtr, true, class_getInstanceMethodAddr, 2, classPtr, selPtr);
	vm_address_t stub = writeObjCBypassStub(task);
	if (!stub) {
		printf("[-] Could not allocate stub for %s %s\n", className, selName);
		return;
	}
	arbCall(task, pthread, NULL, true, method_setImplementationAddr, 2, methodPtr, stub);
	vm_deallocate(task, remoteClassName, classLen);
	vm_deallocate(task, remoteSelName, selLen);
	printf("[+] Patched [%s %s] to bypass SSL pinning\n", className, selName);
}

// Patch all known SSL pinning related C functions and Objective-C methods
void sslkillswitch_rop_hooks(task_t task, thread_act_t pthread, vm_address_t allImageInfoAddr) {
	// Security.framework
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/System/Library/Frameworks/Security.framework/Security", "_SecTrustEvaluate");
	hookCFunctionReturnOne(task, pthread, allImageInfoAddr, "/System/Library/Frameworks/Security.framework/Security", "_SecTrustEvaluateWithError");
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/System/Library/Frameworks/Security.framework/Security", "_SecTrustEvaluateAsync");
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/System/Library/Frameworks/Security.framework/Security", "_SecTrustEvaluateAsyncWithError");
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/System/Library/Frameworks/Security.framework/Security", "_SecTrustEvaluateFastAsync");
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/System/Library/Frameworks/Security.framework/Security", "_SecTrustSetPolicies");
	hookCFunctionReturnOne(task, pthread, allImageInfoAddr, "/System/Library/Frameworks/Security.framework/Security", "_SecKeyVerifySignature");
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/System/Library/Frameworks/Security.framework/Security", "_SecKeyRawVerify");
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/System/Library/Frameworks/Security.framework/Security", "_SSLHandshake");
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/System/Library/Frameworks/Security.framework/Security", "_SSLSetSessionOption");
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/System/Library/Frameworks/Security.framework/Security", "_SSLCreateContext");

	// BoringSSL
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/usr/lib/libboringssl.dylib", "SSL_CTX_set_custom_verify");
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/usr/lib/libboringssl.dylib", "SSL_set_custom_verify");
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/usr/lib/libboringssl.dylib", "SSL_get_psk_identity");

	// libsystem_coretls
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/usr/lib/system/libsystem_coretls.dylib", "tls_helper_create_peer_trust");
	hookCFunctionReturnZero(task, pthread, allImageInfoAddr, "/usr/lib/libnetwork.dylib", "nw_tls_create_peer_trust");

	// SecIsInternalRelease
	hookCFunctionReturnOne(task, pthread, allImageInfoAddr, "/System/Library/Frameworks/Security.framework/Security", "_SecIsInternalRelease");

	// AFNetworking
	hookObjCMethodBypass(task, pthread, allImageInfoAddr, "AFSecurityPolicy", "setSSLPinningMode:");
	hookObjCMethodBypass(task, pthread, allImageInfoAddr, "AFSecurityPolicy", "setAllowInvalidCertificates:");
	hookObjCMethodBypass(task, pthread, allImageInfoAddr, "AFSecurityPolicy", "policyWithPinningMode:");
	hookObjCMethodBypass(task, pthread, allImageInfoAddr, "AFSecurityPolicy", "policyWithPinningMode:withPinnedCertificates:");

	// TrustKit
	hookObjCMethodBypass(task, pthread, allImageInfoAddr, "TSKPinningValidator", "evaluateTrust:forHostname:");

	// // NSURLSessionDelegate
	// hookObjCMethodBypass(task, pthread, allImageInfoAddr, "__NSCFLocalSessionTask", "_onqueue_didReceiveChallenge:request:withCompletion:");
	// hookObjCMethodBypass(task, pthread, allImageInfoAddr, "__NSCFTCPIOStreamTask", "_onqueue_sendSessionChallenge:completionHandler:");

	// // CustomURLConnectionDelegate
	// hookObjCMethodBypass(task, pthread, allImageInfoAddr, "CustomURLConnectionDelegate", "isFingerprintTrusted:");
}

void injectDylibViaRop(task_t task, pid_t pid, const char* dylibPath, vm_address_t allImageInfoAddr)
{
	prepareForMagic(task, allImageInfoAddr);

	thread_act_t pthread = 0;
	kern_return_t kr = createRemotePthread(task, allImageInfoAddr, &pthread);
	if(kr != KERN_SUCCESS) return;

	sandboxFixup(task, pthread, pid, dylibPath, allImageInfoAddr);

	printf("[injectDylibViaRop] Preparation done, now injecting!\n");

	sslkillswitch_rop_hooks(task, pthread, allImageInfoAddr);
	

	// // Lấy base address của libobjc.A.dylib
	// vm_address_t libObjcAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/libobjc.A.dylib");
	// printf("libobjc.A.dylib base: 0x%llx\n", (unsigned long long)libObjcAddr);

	// // Resolve địa chỉ hàm objc_copyClassList
	// uint64_t objcCopyClassListAddr = remoteDlSym(task, libObjcAddr, "_objc_copyClassList");
	// printf("objc_copyClassList address: 0x%llx\n", (unsigned long long)objcCopyClassListAddr);


	// size_t remoteCountLen = sizeof(uint32_t);
	// vm_address_t remoteCountPtr = 0;
	// kr = vm_allocate(task, &remoteCountPtr, remoteCountLen, VM_FLAGS_ANYWHERE);
	// if (kr != KERN_SUCCESS) {
	// 	printf("ERROR: Unable to allocate memory for count\n");
	// 	return;
	// }

	// uint64_t classArrayPtr = 0;
	// arbCall(task, pthread, &classArrayPtr, true, objcCopyClassListAddr, 1, remoteCountPtr);
	// printf("[injectDylibViaRop] objc_copyClassList returned pointer: 0x%llx\n", classArrayPtr);

	// uint32_t classCount = 0;
	// vm_size_t outSize = 0;
	// kr = vm_read_overwrite(task, remoteCountPtr, sizeof(classCount), (vm_address_t)&classCount, &outSize);
	// printf("Number of classes: %u\n", classCount);

	// for (uint32_t i = 0; i < classCount; i++) {
	// 	uint64_t classPtr = 0;
	// 	kr = vm_read_overwrite(task, classArrayPtr + i * sizeof(uint64_t), sizeof(uint64_t), (vm_address_t)&classPtr, &outSize);
	// 	if (kr != KERN_SUCCESS) continue;

	// 	// Gọi ROP để lấy tên class: class_getName
	// 	uint64_t classGetNameAddr = remoteDlSym(task, libObjcAddr, "_class_getName");
	// 	uint64_t namePtr = 0;
	// 	arbCall(task, pthread, &namePtr, true, classGetNameAddr, 1, classPtr);

	// 	if (namePtr) {
	// 		char *className = task_copy_string(task, namePtr);
	// 		printf("Class[%u]: %s\n", i, className ? className : "(null)");
	// 		if (className) free(className);
	// 	}
	// }
	// vm_deallocate(task, remoteCountPtr, remoteCountLen);

	thread_terminate(pthread);
}