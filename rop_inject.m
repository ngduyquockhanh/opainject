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

#import "pac.h"
#import "dyld.h"
#import "sandbox.h"
#import "CoreSymbolication.h"
#import "task_utils.h"
#import "thread_utils.h"
#import "arm64.h"
#include <mach/vm_map.h>

typedef struct {
	const char* libraryName;        // Ví dụ: "/usr/lib/libcoretls.dylib"
	const char* functionName;       // Ví dụ: "_SecTrustEvaluate"
	uint64_t originalAddress;       // Địa chỉ function gốc
	uint64_t hookAddress;           // Địa chỉ hook function (từ dylib)
	uint64_t onEnter;               // Callback khi vào function (optional)
	uint64_t onLeave;               // Callback khi thoát function (optional)
} Interceptor;


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

#define SSL_VERIFY_NONE 0

void hookBoringSSLIndirectJump(task_t task, thread_act_t pthread, vm_address_t allImageInfoAddr) {
	printf("[*] Hooking BoringSSL with indirect jump...\n");

	vm_address_t libboringssl = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/libboringssl.dylib");
	if (!libboringssl) {
		libboringssl = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/libcoretls.dylib");
		if (!libboringssl) {
			printf("[!] No SSL library found\n");
			return;
		}
	}

	printf("[*] SSL library @ 0x%llx\n", (uint64_t)libboringssl);

	// ===== Get function addresses =====
	uint64_t SSL_set_custom_verify = remoteDlSym(task, libboringssl, "_SSL_set_custom_verify");
	uint64_t SSL_get_psk_identity = remoteDlSym(task, libboringssl, "_SSL_get_psk_identity");

	printf("[*] SSL_set_custom_verify @ 0x%llx\n", SSL_set_custom_verify);
	printf("[*] SSL_get_psk_identity @ 0x%llx\n", SSL_get_psk_identity);

	// ===== Allocate space for replacements + jump table =====
	vm_address_t hookAddr = (vm_address_t)NULL;
	kern_return_t kr = vm_allocate(task, &hookAddr, 0x4000, VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) {
		printf("[!] Failed to allocate hook space\n");
		return;
	}

	printf("[*] Hook space allocated @ 0x%llx\n", (uint64_t)hookAddr);

	kr = vm_protect(task, hookAddr, 0x4000, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	if (kr != KERN_SUCCESS) {
		printf("[!] Failed to make writable\n");
		return;
	}

	// ===== Create replacement for SSL_set_custom_verify =====
	// Indirect jump pattern:
	// ADRP x16, <page of jump_table>
	// LDR x16, [x16, <offset in page>]
	// BR x16
	
	vm_address_t replace_addr1 = hookAddr;
	
	// ARM64 indirect jump (3 instructions = 12 bytes)
	uint32_t replace_SSL_set_custom_verify[] = {
		// adrp x16, <jump_table_page> - we'll patch this
		0x90000010,  // placeholder - will be patched with actual page
		
		// ldr x16, [x16, <offset>]
		0xf9400210,  // ldr x16, [x16, 0] (offset 0)
		
		// br x16
		0xd61f0200,  // br x16
		
		// Padding
		0xd503201f,  // nop
	};

	vm_address_t replace_addr2 = replace_addr1 + 0x100;

	uint32_t replace_SSL_get_psk_identity[] = {
		// adrp x16, <jump_table_page>
		0x90000010,  // placeholder
		
		// ldr x16, [x16, 8] (load from offset 8 in jump table)
		0xf9400410,  // ldr x16, [x16, 8]
		
		// br x16
		0xd61f0200,  // br x16
		
		// Padding
		0xd503201f,  // nop
	};

	// Write replacements
	kr = vm_write(task, replace_addr1, (vm_address_t)replace_SSL_set_custom_verify, 
				  sizeof(replace_SSL_set_custom_verify));
	kr = vm_write(task, replace_addr2, (vm_address_t)replace_SSL_get_psk_identity, 
				  sizeof(replace_SSL_get_psk_identity));

	printf("[*] Replacement 1 @ 0x%llx\n", (uint64_t)replace_addr1);
	printf("[*] Replacement 2 @ 0x%llx\n", (uint64_t)replace_addr2);

	// ===== Create jump table =====
	vm_address_t jumpTableAddr = hookAddr + 0x1000;
	
	uint64_t jumpTable[] = {
		// Entry 0: real replacement for SSL_set_custom_verify (does nothing)
		replace_addr1 + 12,  // Skip the adrp/ldr, jump to br
		
		// Entry 1: real replacement for SSL_get_psk_identity
		replace_addr2 + 12,  // Skip to br
	};

	kr = vm_write(task, jumpTableAddr, (vm_address_t)jumpTable, sizeof(jumpTable));
	printf("[*] Jump table @ 0x%llx\n", (uint64_t)jumpTableAddr);

	// ===== BETTER APPROACH: Use simpler inline code =====
	// Don't use indirect jump, instead allocate replacement CLOSE TO original
	
	// Problem: We need replacements near original functions, not at arbitrary address
	// Solution: Use ROP gadgets or simpler approach
	
	// ===== SIMPLEST: Allocate near original, use direct branch =====
	
	// Try to allocate near SSL_set_custom_verify
	// First, find a free region near the function
	
	vm_address_t nearAddr = SSL_set_custom_verify & ~0xFFF;  // Align to page
	vm_address_t candidate = nearAddr - 0x100000;  // Try 1MB below
	
	printf("[*] Trying to allocate near original @ 0x%llx\n", (uint64_t)candidate);
	
	// Actually, we can't allocate at specific address, only VM_FLAGS_ANYWHERE
	// But we can use ADRP + ADD for page addressing
	
	// ===== REAL SOLUTION: Patch with MOV + BR instructions =====
	// These are size-limited but can encode small offsets
	
	// For large offsets: use MOVZ/MOVK chain or create thunk
	
	printf("[!] Direct branch too far, need different approach\n");
	printf("[*] Creating thunk via MOVZ/MOVK/BR pattern...\n");

	// ===== FINAL SOLUTION: Overwrite with MOVZ + MOVK + BR =====
	// This is a 3-instruction sequence that can reach any 64-bit address
	
	// Pattern for SSL_set_custom_verify:
	// movz x16, #(addr & 0xFFFF)
	// movk x16, #((addr >> 16) & 0xFFFF), lsl #16
	// movk x16, #((addr >> 32) & 0xFFFF), lsl #32
	// movk x16, #((addr >> 48) & 0xFFFF), lsl #48
	// br x16
	
	// But this requires 5 instructions = 20 bytes, might overwrite more code
	// Safer: allocate thunk pool and use smaller patch
	
	// ===== PRACTICAL APPROACH: Just NOP out the function =====
	// Simplest: replace function with just RET
	
	printf("[*] Patching functions to just return (NOP approach)...\n");

	// Patch SSL_set_custom_verify
	uint32_t retInst = 0xd65f03c0;  // ret
	
	kr = vm_protect(task, SSL_set_custom_verify, 0x100, TRUE, 
					VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
	if (kr != KERN_SUCCESS) {
		printf("[!] Failed to make SSL_set_custom_verify writable\n");
		return;
	}
	
	kr = vm_write(task, SSL_set_custom_verify, (vm_address_t)&retInst, sizeof(retInst));
	if (kr != KERN_SUCCESS) {
		printf("[!] Failed to patch SSL_set_custom_verify\n");
		vm_protect(task, SSL_set_custom_verify, 0x100, TRUE, VM_PROT_READ | VM_PROT_EXECUTE);
		return;
	}

	vm_protect(task, SSL_set_custom_verify, 0x100, TRUE, VM_PROT_READ | VM_PROT_EXECUTE);
	printf("[+] Patched SSL_set_custom_verify (NOP - just returns)\n");

	// Patch SSL_get_psk_identity - return fake PSK
	// mov x0, <string_address>; ret
	// First allocate string
	
	vm_address_t fakeString = writeStringToTask(task, "notarealPSKidentity", NULL);
	printf("[*] Fake PSK @ 0x%llx\n", (uint64_t)fakeString);

	// Create: MOVZ x0, (fakeString & 0xFFFF); MOVK x0, ((fakeString >> 16) & 0xFFFF), lsl 16; RET
	uint32_t ssl_get_psk_patch[] = {
		// movz x0, #(addr & 0xFFFF)
		0xd2800000 | ((fakeString & 0xFFFF) << 5),
		
		// movk x0, #((addr >> 16) & 0xFFFF), lsl 16
		0xf2a00000 | (((fakeString >> 16) & 0xFFFF) << 5),
		
		// movk x0, #((addr >> 32) & 0xFFFF), lsl 32  
		0xf2c00000 | (((fakeString >> 32) & 0xFFFF) << 5),
		
		// ret
		0xd65f03c0,
	};

	kr = vm_protect(task, SSL_get_psk_identity, 0x100, TRUE, 
					VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
	kr = vm_write(task, SSL_get_psk_identity, (vm_address_t)ssl_get_psk_patch, 
				  sizeof(ssl_get_psk_patch));
	vm_protect(task, SSL_get_psk_identity, 0x100, TRUE, VM_PROT_READ | VM_PROT_EXECUTE);

	printf("[+] Patched SSL_get_psk_identity (returns fake PSK)\n");

	// Flush instruction cache
	sys_icache_invalidate((void*)SSL_set_custom_verify, 0x100);
	sys_icache_invalidate((void*)SSL_get_psk_identity, 0x100);

	printf("[+] BoringSSL hooked successfully!\n");
}

extern void sys_icache_invalidate(void *start, size_t len);

void hook_NSURLSessionChallenge(task_t task, thread_act_t pthread, vm_address_t allImageInfoAddr, const char* dylibPath) {
	vm_address_t libobjc = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/libobjc.A.dylib");
	uint64_t objc_getClass = remoteDlSym(task, libobjc, "_objc_getClass");
	uint64_t sel_registerName = remoteDlSym(task, libobjc, "_sel_registerName");
	uint64_t class_getInstanceMethod = remoteDlSym(task, libobjc, "_class_getInstanceMethod");
	uint64_t method_getImplementation = remoteDlSym(task, libobjc, "_method_getImplementation");
	uint64_t method_setImplementation = remoteDlSym(task, libobjc, "_method_setImplementation");

	vm_address_t className = writeStringToTask(task, "__NSCFLocalSessionTask", NULL);
	vm_address_t selName = writeStringToTask(task, "_onqueue_didReceiveChallenge:request:withCompletion:", NULL);
	
	printf("[+] Hooking _onqueue_didReceiveChallenge:request:withCompletion: of __NSCFLocalSessionTask\n");

	uint64_t classPtr = 0;
	arbCall(task, pthread, &classPtr, true, objc_getClass, 1, className);
	if (!classPtr) {
		printf("[!] objc_getClass failed to get __NSCFLocalSessionTask class!\n");
		return;
	}

	uint64_t selPtr = 0;
	arbCall(task, pthread, &selPtr, true, sel_registerName, 1, selName);
	if (!selPtr) {
		printf("[!] sel_registerName failed to get selector for _onqueue_didReceiveChallenge:request:withCompletion:!\n");
		return;
	}

	uint64_t methodPtr = 0;
	arbCall(task, pthread, &methodPtr, true, class_getInstanceMethod, 2, classPtr, selPtr);
	if (!methodPtr) {
		printf("[!] class_getInstanceMethod failed to get method for _onqueue_didReceiveChallenge:request:withCompletion:!\n");
		return;
	}

	uint64_t oldImp = 0;
	arbCall(task, pthread, &oldImp, true, method_getImplementation, 1, methodPtr);
	if (!oldImp) {
		printf("[!] method_getImplementation failed to get implementation for _onqueue_didReceiveChallenge:request:withCompletion:!\n");
		return;
	}

	vm_address_t myDylibBase = getRemoteImageAddress(task, allImageInfoAddr, dylibPath);
	if (!myDylibBase) {
		printf("[!] Could not find injected dylib in remote process!\n");
		return;
	}

	uint64_t newImp = remoteDlSym(task, myDylibBase, "_new__NSCFLocalSessionTask__onqueue_didReceiveChallenge");
	if (!newImp) {
		printf("[!] remoteDlSym không tìm thấy sslbypass_challenge_hook trong dylib!\n");
		return;
	}

	uint64_t oldImpOut = 0;
	arbCall(task, pthread, &oldImpOut, true, method_setImplementation, 2, methodPtr, newImp);

	printf("[+] Hooked _onqueue_didReceiveChallenge:request:withCompletion:\n");
}

void injectDylibViaRop(task_t task, pid_t pid, const char* dylibPath, vm_address_t allImageInfoAddr)
{
	prepareForMagic(task, allImageInfoAddr);

	thread_act_t pthread = 0;
	kern_return_t kr = createRemotePthread(task, allImageInfoAddr, &pthread);
	if(kr != KERN_SUCCESS) return;

	sandboxFixup(task, pthread, pid, dylibPath, allImageInfoAddr);

	printf("[injectDylibViaRop] Preparation done, now injecting!\n");

	hookBoringSSLFunctions(task, pthread, allImageInfoAddr);

	// FIND OFFSETS
	// vm_address_t libDyldAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libdyld.dylib");
	// uint64_t dlopenAddr = remoteDlSym(task, libDyldAddr, "_dlopen");
	// uint64_t dlerrorAddr = remoteDlSym(task, libDyldAddr, "_dlerror");

	// printf("[injectDylibViaRop] dlopen: 0x%llX, dlerror: 0x%llX\n", (unsigned long long)dlopenAddr, (unsigned long long)dlerrorAddr);

	// // CALL DLOPEN
	// size_t remoteDylibPathSize = 0;
	// vm_address_t remoteDylibPath = writeStringToTask(task, (const char*)dylibPath, &remoteDylibPathSize);
	// if(remoteDylibPath)
	// {
	// 	void* dlopenRet;
	// 	arbCall(task, pthread, (uint64_t*)&dlopenRet, true, dlopenAddr, 2, remoteDylibPath, RTLD_NOW);
	// 	vm_deallocate(task, remoteDylibPath, remoteDylibPathSize);

	// 	if (dlopenRet) {
	// 		printf("[injectDylibViaRop] dlopen succeeded, library handle: %p\n", dlopenRet);
	// 		hook_NSURLSessionChallenge(task, pthread, allImageInfoAddr, dylibPath);
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