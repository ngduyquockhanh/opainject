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

	// === BREAKPOINT DEBUG: Monitor SSL_write ===
	if (sslWriteAddr) {
		printf("[DEBUG] Setting breakpoint at SSL_write: 0x%llX\n", sslWriteAddr);
		
		// 1. Suspend all threads
		thread_act_array_t threads;
		mach_msg_type_number_t thread_count;
		kr = task_threads(task, &threads, &thread_count);
		if (kr == KERN_SUCCESS) {
			for (int i = 0; i < thread_count; i++) {
				thread_suspend(threads[i]);
			}
		}
		
		// 2. Save original instruction (ARM64 = 4 bytes)
		uint32_t original_insn = 0;
		vm_size_t read_size = 4;
		kr = vm_read_overwrite(task, sslWriteAddr, 4, 
		                      (vm_address_t)&original_insn, &read_size);
		if (kr == KERN_SUCCESS) {
			printf("[DEBUG] Original instruction: 0x%08X\n", original_insn);
			
			// 3. Write BRK #0 instruction
			uint32_t brk_insn = 0xD4200000;  // BRK #0 (ARM64)
			kr = vm_write(task, sslWriteAddr, (vm_offset_t)&brk_insn, 4);
			if (kr == KERN_SUCCESS) {
				printf("[DEBUG] Breakpoint set successfully\n");
			} else {
				printf("[DEBUG] ERROR: Failed to write breakpoint: %s\n", mach_error_string(kr));
			}
		} else {
			printf("[DEBUG] ERROR: Failed to read original instruction: %s\n", mach_error_string(kr));
		}
		
		// 4. Setup exception port to receive breakpoint exceptions
		mach_port_t exception_port = MACH_PORT_NULL;
		kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port);
		if (kr == KERN_SUCCESS) {
			kr = mach_port_insert_right(mach_task_self(), exception_port, 
			                            exception_port, MACH_MSG_TYPE_MAKE_SEND);
			if (kr == KERN_SUCCESS) {
				exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_INSTRUCTION;
				kr = task_set_exception_ports(task, mask, exception_port,
				                              EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
				                              ARM_THREAD_STATE64);
				if (kr == KERN_SUCCESS) {
					printf("[DEBUG] Exception port configured: 0x%X\n", exception_port);
				} else {
					printf("[DEBUG] ERROR: Failed to set exception ports: %s\n", mach_error_string(kr));
				}
			}
		}
		
		// 5. Resume threads
		if (thread_count > 0) {
			for (int i = 0; i < thread_count; i++) {
				thread_resume(threads[i]);
			}
			vm_deallocate(mach_task_self(), (vm_offset_t)threads, 
			             sizeof(thread_act_array_t) * thread_count);
		}
		
		// 6. Wait for exception (breakpoint hit)
		printf("[DEBUG] Waiting for SSL_write to be called...\n");
		
		struct {
			mach_msg_header_t head;
			mach_msg_body_t body;
			mach_msg_port_descriptor_t thread_port;
			mach_msg_port_descriptor_t task_port;
			NDR_record_t ndr;
			exception_type_t exception;
			mach_msg_type_number_t code_count;
			int64_t code[2];
			int flavor;
			mach_msg_type_number_t state_count;
			natural_t state[ARM_THREAD_STATE64_COUNT];
			mach_msg_trailer_t trailer;
		} exc_msg;
		
		kr = mach_msg(&exc_msg.head, MACH_RCV_MSG | MACH_RCV_LARGE, 0,
		             sizeof(exc_msg), exception_port,
		             30000,  // 30 second timeout
		             MACH_PORT_NULL);
		
		if (kr == KERN_SUCCESS && exc_msg.exception == EXC_BREAKPOINT) {
			printf("\n[DEBUG] ===== BREAKPOINT HIT: SSL_write called! =====\n");
			
			// Extract thread and get registers
			thread_t exc_thread = exc_msg.thread_port.name;
			arm_thread_state64_t thread_state;
			mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
			
			kr = thread_get_state(exc_thread, ARM_THREAD_STATE64,
			                     (thread_state_t)&thread_state, &state_count);
			if (kr == KERN_SUCCESS) {
				// SSL_write(SSL *ssl, const void *buf, int num)
				// X0 = SSL*, X1 = buf, X2 = num
				uint64_t ssl_ptr = thread_state.__x[0];
				uint64_t buf_ptr = thread_state.__x[1];
				uint64_t buf_len = thread_state.__x[2];
				
				printf("[DEBUG] SSL*:   0x%016llX\n", ssl_ptr);
				printf("[DEBUG] buf*:   0x%016llX\n", buf_ptr);
				printf("[DEBUG] length: %lld bytes\n", buf_len);
				printf("[DEBUG] PC:     0x%016llX\n", thread_state.__pc);
				printf("[DEBUG] LR:     0x%016llX\n", thread_state.__lr);
				
				// Read buffer data
				if (buf_ptr && buf_len > 0 && buf_len < 16384) {
					char *buffer = malloc(buf_len + 1);
					if (buffer) {
					vm_size_t read_size = buf_len;
					kr = vm_read_overwrite(task, buf_ptr, buf_len,
					                      (vm_address_t)buffer, &read_size);
						if (kr == KERN_SUCCESS) {
							buffer[buf_len] = '\0';
							printf("\n[DEBUG] ===== BUFFER CONTENT =====\n");
							printf("%.*s\n", (int)buf_len, buffer);
							printf("[DEBUG] =============================\n\n");
							
							// Hex dump for binary data
							printf("[DEBUG] Hex dump:\n");
							for (int i = 0; i < buf_len && i < 256; i += 16) {
								printf("  %04X: ", i);
								for (int j = 0; j < 16 && (i+j) < buf_len; j++) {
									printf("%02X ", (unsigned char)buffer[i+j]);
								}
								printf("\n");
							}
						}
						free(buffer);
					}
				}
				
				// Restore original instruction
				kr = vm_write(task, sslWriteAddr, 
				             (vm_offset_t)&original_insn, 4);
				
				// Rewind PC to re-execute original instruction
				thread_state.__pc = sslWriteAddr;
				thread_set_state(exc_thread, ARM_THREAD_STATE64,
				                (thread_state_t)&thread_state, state_count);
				
				printf("[DEBUG] Restored instruction and rewound PC\n");
			}
			
			// Reply to exception to resume execution
			mach_msg_header_t reply;
			reply.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
			reply.msgh_remote_port = exc_msg.head.msgh_remote_port;
			reply.msgh_local_port = MACH_PORT_NULL;
			reply.msgh_id = exc_msg.head.msgh_id + 100;
			reply.msgh_size = sizeof(reply);
			
			mach_msg(&reply, MACH_SEND_MSG, sizeof(reply), 0,
			        MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
			
			printf("[DEBUG] Execution resumed\n");
		} else if (kr == MACH_RCV_TIMED_OUT) {
			printf("[DEBUG] Timeout: SSL_write not called within 30 seconds\n");
		} else {
			printf("[DEBUG] ERROR: mach_msg failed: %s\n", mach_error_string(kr));
		}
	}
	
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