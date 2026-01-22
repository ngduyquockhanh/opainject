//
//  SimpleDebugger.h
//  SimpleDebugger
//
//  Created by Noah Martin on 10/9/24.
//

#if TARGET_OS_TV || TARGET_OS_WATCH || !(defined(__arm64__) || defined(__aarch64__))
  #define EMG_ENABLE_MACH_APIS 0
#else
  #define EMG_ENABLE_MACH_APIS 1
#endif

#if EMG_ENABLE_MACH_APIS

#ifdef __cplusplus
extern "C++" {

#import <functional>
#import <mach/mach.h>
#import <pthread.h>
#import <mutex>
#import <unordered_map>


struct MachExceptionMessage;

class SimpleDebugger {
public:
  using ExceptionCallback = std::function<void(mach_port_t thread, arm_thread_state64_t state, std::function<void(bool removeBreak)>)>;
  
  using BadAccessCallback = std::function<void(mach_port_t thread, arm_thread_state64_t state)>;

  SimpleDebugger();
  SimpleDebugger(mach_port_t remoteTask)

  void setTargetTask(mach_port_t task);
  mach_port_t getTargetTask() const;

  bool startDebugging();
  void setExceptionCallback(ExceptionCallback callback);
  void setBadAccessCallback(BadAccessCallback callback);
  void setBreakpoint(vm_address_t address);

  // The function at originalFunc must be at least 5 instructions
  int hookFunction(void *originalFunc, void *newFunc);

  bool readMemory(vm_address_t address, void* buffer, vm_size_t size);
  
  // Ghi memory vào target process
  bool writeMemory(vm_address_t address, const void* buffer, vm_size_t size);
  
  // Tìm symbol trong remote process
  vm_address_t findSymbol(const char* symbolName, const char* imageName = nullptr);
  
  std::vector<std::string> getLoadedImages();

  ~SimpleDebugger();

private:
  mach_port_t targetTask; 
  bool isRemote;  
  mach_port_t exceptionPort;
  pthread_t serverThread;
  std::mutex m;
  std::mutex instructionMutex;
  ExceptionCallback exceptionCallback;
  BadAccessCallback badAccessCallback;
  std::unordered_map<vm_address_t, uint32_t> originalInstruction;

  static void* exceptionServerWrapper(void* arg);
  void* exceptionServer();
  void continueFromBreak(mach_port_t thread, bool removeBreak, MachExceptionMessage exceptionMessage, arm_thread_state64_t state, mach_msg_type_number_t state_count);
  
  // Helper methods cho remote operations
  uint32_t readInstruction(vm_address_t address);
  bool setInstructionRemote(vm_address_t address, uint32_t newInst, uint32_t* oldInst);
  void protectPageRemote(vm_address_t address, vm_size_t size, vm_prot_t newProtection);
  
  // Suspend/resume all threads trong target process
  bool suspendAllThreads(thread_act_array_t* threads, mach_msg_type_number_t* thread_count);
  void resumeAllThreads(thread_act_array_t threads, mach_msg_type_number_t thread_count);

};
}
#endif

#endif
