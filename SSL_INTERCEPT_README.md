# SSL Interception Implementation

## Overview

This project implements SSL_write interception for iOS applications using **hardware breakpoints** instead of code patching, avoiding instruction cache flush issues.

## Architecture

### Components

1. **SimpleDebugger** (`SimpleDebugger.h/m`)
   - Low-level Mach exception handling
   - Hardware breakpoint management using ARM debug registers
   - Thread state manipulation
   - Works with both local and remote processes

2. **ssl_intercept** (`ssl_intercept.h/m`)
   - High-level SSL_write interception wrapper
   - Uses SimpleDebugger to set breakpoints
   - Dumps plaintext SSL data
   - Handles ARM64 calling convention

3. **rop_inject** (`rop_inject.m`)
   - Main entry point
   - Gets task port for target process
   - Resolves SSL_write address
   - Initializes SSL interception

## How It Works

### 1. Breakpoint Location

The breakpoint is set at `SSL_write + 0x1C` (28 bytes offset), which is **after the function prologue**:

```assembly
SSL_write:
+0x00:  PACIBSP                    ; PAC authentication
+0x04:  SUB SP, SP, #0x40          ; Allocate stack
+0x08:  STP X22, X21, [SP, #16]    ; Save registers
+0x0C:  STP X20, X19, [SP, #32]    
+0x10:  STP X29, X30, [SP, #48]    
+0x14:  ADD X29, SP, #48           ; Setup frame pointer
+0x18:  MOV X19, X2                ; Save size to X19
+0x1C:  MOV X20, X1                ; ← BREAKPOINT HERE - Save buffer to X20
+0x20:  MOV X21, X0                ; Save SSL* to X21
...
```

At offset `+0x1C`, the arguments have been saved to callee-saved registers:
- **X21** = SSL context (originally X0)
- **X20** = Buffer pointer (originally X1) **← This is the plaintext data!**
- **X19** = Buffer size (originally X2)

### 2. Interception Flow

```
┌─────────────────┐
│  Target App     │
│  calls          │
│  SSL_write()    │
└────────┬────────┘
         │
         ├─ PC reaches SSL_write + 0x1C
         │
         ▼
┌─────────────────────────────────┐
│  ARM Hardware Breakpoint Fires  │
│  (No code modification)         │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  Mach Exception                 │
│  EXC_BREAKPOINT                 │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  SimpleDebugger catches         │
│  exception in our process       │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  ssl_exception_callback()       │
│  1. Read thread state           │
│  2. Extract X20 (buffer)        │
│  3. Extract X19 (size)          │
│  4. vm_read_overwrite() data    │
│  5. Dump plaintext              │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  continueCallback(false)        │
│  - Advance PC by 4 bytes        │
│  - Keep breakpoint active       │
│  - Resume execution             │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────┐
│  Target App     │
│  continues      │
│  normally       │
└─────────────────┘
```

### 3. Key Advantages

✅ **No Code Modification**
   - Uses ARM hardware debug registers (BVR/BCR)
   - No instruction cache flush needed
   - No crashes from shared cache tampering

✅ **Stable & Reliable**
   - Breakpoint after prologue = stable state
   - All arguments saved to registers
   - Stack frame properly set up

✅ **Zero Performance Impact When Idle**
   - Hardware breakpoints have no overhead
   - Only triggers on SSL_write calls

✅ **Survives Code Signing**
   - No binary modification
   - Works with signed binaries

## Usage

### Build

```bash
make
```

### Run

```bash
# Get PID of target app
ps aux | grep YourApp

# Run interceptor
./opainject <PID>
```

### Example Output

```
╔═══════════════════════════════════════════════════════════════════════╗
║          SSL_write Interception with SimpleDebugger                   ║
╚═══════════════════════════════════════════════════════════════════════╝

✓ SimpleDebugger created for remote task
✓ Exception callback registered
✓ Exception ports configured
✓ Hardware breakpoint set at 0x1a2b3c4d (SSL_write + 0x1C)

🎯 Interception active! Waiting for SSL_write calls...
   (No code modification - using ARM debug registers)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 SSL_write BREAKPOINT HIT!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Thread:        0x1234
PC:            0x1a2b3c4d (SSL_write + 0x1c)
SSL Context:   0x12345678 (X21)
Buffer:        0x87654321 (X20)
Size:          256 bytes (X19)

╔═══════════════════════════════════════════════════════════════════════╗
║ SSL_write Plaintext Data (256 bytes)                                 
╠═══════════════════════════════════════════════════════════════════════╣
║ 0000: 47 45 54 20 2f 61 70 69  2f 75 73 65 72 73 20 48  │ GET /api/users H ║
║ 0010: 54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 61  │ TTP/1.1..Host: a ║
║ 0020: 70 69 2e 65 78 61 6d 70  6c 65 2e 63 6f 6d 0d 0a  │ pi.example.com.. ║
...
╚═══════════════════════════════════════════════════════════════════════╝

✅ Continuing execution...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Technical Details

### ARM Debug Registers

- **BVR (Breakpoint Value Register)**: Holds the breakpoint address
- **BCR (Breakpoint Control Register)**: Configuration
  - Bit 0: Enable
  - Bits 1-2: PMC (Privilege Mode Control) = 11b (any mode)
  - Bits 5-8: BAS (Byte Address Select) = 1111b (all 4 bytes)
  - Value: `0x1E5`

### Mach Exception Handling

```c
task_set_exception_ports(
    task,
    EXC_MASK_BREAKPOINT,      // Only breakpoint exceptions
    exception_port,
    EXCEPTION_DEFAULT,
    ARM_THREAD_STATE64
);
```

### Thread State Access

```c
arm_thread_state64_t state;
thread_get_state(thread, ARM_THREAD_STATE64, &state, &count);

uint64_t ssl_ctx = state.__x[21];  // X21
uint64_t buffer  = state.__x[20];  // X20
uint64_t size    = state.__x[19];  // X19
```

## Limitations

1. **Requires task_for_pid() entitlement**
   - Need `com.apple.security.cs.debugger` or `task_for_pid-allow`
   
2. **Only works on arm64/arm64e**
   - Uses ARM-specific debug registers
   
3. **Single breakpoint per thread**
   - ARM typically has 4-6 hardware breakpoints
   - We use breakpoint slot 0

## Future Enhancements

- [ ] Add SSL_read interception
- [ ] Support multiple breakpoints
- [ ] Filter by thread/connection
- [ ] Export to PCAP format
- [ ] Add TLS 1.3 support

## Credits

- SimpleDebugger framework
- ARM64 calling convention documentation
- Mach exception handling guides

## License

See LICENSE file.
