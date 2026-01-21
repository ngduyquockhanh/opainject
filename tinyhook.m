#include "private.h"
#include <mach/mach_error.h>
#include <mach/vm_map.h> // vm_*
#include <stdio.h> // Added to declare printf
#define mach_vm_address_t  vm_address_t
#define mach_vm_allocate   vm_allocate
#define mach_vm_deallocate vm_deallocate
#define mach_vm_read       vm_read
#define mach_vm_write      vm_write
#define mach_vm_protect    vm_protect
#define mach_vm_read_overwrite vm_read_overwrite

// Updated write_mem to accept a task parameter
int write_mem(task_t task, void *destination, const void *source, size_t len) {
    printf("Writing %zu bytes to %p in task %d\n", len, destination, task);
    int kr = 0;
    kr |= mach_vm_protect(task, (mach_vm_address_t)destination, len, FALSE,
                          VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    kr |= mach_vm_write(task, (mach_vm_address_t)destination, (vm_offset_t)source, len);
    kr |= mach_vm_protect(task, (mach_vm_address_t)destination, len, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != 0) {
        printf("write_mem: %s", mach_error_string(kr));
    }
    return kr;
}

int32_t sign_extend(uint32_t x, int N) {
    return (int32_t)(x << (32 - N)) >> (32 - N);
}

bool need_far_jump(const void *src, const void *dst) {
    long long distance = dst > src ? dst - src : src - dst;
    return distance >= 128 * MB;

}

static int calc_near_jump(uint8_t *output, void *src, void *dst, bool link) {
    uint32_t insn = (dst - src) >> 2 & 0x3ffffff;
    insn |= link ? AARCH64_BL : AARCH64_B;
    *(uint32_t *)output = insn;
    return 4; // Return the jump size directly
}

static int calc_far_jump(uint8_t *output, void *src, void *dst, bool link) {
    // adrp    x17, imm
    // add     x17, x17, imm    ; x17 -> dst
    // br/blr  x17
    int64_t insn = ((int64_t)dst >> 12) - ((int64_t)src >> 12);
    insn = ((insn & 0x3) << 29) | ((insn & 0x1ffffc) << 3) | AARCH64_ADRP;
    *(uint32_t *)output = insn;
    insn = ((int64_t)dst & 0xfff) << 10 | AARCH64_ADD;
    *(uint32_t *)(output + 4) = insn;
    *(uint32_t *)(output + 8) = link ? AARCH64_BLR : AARCH64_BR;
    return 12; // Return the jump size directly
}

static int calc_jump(uint8_t *output, void *src, void *dst, bool link) {
    printf("Calculating jump from %p to %p\n", src, dst);
    if (need_far_jump(src, dst))
        return calc_far_jump(output, src, dst, link);
    else
        return calc_near_jump(output, src, dst, link);
}

static void *trampo;
static mach_vm_address_t vmbase;


static inline void save_header(task_t task, void **src, void **dst, int min_len) {
    printf("Saving header from %p to %p\n", *src, *dst);
    mach_vm_protect(task, vmbase, PAGE_SIZE, FALSE, VM_PROT_DEFAULT);
     uint32_t insn;
    for (int i = 0; i < min_len; i += 4) {
        // Đọc lệnh từ bộ nhớ từ xa
        mach_vm_read_overwrite(task, (mach_vm_address_t)*src, sizeof(uint32_t), (vm_address_t)&insn, NULL);

        if (((insn ^ 0x90000000) & 0x9f000000) == 0) {
            // adrp
            int32_t imm21 = sign_extend((insn >> 29 & 0x3) | (insn >> 3 & 0x1ffffc), 21);
            int64_t addr = ((int64_t)*src >> 12) + imm21;
            int64_t len = addr - ((int64_t)*dst >> 12);
            if ((len << 12) < 4 * GB) {
                // modify the immediate (len: 4 -> 4)
                insn &= 0x9f00001f; // clean the immediate
                insn = ((len & 0x3) << 29) | ((len & 0x1ffffc) << 3) | insn;
                mach_vm_write(task, (mach_vm_address_t)*dst, (vm_offset_t)&insn, sizeof(uint32_t));
                *dst += 4;
            } else {
                // use movz + movk to get the address (len: 4 -> 16)
                int64_t imm64 = addr << 12;
                uint16_t rd = insn & 0b11111;
                bool cleaned = false;
                for (int j = 0; imm64; imm64 >>= 16, j++) {
                    uint64_t cur_imm = imm64 & 0xffff;
                    if (cur_imm) {
                        insn = (j << 21) | (cur_imm << 5) | rd | (cleaned ? AARCH64_MOVK : AARCH64_MOVZ);
                        mach_vm_write(task, (mach_vm_address_t)*dst, (vm_offset_t)&insn, sizeof(uint32_t));
                        *dst += 4;
                        cleaned = true;
                    }
                }
            }
        } else if (((insn ^ 0x14000000) & 0xfc000000) == 0 || ((insn ^ 0x94000000) & 0xfc000000) == 0) {
            // b or bl
            bool link = insn >> 31;
            int32_t imm26 = sign_extend(insn, 26);
            void *addr = *src + (imm26 << 2);
            int jump_len = calc_jump((uint8_t *)*dst, *dst, addr, link);
            *dst += jump_len;
        } else {
            mach_vm_write(task, (mach_vm_address_t)*dst, (vm_offset_t)&insn, sizeof(uint32_t));
            *dst += 4;
        }
        *src += 4;
    }
    mach_vm_protect(task, vmbase, PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    printf("Header saved, new src: %p, new dst: %p\n", *src, *dst);
    return;

}


int tiny_hook(task_t task, void *src, void *dst, void **orig) {
    printf("Installing tiny hook from %p to %p\n", src, dst);
    int kr = 0;
    int jump_size;
    uint8_t jump_insns[MAX_JUMP_SIZE];
    if (orig == NULL) {
        jump_size = calc_jump(jump_insns, src, dst, false);
        kr = write_mem(task, src, jump_insns, jump_size);
    }
    else {
        // check if the space is enough
        if (!trampo || ((uint64_t)trampo + MAX_JUMP_SIZE + MAX_HEAD_SIZE >= vmbase + PAGE_SIZE)) {
            // alloc a vm to store headers and jumps
            kr = mach_vm_allocate(task, &vmbase, PAGE_SIZE, VM_FLAGS_ANYWHERE);
            if (kr != 0) {
                printf("mach_vm_allocate: %s", mach_error_string(kr));
                return kr;
            }
            trampo = (void *)vmbase;
        }
        void *bak = src;
        *orig = trampo;
        jump_size = calc_jump(jump_insns, src, dst, false);
        save_header(task, &bak, &trampo, jump_size);
        kr |= write_mem(task, src, jump_insns, jump_size);
        jump_size += calc_jump(jump_insns, trampo, bak, false);
        kr |= write_mem(task, trampo, jump_insns, jump_size);
        trampo += jump_size;
    }
    return kr;
}
