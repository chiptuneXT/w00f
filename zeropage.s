/*
 * Copyright (c) 2014, winocm. <winocm@icloud.com>. All rights reserved.
 */
/*
 * Some pieces stolen from evasi0n7, some improved, some new.
 */
 
#include <mach/arm/asm.h>

        /* This is in data so it can be dynamically fixed up. */
        .data
        .syntax unified

        /*
         * Exported symbols:
         *      void *shellcode_begin, *shellcode_end;
         *      void *sandbox_helper_hook, *sandbox_helper_hook_end;
         *      void *dyld_helper_hook, *dyld_helper_hook64;
         *      void *syscall0_trampoline_handler;
         *      uint32_t stat_offset, copyinstr_offset, kernel_base;
         *
         * Relocate me to the (beginning of shadowmap + 0xc00)...
         * Or else.
         */

        .globl EXT(shellcode_begin)
        .globl EXT(shellcode_end)
LEXT(shellcode_begin)

	.code 16
	.thumb_func

        /* Stolen from evasi0n7. Arguments for a syscall are: syscall(arm_saved_state_t*, ...) */
	.align 2
	.globl EXT(dyld_helper_hook)
LEXT(dyld_helper_hook)
        push    {r4-r7, lr}
        add     r7, sp, #0xc
        sub     sp, sp, #0x410
        mov     r4, r0
        mov     r5, r1
        mov     r6, r2
        mov     r0, r1
        ldr     r0, [r0]
        add     r1, sp, #8
        mov     r2, #0x400
        mov     r3, #0x408
        mov     r4, sp
        add     r3, r4
        ldr     r4, EXT(copyinstr_offset)
        blx     r4
        add     r0, sp, #8
        adr     r1, .Ldyld_helper_hook_str
        blx     EXT(fast_strcmp)
        cmp     r0, #0
        bne     .Ldyld_helper_hook_call_orig
        mov     r0, #-1
        str     r0, [r6]
        mov     r0, #2
        b       .Ldyld_helper_hook_exit

        .align 2
        .code 16
        .thumb_func
.Ldyld_helper_hook_call_orig:
        mov     r0, r4
        mov     r1, r5
        mov     r2, r6
        ldr     r3, EXT(stat_offset)
        blx     r3

        .align 2
        .code 16
        .thumb_func
.Ldyld_helper_hook_exit:
        add     sp, sp, #0x410
        pop     {r4-r7, pc}

        /* Stolen from evasi0n7. Arguments for a syscall are: syscall(arm_saved_state_t*, ...) */
        .align 2
        .globl EXT(dyld_helper_hook64)
LEXT(dyld_helper_hook64)
        push    {r4-r7, lr}
        add     r7, sp, #0xc
        sub     sp, sp, #0x410
        mov     r4, r0
        mov     r5, r1
        mov     r6, r2
        mov     r0, r1
        ldr     r0, [r0]
        add     r1, sp, #8
        mov     r2, #0x400
        mov     r3, #0x408
        mov     r4, sp
        add     r3, r4
        ldr     r4, EXT(copyinstr_offset)
        blx     r4
        add     r0, sp, #8
        adr     r1, .Ldyld_helper_hook_str
        blx     EXT(fast_strcmp)
        cmp     r0, #0
        bne     .Ldyld_helper_hook_call_orig64
        mov     r0, #-1
        str     r0, [r6]
        mov     r0, #2
        b       .Ldyld_helper_hook_exit64

        .align 2
        .code 16
        .thumb_func
.Ldyld_helper_hook_call_orig64:
        mov     r0, r4
        mov     r1, r5
        mov     r2, r6
        ldr     r3, EXT(stat64_offset)
        blx     r3

        .align 2
        .code 16
        .thumb_func
.Ldyld_helper_hook_exit64:
        add     sp, sp, #0x410
        pop     {r4-r7, pc}

        /* Blah globally fixed variables */
        .align 2
        .globl EXT(stat_offset)
        .globl EXT(stat64_offset)
        .globl EXT(copyinstr_offset)
LEXT(stat64_offset)
        .long 0xdeadbeef
LEXT(stat_offset)
        .long 0xdeadbeef
LEXT(copyinstr_offset)
        .long 0xdeadbeef
.Ldyld_helper_hook_str:
        .asciz "/System/Library/Caches/com.apple.dyld/enable-dylibs-to-override-cache"

        /* Sandbox helper hook, I personally don't care about 
         * sandboxing, because what's the point? */
        .code 16
        .thumb_func
        .align 2
        .globl EXT(sandbox_helper_hook)
LEXT(sandbox_helper_hook)
        mov     r1, #0
        str     r1, [r0]
        mov     r1, #0x18
        strb    r1, [r0, #4]
        bx      lr
         
        .align 2
        .globl EXT(sandbox_helper_hook_end)
LEXT(sandbox_helper_hook_end)

        /* Rewritten strcmp. */
        .code 32
        .align 2
        .globl EXT(fast_strcmp)
LEXT(fast_strcmp)
        ldrb    r2, [r0], #1
        ldrb    r3, [r1], #1
        cmp     r2, r3
        bne     .Lstrcmpfail
        teq     r2, #0
        bne     EXT(fast_strcmp)
        moveq   r0, #0
.Lstrcmpfail:
        movne   r0, #-1
        bx      lr

        /*
         * syscall(0) hook for processor functions. This one is
         * done supposedly securely.
         * 
         * void syscall0_trampoline_handler(int func);
         *
         * Functions:
         *   #0 -> Invalidate unified TLB. All processors.
         */
        .code 16
        .thumb_func
        .align 2
        .globl EXT(syscall0_trampoline_handler)
LEXT(syscall0_trampoline_handler)
        push    {r4-r7, lr}
        mov     r4, r2
        ldr     r0, [r0]
        /* Technically could use a jump table.. who cares */
        cmp     r0, #0
        beq     EXT(InvalidateTLB_Unified)
        cmp     r0, #1
        beq     EXT(CleanAndInvalidateDcacheEntry_PoC)
        movs    r0, #0
        pop     {r4-r7, pc}

        /* Processor functions. */
        .code 16
        .thumb_func
        .align 2
        .globl EXT(InvalidateTLB_Unified)
LEXT(InvalidateTLB_Unified)
        mov     r0, #0
        mcr     p15, 0, r0, c8, c7, 0
        bx      lr

        /*
         * Clean D-cache entry to PoC for SMP systems. Flushes up to 32MB/16MB depending on Caches
         * linesize. 
         */
        .code 16
        .thumb_func
        .align 2
        .globl EXT(CleanAndInvalidateDcacheEntry_PoC)
LEXT(CleanAndInvalidateDcacheEntry_PoC)
        /* Cortex-A8 errata workaround (if it happens) */
        mrs     r12, cpsr
        cpsid   if

        /* Flush data-cache starting from kernel base and up. */
        ldr     r1, EXT(kernel_base)

        /* Read CCSIDR, get line size in mask bytes. */
        mrc     p15, 1, r2, c0, c0, 0
        and     r2, r2, #3
        lsl     r2, r2, #5
        sub     r3, r2, #1

        /* r2 -> Mask */
        bic     r1, r1, r3
        mcr     p15, 0, r1, c7, c14, 1
        mov     r1, #0x80000

        .code 16
        .thumb_func
        .align 2
.LcacheClean:
        add     r1, r1, r2
        mcr     p15, 0, r1, c7, c14, 1
        subs    r1, r1, #1
        bne     .LcacheClean

        /* Restore state and exit */
        msr     cpsr_c, r12
        bx      lr

        .align 2
        .globl EXT(kernel_base)
LEXT(kernel_base)
        .long 0xdeadbeef

        /* The scourge of Carpathia, the sorrow of Moldavia. */
        .align 2
        .globl EXT(miaubiz_was_here)
LEXT(miaubiz_was_here)
        .asciz "The solution is @snare."

        /* EOF */
LEXT(shellcode_end)
