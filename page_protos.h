/*
 * Copyright (c) 2014, winocm. <winocm@icloud.com>. All rights reserved.
 */

#ifndef _ARM_PAGE_PROTOS_H_
#define _ARM_PAGE_PROTOS_H_

/* ARM page bits for L1 sections. */
#define L1_SHIFT            20            /* log2(1MB) */
 
#define L1_SECT_PROTO        (1 << 1)        /* 0b10 */
 
#define L1_SECT_B_BIT        (1 << 2)
#define L1_SECT_C_BIT        (1 << 3)
 
#define L1_SECT_SORDER       (0)            /* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_SH_DEVICE    (L1_SECT_B_BIT)
#define L1_SECT_WT_NWA       (L1_SECT_C_BIT)
#define L1_SECT_WB_NWA       (L1_SECT_B_BIT | L1_SECT_C_BIT)
#define L1_SECT_S_BIT        (1 << 16)
 
#define L1_SECT_AP_URW       (1 << 10) | (1 << 11)
#define L1_SECT_PFN(x)       (x & 0xFFF00000)
 
#define L1_SECT_DEFPROT      (L1_SECT_AP_URW)
#define L1_SECT_DEFCACHE     (L1_SECT_SORDER)
 
#define L1_PROTO_TTE(paddr)  (L1_SECT_PFN(paddr) | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE | L1_SECT_PROTO)
 
#define PFN_SHIFT            2
#define TTB_OFFSET(vaddr)    ((vaddr >> L1_SHIFT) << PFN_SHIFT)
 
/*
 * RAM physical base begin. 
 */
#define S5L8930_PHYS_OFF    0x40000000
#define S5L8940_PHYS_OFF    0x80000000        /* Note: RAM base is identical for 8940-8955. */

#define PHYS_OFF            S5L8930_PHYS_OFF
 
/*
 * Shadowmap begin and end. 15MB of shadowmap is enough for the kernel.
 * We don't need to invalidate unified D/I TLB or any cache lines
 * since the kernel is mapped as writethrough memory, and these
 * addresses are guaranteed to not be translated.
 * (Accesses will cause segmentation faults due to failure on L1 translation.)
 *
 * Clear the shadowmappings when done owning the kernel.
 *
 * 0x7ff0'0000 is also below the limit for vm_read and such, so that's also *great*.
 * (2048 bytes)
 */
#define SHADOWMAP_BEGIN         0x7f000000
#define SHADOWMAP_END           0x7ff00000
#define SHADOWMAP_GRANULARITY   0x00100000
 
#define SHADOWMAP_SIZE_BYTES    (SHADOWMAP_END - SHADOWMAP_BEGIN)
 
#define SHADOWMAP_BEGIN_OFF     TTB_OFFSET(SHADOWMAP_BEGIN)
#define SHADOWMAP_END_OFF       TTB_OFFSET(SHADOWMAP_END)
#define SHADOWMAP_SIZE          (SHADOWMAP_END_OFF - SHADOWMAP_BEGIN_OFF)
 
#define SHADOWMAP_BEGIN_IDX     (SHADOWMAP_BEGIN_OFF >> PFN_SHIFT)
#define SHADOWMAP_END_IDX       (SHADOWMAP_END_OFF >> PFN_SHIFT)
 
#define TTB_SIZE                4096
#define DEFAULT_KERNEL_SLIDE    0x80000000

#endif /* _ARM_PAGE_PROTOS_H_ */