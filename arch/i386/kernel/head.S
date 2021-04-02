.text
#include <linux/config.h>
#include <linux/threads.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/desc.h>
#include <asm/cache.h>
#include <asm/thread_info.h>
#include <asm/asm_offsets.h>
#include <asm/setup.h>

/*
 * References to members of the new_cpu_data structure.
 */

#define X86		new_cpu_data+CPUINFO_x86
#define X86_VENDOR	new_cpu_data+CPUINFO_x86_vendor
#define X86_MODEL	new_cpu_data+CPUINFO_x86_model
#define X86_MASK	new_cpu_data+CPUINFO_x86_mask
#define X86_HARD_MATH	new_cpu_data+CPUINFO_hard_math
#define X86_CPUID	new_cpu_data+CPUINFO_cpuid_level
#define X86_CAPABILITY	new_cpu_data+CPUINFO_x86_capability
#define X86_VENDOR_ID	new_cpu_data+CPUINFO_x86_vendor_id

#define INIT_MAP_BEYOND_END	(128*1024)

ENTRY(startup_32)
    cld
    lgdt boot_gdt_descr - __PAGE_OFFSET
    movl $__BOOT_DS, %eax
    movl %eax,%ds
	movl %eax,%es
	movl %eax,%fs
	movl %eax,%gs

    xorl %eax, %eax
    movl $__bss_start - __PAGE_OFFSET, %edi
    movl $__bss_stop - __PAGE_OFFSET, %ecx
    subl %edi, %ecx
    shrl $2, %ecx
    rep stosl
    jmp .

.globl boot_gdt_descr

boot_gdt_descr:
    .word __BOOT_DS + 7
    .long boot_gdt_table - __PAGE_OFFSET

/*
 * The boot_gdt_table must mirror the equivalent in setup.S and is
 * used only for booting.
 */
	.align L1_CACHE_BYTES
ENTRY(boot_gdt_table)
    .fill GDT_ENTRY_BOOT_CS,8,0
	.quad 0x00cf9a000000ffff	/* kernel 4GB code at 0x00000000 */
	.quad 0x00cf92000000ffff	/* kernel 4GB data at 0x00000000 */