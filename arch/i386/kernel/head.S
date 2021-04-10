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
    lgdt boot_gdt_descr - __PAGE_OFFSET         # 这里只加载了启动阶段使用的全局描述符表
    movl $__BOOT_DS, %eax
    movl %eax,%ds
	movl %eax,%es
	movl %eax,%fs
	movl %eax,%gs

/**
 * clear BSS
 */
    xorl %eax, %eax
    movl $__bss_start - __PAGE_OFFSET, %edi
    movl $__bss_stop - __PAGE_OFFSET, %ecx
    subl %edi, %ecx
    shrl $2, %ecx
    rep stosl

page_pde_offset = (__PAGE_OFFSET >> 20)

    movl $pg0 - __PAGE_OFFSET, %edi             # edi指向pg0的首地址（0x106000）
    movl $swapper_pg_dir - __PAGE_OFFSET, %edx  # edx指向页目录首地址（0x104000）
    movl $0x007, %eax                           # eax依次为0x07、0x1007、0x2007、...代表
10:
    leal 0x007(%edi), %ecx                      # pg0首地址值+0x7（属性）
    movl %ecx, (%edx)                           # 存储到页目录首地址
    movl %ecx, page_pde_offset(%edx)            # 存储到页目录虚拟地址0xc0000000处
    addl $4, %edx
    movl $1024, %ecx
11:
    stosl
    addl $0x1000, %eax
    loop 11b

    # 第一次运行到这里，eax值为0x400007，edi为0x107000
    leal (INIT_MAP_BEYOND_END+0x007)(%edi), %ebp
    cmpl %ebp, %eax         # 0x400007 - 0x107000
    jb 10b
    movl %edi, (init_pg_tables_end - __PAGE_OFFSET)     # 0x10700 pg0的最后地址赋值给init_pg_tables_end

#ifdef CONFIG_SMP
    xorl %ebx, %ebx
    jmp 3f

ENTRY(startup_32_smp)
	cld
	movl $(__BOOT_DS),%eax
	movl %eax,%ds
	movl %eax,%es
	movl %eax,%fs
	movl %eax,%gs
    hlt
3:
#endif  /* CONFIG_SMP */

    # enable paging
    movl $swapper_pg_dir - __PAGE_OFFSET, %eax
    movl %eax, %cr3
    movl %cr0, %eax
    orl $0x80000000,%eax
    movl %eax, %cr0
    ljmp $__BOOT_CS, $1f
1:
    lss stack_start, %esp
    pushl $0
    popfl

#ifdef CONFIG_SMP
    andl %ebx, %ebx
    jz 1f               
    hlt
1:
#endif

    call setup_idt

    movl $boot_params, %edi
    movl $(PARAM_SIZE/4),%ecx
	cld
	rep movsl                   # copy from 0x90000 to boot_params for 2048 byte
    movl boot_params+NEW_CL_POINTER, %esi   # 起始就是将0x90228位置的一个双字给到esi
    andl %esi, %esi
    jnz 2f
    cmpw $OLD_CL_MAGIC, OLD_CL_MAGIC_ADDR
    jne 1f
    hlt
2:
    movl $saved_command_line,%edi
	movl $(COMMAND_LINE_SIZE/4),%ecx
	rep
	movsl
1:
checkCPUtype:
    movl $-1, X86_CPUID     #  -1 for no CPUID initially

    movb $3,X86		# at least 386
	pushfl			# push EFLAGS
	popl %eax		# get EFLAGS
	movl %eax,%ecx		# save original EFLAGS
	xorl $0x240000,%eax	# flip AC and ID bits in EFLAGS
	pushl %eax		# copy to EFLAGS
	popfl			# set EFLAGS
	pushfl			# get new EFLAGS
	popl %eax		# put it in eax
	xorl %ecx,%eax		# change in flags
	pushl %ecx		# restore original EFLAGS
	popfl
	testl $0x40000,%eax	# check if AC bit changed
	je is386

    movb $4,X86		# at least 486
	testl $0x200000,%eax	# check if ID bit changed
	je is486

    /* get vendor info */
	xorl %eax,%eax			# call CPUID with 0 -> return vendor ID
	cpuid
	movl %eax,X86_CPUID		# save CPUID level
	movl %ebx,X86_VENDOR_ID		# lo 4 chars
	movl %edx,X86_VENDOR_ID+4	# next 4 chars
	movl %ecx,X86_VENDOR_ID+8	# last 4 chars

	orl %eax,%eax			# do we have processor info as well?
	je is486

    movl $1,%eax		# Use the CPUID instruction to get CPU type
	cpuid
	movb %al,%cl		# save reg for future use
	andb $0x0f,%ah		# mask processor family
	movb %ah,X86
	andb $0xf0,%al		# mask model
	shrb $4,%al
	movb %al,X86_MODEL
	andb $0x0f,%cl		# mask mask revision
	movb %cl,X86_MASK
	movl %edx,X86_CAPABILITY

is486:
    movl $0x50022,%ecx	# set AM, WP, NE and MP
	jmp 2f
is386:
    hlt
2:
    movl %cr0, %eax
	andl $0x80000011, %eax	# Save PG,PE,ET
	orl %ecx, %eax
	movl %eax, %cr0

    call check_x87
    incb ready
    lgdt cpu_gdt_descr
    lidt idt_descr
    ljmp $__KERNEL_CS, $1f
1:
    movl $__KERNEL_DS, %eax
    movl %eax, %ss

    movl $__USER_DS, %eax
    movl %eax, %ds
    movl %eax, %es

    xorl %eax, %eax
    movl %eax, %fs
    movl %eax, %gs
    lldt %ax
    cld
#ifdef CONFIG_SMP
    movb ready, %cl
    cmpb $1, %cl
    je 1f           # the first CPU calls start_kernel
                    # all other CPUs call initialize_secondary
    call initialize_secondary
    jmp L6
    
1:
#endif
    call start_kernel
L6:
    jmp L6

check_x87:
    movb $0,X86_HARD_MATH
	clts
	fninit
	fstsw %ax
	cmpb $0,%al
	je 1f
    hlt

	ALIGN
1:	
    movb $1, X86_HARD_MATH
	.byte 0xDB,0xE4		/* fsetpm for 287, ignored by 387 */
	ret

setup_idt:
    lea ignore_int, %edx
    movl $__KERNEL_CS << 16, %eax
    movw %dx, %ax
    movw $0x8E00, %dx       # interrupt gate - dpl = 0, present

    lea idt_table, %edi
    mov $256, %ecx          # 256个中断
rp_sidt:
    movl %eax, (%edi)
    movl %edx, 4(%edi)
    addl $8, %edi
    dec %ecx
    jne rp_sidt
    ret

ALIGN
ignore_int:
    cld
	pushl %eax
	pushl %ecx
	pushl %edx
	pushl %es
	pushl %ds
	movl $(__KERNEL_DS),%eax
	movl %eax,%ds
	movl %eax,%es
	pushl 16(%esp)
	pushl 24(%esp)
	pushl 32(%esp)
	pushl 40(%esp)
	pushl $int_msg
	call printk
	addl $(5*4),%esp
	popl %ds
	popl %es
	popl %edx
	popl %ecx
	popl %eax
	iret

ENTRY(stext)
ENTRY(_stext)

.section ".bss.page_aligned", "w"
ENTRY(swapper_pg_dir)
    .fill 1024, 4, 0
ENTRY(empty_zero_page)
    .fill 4096, 1, 0

.data

ENTRY(stack_start)
    .long init_thread_union+THREAD_SIZE
    .long __BOOT_DS

ready:
    .byte 0

int_msg:
	.asciz "Unknown interrupt or fault at EIP %p %p %p\n"


.globl boot_gdt_descr
.globl idt_descr
.globl cpu_gdt_descr

boot_gdt_descr:
    .word __BOOT_DS + 7
    .long boot_gdt_table - __PAGE_OFFSET

    .word 0
idt_descr:
    .word IDT_ENTRIES*8-1   # 256 entries
    .long idt_table

# boot GDT descriptor (later on used by CPU#0):
    .word 0
cpu_gdt_descr:
    .word GDT_ENTRIES*8-1
    .long cpu_gdt_table

    .fill NR_CPUS-1, 8, 0   # space for the other GDT descriptors

/*
 * The boot_gdt_table must mirror the equivalent in setup.S and is
 * used only for booting.
 */
	.align L1_CACHE_BYTES
ENTRY(boot_gdt_table)
    .fill GDT_ENTRY_BOOT_CS,8,0
	.quad 0x00cf9a000000ffff	/* kernel 4GB code at 0x00000000 */
	.quad 0x00cf92000000ffff	/* kernel 4GB data at 0x00000000 */

	.align PAGE_SIZE_asm
ENTRY(cpu_gdt_table)
	.quad 0x0000000000000000	/* NULL descriptor */
	.quad 0x0000000000000000	/* 0x0b reserved */
	.quad 0x0000000000000000	/* 0x13 reserved */
	.quad 0x0000000000000000	/* 0x1b reserved */
	.quad 0x0000000000000000	/* 0x20 unused */
	.quad 0x0000000000000000	/* 0x28 unused */
	.quad 0x0000000000000000	/* 0x33 TLS entry 1 */
	.quad 0x0000000000000000	/* 0x3b TLS entry 2 */
	.quad 0x0000000000000000	/* 0x43 TLS entry 3 */
	.quad 0x0000000000000000	/* 0x4b reserved */
	.quad 0x0000000000000000	/* 0x53 reserved */
	.quad 0x0000000000000000	/* 0x5b reserved */

	.quad 0x00cf9a000000ffff	/* 0x60 kernel 4GB code at 0x00000000 */
	.quad 0x00cf92000000ffff	/* 0x68 kernel 4GB data at 0x00000000 */
	.quad 0x00cffa000000ffff	/* 0x73 user 4GB code at 0x00000000 */
	.quad 0x00cff2000000ffff	/* 0x7b user 4GB data at 0x00000000 */

	.quad 0x0000000000000000	/* 0x80 TSS descriptor */
	.quad 0x0000000000000000	/* 0x88 LDT descriptor */

	/* Segments used for calling PnP BIOS */
	.quad 0x00c09a0000000000	/* 0x90 32-bit code */
	.quad 0x00809a0000000000	/* 0x98 16-bit code */
	.quad 0x0080920000000000	/* 0xa0 16-bit data */
	.quad 0x0080920000000000	/* 0xa8 16-bit data */
	.quad 0x0080920000000000	/* 0xb0 16-bit data */
	/*
	 * The APM segments have byte granularity and their bases
	 * and limits are set at run time.
	 */
	.quad 0x00409a0000000000	/* 0xb8 APM CS    code */
	.quad 0x00009a0000000000	/* 0xc0 APM CS 16 code (16 bit) */
	.quad 0x0040920000000000	/* 0xc8 APM DS    data */

	.quad 0x0000000000000000	/* 0xd0 - unused */
	.quad 0x0000000000000000	/* 0xd8 - unused */
	.quad 0x0000000000000000	/* 0xe0 - unused */
	.quad 0x0000000000000000	/* 0xe8 - unused */
	.quad 0x0000000000000000	/* 0xf0 - unused */
	.quad 0x0000000000000000	/* 0xf8 - GDT entry 31: double-fault TSS */