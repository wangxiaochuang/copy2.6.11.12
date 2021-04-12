.text

#include <linux/linkage.h>
#include <asm/segment.h>

	.globl startup_32
	
startup_32:
    cld
    cli
    movl $__BOOT_DS, %eax
    movl %eax, %ds
	movl %eax, %es
	movl %eax, %fs
	movl %eax, %gs

    lss stack_start, %esp
    xorl %eax, %eax
1:
    incl %eax
    movl %eax, 0x000000
    cmpl %eax, 0x100000
    je 1b

    pushl $0
    popfl

    xorl %eax, %eax
    movl $_edata, %edi
    movl $_end, %ecx
    subl %edi, %ecx
    cld
    rep stosb
    
    subl $16, %esp
    movl %esp, %eax
    pushl %esi          # 0x90000
    pushl %eax
    call decompress_kernel
    orl %eax, %eax
    jnz 3f
    popl %esi
    popl %esi           # 0x90000
    xorl %ebx, %ebx
    ljmp $__BOOT_CS, $0x100000

3:
    hlt
    