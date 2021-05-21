#include <linux/config.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/blkdev.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <asm/mmx.h>

static inline int __movsl_is_ok(unsigned long a1, unsigned long a2, unsigned long n)
{
#ifdef CONFIG_X86_INTEL_USERCOPY
	if (n >= 64 && ((a1 ^ a2) & movsl_mask.mask))
		return 0;
#endif
	return 1;
}
#define movsl_is_ok(a1,a2,n) \
	__movsl_is_ok((unsigned long)(a1),(unsigned long)(a2),(n))




#ifdef CONFIG_X86_INTEL_USERCOPY

static unsigned long
__copy_user_zeroing_intel(void *to, const void __user *from, unsigned long size)
{
	int d0, d1;
	__asm__ __volatile__(
		       "        .align 2,0x90\n"
		       "0:      movl 32(%4), %%eax\n"
		       "        cmpl $67, %0\n"      
		       "        jbe 2f\n"            
		       "1:      movl 64(%4), %%eax\n"
		       "        .align 2,0x90\n"     
		       "2:      movl 0(%4), %%eax\n" 
		       "21:     movl 4(%4), %%edx\n" 
		       "        movl %%eax, 0(%3)\n" 
		       "        movl %%edx, 4(%3)\n" 
		       "3:      movl 8(%4), %%eax\n" 
		       "31:     movl 12(%4),%%edx\n" 
		       "        movl %%eax, 8(%3)\n" 
		       "        movl %%edx, 12(%3)\n"
		       "4:      movl 16(%4), %%eax\n"
		       "41:     movl 20(%4), %%edx\n"
		       "        movl %%eax, 16(%3)\n"
		       "        movl %%edx, 20(%3)\n"
		       "10:     movl 24(%4), %%eax\n"
		       "51:     movl 28(%4), %%edx\n"
		       "        movl %%eax, 24(%3)\n"
		       "        movl %%edx, 28(%3)\n"
		       "11:     movl 32(%4), %%eax\n"
		       "61:     movl 36(%4), %%edx\n"
		       "        movl %%eax, 32(%3)\n"
		       "        movl %%edx, 36(%3)\n"
		       "12:     movl 40(%4), %%eax\n"
		       "71:     movl 44(%4), %%edx\n"
		       "        movl %%eax, 40(%3)\n"
		       "        movl %%edx, 44(%3)\n"
		       "13:     movl 48(%4), %%eax\n"
		       "81:     movl 52(%4), %%edx\n"
		       "        movl %%eax, 48(%3)\n"
		       "        movl %%edx, 52(%3)\n"
		       "14:     movl 56(%4), %%eax\n"
		       "91:     movl 60(%4), %%edx\n"
		       "        movl %%eax, 56(%3)\n"
		       "        movl %%edx, 60(%3)\n"
		       "        addl $-64, %0\n"     
		       "        addl $64, %4\n"      
		       "        addl $64, %3\n"      
		       "        cmpl $63, %0\n"      
		       "        ja  0b\n"            
		       "5:      movl  %0, %%eax\n"   
		       "        shrl  $2, %0\n"      
		       "        andl $3, %%eax\n"    
		       "        cld\n"               
		       "6:      rep; movsl\n"   
		       "        movl %%eax,%0\n"
		       "7:      rep; movsb\n"	
		       "8:\n"			
		       ".section .fixup,\"ax\"\n"
		       "9:      lea 0(%%eax,%0,4),%0\n"	
		       "16:     pushl %0\n"	
		       "        pushl %%eax\n"	
		       "        xorl %%eax,%%eax\n"
		       "        rep; stosb\n"	
		       "        popl %%eax\n"	
		       "        popl %0\n"	
		       "        jmp 8b\n"	
		       ".previous\n"		
		       ".section __ex_table,\"a\"\n"
		       "	.align 4\n"	   
		       "	.long 0b,16b\n"	 
		       "	.long 1b,16b\n"
		       "	.long 2b,16b\n"
		       "	.long 21b,16b\n"
		       "	.long 3b,16b\n"	
		       "	.long 31b,16b\n"
		       "	.long 4b,16b\n"	
		       "	.long 41b,16b\n"
		       "	.long 10b,16b\n"
		       "	.long 51b,16b\n"
		       "	.long 11b,16b\n"
		       "	.long 61b,16b\n"
		       "	.long 12b,16b\n"
		       "	.long 71b,16b\n"
		       "	.long 13b,16b\n"
		       "	.long 81b,16b\n"
		       "	.long 14b,16b\n"
		       "	.long 91b,16b\n"
		       "	.long 6b,9b\n"	
		       "        .long 7b,16b\n" 
		       ".previous"		
		       : "=&c"(size), "=&D" (d0), "=&S" (d1)
		       :  "1"(to), "2"(from), "0"(size)
		       : "eax", "edx", "memory");
	return size;
}
#else
/*
 * Leave these declared but undefined.  They should not be any references to
 * them
 */
unsigned long
__copy_user_zeroing_intel(void *to, const void __user *from, unsigned long size);
unsigned long
__copy_user_intel(void __user *to, const void *from, unsigned long size);
#endif /* CONFIG_X86_INTEL_USERCOPY */

#define __copy_user_zeroing(to,from,size)				\
do {									\
	int __d0, __d1, __d2;						\
	__asm__ __volatile__(						\
		"	cmp  $7,%0\n"					\
		"	jbe  1f\n"					\
		"	movl %1,%0\n"					\
		"	negl %0\n"					\
		"	andl $7,%0\n"					\
		"	subl %0,%3\n"					\
		"4:	rep; movsb\n"					\
		"	movl %3,%0\n"					\
		"	shrl $2,%0\n"					\
		"	andl $3,%3\n"					\
		"	.align 2,0x90\n"				\
		"0:	rep; movsl\n"					\
		"	movl %3,%0\n"					\
		"1:	rep; movsb\n"					\
		"2:\n"							\
		".section .fixup,\"ax\"\n"				\
		"5:	addl %3,%0\n"					\
		"	jmp 6f\n"					\
		"3:	lea 0(%3,%0,4),%0\n"				\
		"6:	pushl %0\n"					\
		"	pushl %%eax\n"					\
		"	xorl %%eax,%%eax\n"				\
		"	rep; stosb\n"					\
		"	popl %%eax\n"					\
		"	popl %0\n"					\
		"	jmp 2b\n"					\
		".previous\n"						\
		".section __ex_table,\"a\"\n"				\
		"	.align 4\n"					\
		"	.long 4b,5b\n"					\
		"	.long 0b,3b\n"					\
		"	.long 1b,6b\n"					\
		".previous"						\
		: "=&c"(size), "=&D" (__d0), "=&S" (__d1), "=r"(__d2)	\
		: "3"(size), "0"(size), "1"(to), "2"(from)		\
		: "memory");						\
} while (0)

unsigned long
__copy_from_user_ll(void *to, const void __user *from, unsigned long n)
{
	BUG_ON((long)n < 0);
	if (movsl_is_ok(to, from, n))
		__copy_user_zeroing(to, from, n);
	else
		n = __copy_user_zeroing_intel(to, from, n);
	return n;
}
/**
 * copy_from_user: - Copy a block of data from user space.
 * @to:   Destination address, in kernel space.
 * @from: Source address, in user space.
 * @n:    Number of bytes to copy.
 *
 * Context: User context only.  This function may sleep.
 *
 * Copy data from user space to kernel space.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 *
 * If some data could not be copied, this function will pad the copied
 * data to the requested size using zero bytes.
 */
unsigned long
copy_from_user(void *to, const void __user *from, unsigned long n)
{
	might_sleep();
	BUG_ON((long) n < 0);
	if (access_ok(VERIFY_READ, from, n))
		n = __copy_from_user(to, from, n);
	else
		memset(to, 0, n);
	return n;
}
EXPORT_SYMBOL(copy_from_user);