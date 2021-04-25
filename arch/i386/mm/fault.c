#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/vt_kern.h>		/* For unblank_screen() */
#include <linux/highmem.h>
#include <linux/module.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/desc.h>
#include <asm/kdebug.h>

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 *
 * error_code:
 *	bit 0 == 0 means no page found, 1 means protection fault
 *	bit 1 == 0 means read, 1 means write
 *	bit 2 == 0 means kernel, 1 means user-mode
 */
fastcall void do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
    struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct * vma;
	unsigned long address;
	unsigned long page;
	int write;
	siginfo_t info;

	/* get the address */
	__asm__("movl %%cr2,%0":"=r" (address));
    if (notify_die(DIE_PAGE_FAULT, "page fault", regs, error_code, 14,
					SIGSEGV) == NOTIFY_STOP)
		return;
    /* It's safe to allow irq's after cr2 has been saved */
	if (regs->eflags & (X86_EFLAGS_IF|VM_MASK))
		local_irq_enable();

	tsk = current;

	info.si_code = SEGV_MAPERR;

    if (unlikely(address >= TASK_SIZE)) { 
		if (!(error_code & 5))
			goto vmalloc_fault;
		/* 
		 * Don't take the mm semaphore here. If we fixup a prefetch
		 * fault we could otherwise deadlock.
		 */
		goto bad_area_nosemaphore;
	} 

bad_area_nosemaphore:
    if (error_code & 4) {
        mypanic("in page fault.c");
    }

#ifdef CONFIG_X86_F00F_BUG
#error "CONFIG_X86_F00F_BUG"
#endif
no_context:
    /* Are we prepared to handle this kernel fault?  */
	if (fixup_exception(regs))
		return;
vmalloc_fault:
    {
        int index = pgd_index(address);
    }
}