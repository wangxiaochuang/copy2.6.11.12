#include <stdarg.h>

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/elfcore.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/user.h>
#include <linux/a.out.h>
#include <linux/interrupt.h>
#include <linux/config.h>
#include <linux/utsname.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/init.h>
#include <linux/mc146818rtc.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/ldt.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/irq.h>
#include <asm/desc.h>
#ifdef CONFIG_MATH_EMULATION
#include <asm/math_emu.h>
#endif

#include <linux/irq.h>
#include <linux/err.h>

asmlinkage void ret_from_fork(void) __asm__("ret_from_fork");

int hlt_counter;

/*
 * Powermanagement idle function, if any..
 */
void (*pm_idle)(void);
static cpumask_t cpu_idle_map;

void disable_hlt(void)
{
	hlt_counter++;
}

EXPORT_SYMBOL(disable_hlt);

void enable_hlt(void)
{
	hlt_counter--;
}

EXPORT_SYMBOL(enable_hlt);

/*
 * We use this if we don't have any better
 * idle routine..
 */
void default_idle(void)
{
	if (!hlt_counter && boot_cpu_data.hlt_works_ok) {
		local_irq_disable();
		if (!need_resched())
			safe_halt();
		else
			local_irq_enable();
	} else {
		cpu_relax();
	}
}

void cpu_idle (void)
{
	int cpu = _smp_processor_id();

    while (1) {
        while (!need_resched()) {
            void (*idle)(void);

            if (cpu_isset(cpu, cpu_idle_map))
                cpu_clear(cpu, cpu_idle_map);
            rmb();
			idle = pm_idle;

			if (!idle)
				idle = default_idle;

			irq_stat[cpu].idle_timestamp = jiffies;
			idle();
        }
        schedule();
        printk("in idle\n");
    }
}

/*
 * This gets run with %ebx containing the
 * function to call, and %edx containing
 * the "args".
 */
extern void kernel_thread_helper(void);
__asm__(".section .text\n"
    ".align 4\n"
    "kernel_thread_helper:\n\t"
    "movl %edx, %eax\n\t"
    "pushl %edx\n\t"
    "call *%ebx\n\t"
    "pushl %eax\n\t"
    "call do_exit\n"
    ".previous");

/*
 * Create a kernel thread
 */
int kernel_thread(int (*fn)(void *), void * arg, unsigned long flags)
{
    struct pt_regs regs;

    memset(&regs, 0, sizeof(regs));

    regs.ebx = (unsigned long) fn;
    regs.edx = (unsigned long) arg;

    regs.xds = __USER_DS;
    regs.xes = __USER_DS;
    regs.orig_eax = -1;
    regs.eip = (unsigned long) kernel_thread_helper;
    regs.xcs = __KERNEL_CS;
    regs.eflags = X86_EFLAGS_IF | X86_EFLAGS_SF | X86_EFLAGS_PF | 0x2;
    return do_fork(flags | CLONE_VM | CLONE_UNTRACED, 0, &regs, 0, NULL, NULL);
}

void exit_thread(void)
{
	struct task_struct *tsk = current;
	struct thread_struct *t = &tsk->thread;

	/* The process may have allocated an io port bitmap... nuke it. */
	if (unlikely(NULL != t->io_bitmap_ptr)) {
		int cpu = get_cpu();
		struct tss_struct *tss = &per_cpu(init_tss, cpu);

		kfree(t->io_bitmap_ptr);
		t->io_bitmap_ptr = NULL;
		/*
		 * Careful, clear this in the TSS too:
		 */
		memset(tss->io_bitmap, 0xff, tss->io_bitmap_max);
		t->io_bitmap_max = 0;
		tss->io_bitmap_owner = NULL;
		tss->io_bitmap_max = 0;
		tss->io_bitmap_base = INVALID_IO_BITMAP_OFFSET;
		put_cpu();
	}
}

void release_thread(struct task_struct *dead_task)
{
	if (dead_task->mm) {
		// temporary debugging check
		if (dead_task->mm->context.size) {
			printk("WARNING: dead process %8s still has LDT? <%p/%d>\n",
					dead_task->comm,
					dead_task->mm->context.ldt,
					dead_task->mm->context.size);
			BUG();
		}
	}

	release_vm86_irqs(dead_task);
}

/*
 * This gets called before we allocate a new thread and copy
 * the current task into it.
 */
void prepare_to_copy(struct task_struct *tsk)
{
	unlazy_fpu(tsk);
}

int copy_thread(int nr, unsigned long clone_flags, unsigned long esp,
	unsigned long unused,
	struct task_struct * p, struct pt_regs * regs)
{
	struct pt_regs * childregs;
	struct task_struct *tsk;
	int err;

    childregs = ((struct pt_regs *) (THREAD_SIZE + (unsigned long) p->thread_info)) - 1;
    *childregs = *regs;
    childregs->eax = 0;
    childregs->esp = esp;

    p->thread.esp = (unsigned long) childregs;
    p->thread.esp0 = (unsigned long) (childregs + 1);

    p->thread.eip = (unsigned long) ret_from_fork;

    savesegment(fs,p->thread.fs);
	savesegment(gs,p->thread.gs);

    tsk = current;
    if (unlikely(NULL != tsk->thread.io_bitmap_ptr)) {
        p->thread.io_bitmap_ptr = kmalloc(IO_BITMAP_BYTES, GFP_KERNEL);
        if (!p->thread.io_bitmap_ptr) {
            p->thread.io_bitmap_max = 0;
			return -ENOMEM;
        }
        memcpy(p->thread.io_bitmap_ptr, tsk->thread.io_bitmap_ptr,
			IO_BITMAP_BYTES);
    }

    /*
	 * Set a new TLS for the child thread?
	 */
	if (clone_flags & CLONE_SETTLS) {
		struct desc_struct *desc;
		struct user_desc info;
		int idx;

		err = -EFAULT;
		if (copy_from_user(&info, (void __user *)childregs->esi, sizeof(info)))
			goto out;
		err = -EINVAL;
		if (LDT_empty(&info))
			goto out;

		idx = info.entry_number;
		if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX)
			goto out;

		desc = p->thread.tls_array + idx - GDT_ENTRY_TLS_MIN;
		desc->a = LDT_entry_a(&info);
		desc->b = LDT_entry_b(&info);
	}

	err = 0;
 out:
	if (err && p->thread.io_bitmap_ptr) {
		kfree(p->thread.io_bitmap_ptr);
		p->thread.io_bitmap_max = 0;
	}
	return err;
}

static inline void
handle_io_bitmap(struct thread_struct *next, struct tss_struct *tss)
{
	if (!next->io_bitmap_ptr) {
		/*
		 * Disable the bitmap via an invalid offset. We still cache
		 * the previous bitmap owner and the IO bitmap contents:
		 */
		tss->io_bitmap_base = INVALID_IO_BITMAP_OFFSET;
		return;
	}
	if (likely(next == tss->io_bitmap_owner)) {
		/*
		 * Previous owner of the bitmap (hence the bitmap content)
		 * matches the next task, we dont have to do anything but
		 * to set a valid offset in the TSS:
		 */
		tss->io_bitmap_base = IO_BITMAP_OFFSET;
		return;
	}
	/*
	 * Lazy TSS's I/O bitmap copy. We set an invalid offset here
	 * and we let the task to get a GPF in case an I/O instruction
	 * is performed.  The handler of the GPF will verify that the
	 * faulting task has a valid I/O bitmap and, it true, does the
	 * real copy and restart the instruction.  This will save us
	 * redundant copies when the currently switched task does not
	 * perform any I/O during its timeslice.
	 */
	tss->io_bitmap_base = INVALID_IO_BITMAP_OFFSET_LAZY;
}

#define loaddebug(thread,register) \
		__asm__("movl %0,%%db" #register  \
			: /* no output */ \
			:"r" (thread->debugreg[register]))

struct task_struct fastcall * __switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
	struct thread_struct *prev = &prev_p->thread,
				 *next = &next_p->thread;
	int cpu = smp_processor_id();
	struct tss_struct *tss = &per_cpu(init_tss, cpu);

	/* never put a printk in __switch_to... printk() calls wake_up*() indirectly */

	__unlazy_fpu(prev_p);

	/*
	 * Reload esp0, LDT and the page table pointer:
	 */
	load_esp0(tss, next);

	/*
	 * Load the per-thread Thread-Local Storage descriptor.
	 */
	load_TLS(next, cpu);

	/*
	 * Save away %fs and %gs. No need to save %es and %ds, as
	 * those are always kernel segments while inside the kernel.
	 */
	asm volatile("movl %%fs,%0":"=rm" ((int) prev->fs)::"memory");
	asm volatile("movl %%gs,%0":"=rm" ((int) prev->gs)::"memory");

	/*
	 * Restore %fs and %gs if needed.
	 */
	if (unlikely(prev->fs | prev->gs | next->fs | next->gs)) {
		loadsegment(fs, next->fs);
		loadsegment(gs, next->gs);
	}

	/*
	 * Now maybe reload the debug registers
	 */
	if (unlikely(next->debugreg[7])) {
		loaddebug(next, 0);
		loaddebug(next, 1);
		loaddebug(next, 2);
		loaddebug(next, 3);
		/* no 4 and 5 */
		loaddebug(next, 6);
		loaddebug(next, 7);
	}

	if (unlikely(prev->io_bitmap_ptr || next->io_bitmap_ptr))
		handle_io_bitmap(next, tss);

	return prev_p;
}

asmlinkage int sys_fork(struct pt_regs regs)
{
	return do_fork(SIGCHLD, regs.esp, &regs, 0, NULL, NULL);
}

asmlinkage int sys_execve(struct pt_regs regs)
{
	int error;
	char * filename;

	filename = getname((char __user *) regs.ebx);
	error = PTR_ERR(filename);
	if (IS_ERR(filename))
		goto out;
	error = do_execve(filename,
			(char __user * __user *) regs.ecx,
			(char __user * __user *) regs.edx,
			&regs);
	if (error == 0) {
		task_lock(current);
		current->ptrace &= ~PT_DTRACE;
		task_unlock(current);
		/* Make sure we don't return using sysenter.. */
		set_thread_flag(TIF_IRET);
	}
	putname(filename);
out:
	return error;
}