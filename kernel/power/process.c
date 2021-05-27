#undef DEBUG

#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/suspend.h>
#include <linux/module.h>

/* Refrigerator is place where frozen processes are stored :-). */
void refrigerator(unsigned long flag)
{
    long save;
    save = current->state;
    current->state = TASK_UNINTERRUPTIBLE;
    pr_debug("%s entered refrigerator\n", current->comm);
	printk("=");
	current->flags &= ~PF_FREEZE;

    spin_lock_irq(&current->sighand->siglock);
	recalc_sigpending(); /* We sent fake signal, clean it up */
	spin_unlock_irq(&current->sighand->siglock);

    while (current->flags & PF_FROZEN)
        schedule();
    pr_debug("%s left refrigerator\n", current->comm);
	current->state = save;
}