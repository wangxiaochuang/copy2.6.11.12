#include <linux/mm.h>
#include <linux/module.h>
#include <linux/nmi.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include <linux/highmem.h>
#include <linux/smp_lock.h>
#include <asm/mmu_context.h>
#include <linux/interrupt.h>
#include <linux/completion.h>
#include <linux/kernel_stat.h>
#include <linux/security.h>
#include <linux/notifier.h>
#include <linux/profile.h>
#include <linux/suspend.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/threads.h>
#include <linux/timer.h>
#include <linux/rcupdate.h>
#include <linux/cpu.h>
#include <linux/percpu.h>
#include <linux/kthread.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/times.h>
#include <asm/tlb.h>

#include <asm/unistd.h>

asmlinkage void __sched schedule(void) {
	
}

static int try_to_wake_up(task_t * p, unsigned int state, int sync)
{
	return 1;
}

#ifdef CONFIG_PREEMPT
#error "CONFIG_PREEMPT"
#endif /* CONFIG_PREEMPT */

int default_wake_function(wait_queue_t *curr, unsigned mode, int sync, void *key)
{
	task_t *p = curr->task;
	return try_to_wake_up(p, mode, sync);
}

EXPORT_SYMBOL(default_wake_function);

static void __wake_up_common(wait_queue_head_t *q, unsigned int mode,
			     int nr_exclusive, int sync, void *key)
{
	struct list_head *tmp, *next;

	list_for_each_safe(tmp, next, &q->task_list) {
		wait_queue_t *curr;
		unsigned flags;
		curr = list_entry(tmp, wait_queue_t, task_list);
		flags = curr->flags;
		if (curr->func(curr, mode, sync, key) &&
		    (flags & WQ_FLAG_EXCLUSIVE) &&
		    !--nr_exclusive)
			break;
	}
}

void fastcall __wake_up(wait_queue_head_t *q, unsigned int mode,
				int nr_exclusive, void *key)
{
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	__wake_up_common(q, mode, nr_exclusive, 0, key);
	spin_unlock_irqrestore(&q->lock, flags);
}

EXPORT_SYMBOL(__wake_up);

void fastcall __wake_up_locked(wait_queue_head_t *q, unsigned int mode)
{
	__wake_up_common(q, mode, 1, 0, NULL);
}