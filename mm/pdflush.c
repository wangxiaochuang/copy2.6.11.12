#include <linux/sched.h>
#include <linux/list.h>
#include <linux/signal.h>
#include <linux/spinlock.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>		// Needed by writeback.h
#include <linux/writeback.h>	// Prototypes pdflush_operation()
#include <linux/kthread.h>

#define MIN_PDFLUSH_THREADS	2
#define MAX_PDFLUSH_THREADS	8

static void start_one_pdflush_thread(void);

static LIST_HEAD(pdflush_list);
static DEFINE_SPINLOCK(pdflush_lock);

int nr_pdflush_threads = 0;

static unsigned long last_empty_jifs;

struct pdflush_work {
	struct task_struct *who;	/* The thread */
	void (*fn)(unsigned long);	/* A callback function */
	unsigned long arg0;		/* An argument to the callback */
	struct list_head list;		/* On pdflush_list, when idle */
	unsigned long when_i_went_to_sleep;
};

int pdflush_operation(void (*fn)(unsigned long), unsigned long arg0)
{
	unsigned long flags;
	int ret = 0;

	if (fn == NULL)
		BUG();		/* Hard to diagnose if it's deferred */

	spin_lock_irqsave(&pdflush_lock, flags);
	if (list_empty(&pdflush_list)) {
		spin_unlock_irqrestore(&pdflush_lock, flags);
		ret = -1;
	} else {
		struct pdflush_work *pdf;

		pdf = list_entry(pdflush_list.next, struct pdflush_work, list);
		list_del_init(&pdf->list);
		if (list_empty(&pdflush_list))
			last_empty_jifs = jiffies;
		pdf->fn = fn;
		pdf->arg0 = arg0;
		wake_up_process(pdf->who);
		spin_unlock_irqrestore(&pdflush_lock, flags);
	}
	return ret;
}