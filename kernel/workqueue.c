#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/signal.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/kthread.h>

struct cpu_workqueue_struct {

	spinlock_t lock;

	long remove_sequence;	/* Least-recently added (next to run) */
	long insert_sequence;	/* Next to add */

	struct list_head worklist;
	wait_queue_head_t more_work;
	wait_queue_head_t work_done;

	struct workqueue_struct *wq;
	task_t *thread;

	int run_depth;		/* Detect run_workqueue() recursion depth */
} ____cacheline_aligned;

struct workqueue_struct {
	struct cpu_workqueue_struct cpu_wq[NR_CPUS];
	const char *name;
	struct list_head list; 	/* Empty if single thread */
};

/* All the per-cpu workqueues on the system, for hotplug cpu to add/remove
   threads to each one as cpus come/go. */
static DEFINE_SPINLOCK(workqueue_lock);
static LIST_HEAD(workqueues);

/* If it's single threaded, it isn't in the list of workqueues. */
static inline int is_single_threaded(struct workqueue_struct *wq)
{
	return list_empty(&wq->list);
}

/* Preempt must be disabled. */
static void __queue_work(struct cpu_workqueue_struct *cwq,
			 struct work_struct *work)
{
	unsigned long flags;

	spin_lock_irqsave(&cwq->lock, flags);
	work->wq_data = cwq;
	list_add_tail(&work->entry, &cwq->worklist);
	cwq->insert_sequence++;
	wake_up(&cwq->more_work);
	spin_unlock_irqrestore(&cwq->lock, flags);
}

/*
 * Queue work on a workqueue. Return non-zero if it was successfully
 * added.
 *
 * We queue the work to the CPU it was submitted, but there is no
 * guarantee that it will be processed by that CPU.
 */
int fastcall queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	int ret = 0, cpu = get_cpu();

	if (!test_and_set_bit(0, &work->pending)) {
		if (unlikely(is_single_threaded(wq)))
			cpu = 0;
		BUG_ON(!list_empty(&work->entry));
		__queue_work(wq->cpu_wq + cpu, work);
		ret = 1;
	}
	put_cpu();
	return ret;
}

static void delayed_work_timer_fn(unsigned long __data)
{
	struct work_struct *work = (struct work_struct *)__data;
	struct workqueue_struct *wq = work->wq_data;
	int cpu = smp_processor_id();

	if (unlikely(is_single_threaded(wq)))
		cpu = 0;

	__queue_work(wq->cpu_wq + cpu, work);
}

int fastcall queue_delayed_work(struct workqueue_struct *wq,
			struct work_struct *work, unsigned long delay)
{
	int ret = 0;
	struct timer_list *timer = &work->timer;

	if (!test_and_set_bit(0, &work->pending)) {
		BUG_ON(timer_pending(timer));
		BUG_ON(!list_empty(&work->entry));

		work->wq_data = wq;
		timer->expires = jiffies + delay;
		timer->data = (unsigned long) work;
		timer->function = delayed_work_timer_fn;
		add_timer(timer);
		ret = 1;
	}
	return ret;
}

static inline void run_workqueue(struct cpu_workqueue_struct *cwq)
{
	unsigned long flags;

	spin_lock_irqsave(&cwq->lock, flags);
	cwq->run_depth++;
	if (cwq->run_depth > 3) {
		/* morton gets to eat his hat */
		printk("%s: recursion depth exceeded: %d\n",
			__FUNCTION__, cwq->run_depth);
		dump_stack();
	}
	while (!list_empty(&cwq->worklist)) {
		struct work_struct *work = list_entry(cwq->worklist.next,
						struct work_struct, entry);
		void (*f) (void *) = work->func;
		void *data = work->data;

		list_del_init(cwq->worklist.next);
		spin_unlock_irqrestore(&cwq->lock, flags);

		BUG_ON(work->wq_data != cwq);
		clear_bit(0, &work->pending);
		f(data);

		spin_lock_irqsave(&cwq->lock, flags);
		cwq->remove_sequence++;
		wake_up(&cwq->work_done);
	}
	cwq->run_depth--;
	spin_unlock_irqrestore(&cwq->lock, flags);
}

static int worker_thread(void *__cwq)
{
	struct cpu_workqueue_struct *cwq = __cwq;
	DECLARE_WAITQUEUE(wait, current);
	struct k_sigaction sa;
	sigset_t blocked;

	current->flags |= PF_NOFREEZE;

	set_user_nice(current, -5);

	sigfillset(&blocked);
	sigprocmask(SIG_BLOCK, &blocked, NULL);
	flush_signals(current);

	sa.sa.sa_handler = SIG_IGN;
	sa.sa.sa_flags = 0;
	siginitset(&sa.sa.sa_mask, sigmask(SIGCHLD));
	do_sigaction(SIGCHLD, &sa, (struct k_sigaction *)0);

	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		add_wait_queue(&cwq->more_work, &wait);
		if (list_empty(&cwq->worklist))
			schedule();
		else
			__set_current_state(TASK_RUNNING);
		remove_wait_queue(&cwq->more_work, &wait);

		if (!list_empty(&cwq->worklist))
			run_workqueue(cwq);
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

void fastcall flush_workqueue(struct workqueue_struct *wq)
{
}

static struct task_struct *create_workqueue_thread(struct workqueue_struct *wq,
						   int cpu)
{
	struct cpu_workqueue_struct *cwq = wq->cpu_wq + cpu;
	struct task_struct *p;

	spin_lock_init(&cwq->lock);
	cwq->wq = wq;
	cwq->thread = NULL;
	cwq->insert_sequence = 0;
	cwq->remove_sequence = 0;
	INIT_LIST_HEAD(&cwq->worklist);
	init_waitqueue_head(&cwq->more_work);
	init_waitqueue_head(&cwq->work_done);

	if (is_single_threaded(wq))
		p = kthread_create(worker_thread, cwq, "%s", wq->name);
	else
		p = kthread_create(worker_thread, cwq, "%s/%d", wq->name, cpu);
	if (IS_ERR(p))
		return NULL;
	cwq->thread = p;
	return p;
}

struct workqueue_struct *__create_workqueue(const char *name,
					    int singlethread)
{
	int cpu, destroy = 0;
	struct workqueue_struct *wq;
	struct task_struct *p;

	BUG_ON(strlen(name) > 10);

	wq = kmalloc(sizeof(*wq), GFP_KERNEL);
	if (!wq)
		return NULL;
	memset(wq, 0, sizeof(*wq));

	wq->name = name;
	lock_cpu_hotplug();
	if (singlethread) {
		INIT_LIST_HEAD(&wq->list);
		p = create_workqueue_thread(wq, 0);
		if (!p)
			destroy = 1;
		else
			wake_up_process(p);
	} else {
		spin_lock(&workqueue_lock);
		list_add(&wq->list, &workqueues);
		spin_unlock(&workqueue_lock);
		for_each_online_cpu(cpu) {
			p = create_workqueue_thread(wq, cpu);
			if (p) {
				kthread_bind(p, cpu);
				wake_up_process(p);
			} else
				destroy = 1;
		}
	}
	unlock_cpu_hotplug();

	if (destroy) {
		destroy_workqueue(wq);
		wq = NULL;
	}
	return wq;
}

static void cleanup_workqueue_thread(struct workqueue_struct *wq, int cpu)
{
	struct cpu_workqueue_struct *cwq;
	unsigned long flags;
	struct task_struct *p;

	cwq = wq->cpu_wq + cpu;
	spin_lock_irqsave(&cwq->lock, flags);
	p = cwq->thread;
	cwq->thread = NULL;
	spin_unlock_irqrestore(&cwq->lock, flags);
	if (p)
		kthread_stop(p);
}

void destroy_workqueue(struct workqueue_struct *wq)
{
	int cpu;

	flush_workqueue(wq);

	lock_cpu_hotplug();
	if (is_single_threaded(wq)) {
		cleanup_workqueue_thread(wq, 0);
	} else {
		for_each_online_cpu(cpu)
			cleanup_workqueue_thread(wq, cpu);
		spin_lock(&workqueue_lock);
		list_del(&wq->list);
		spin_unlock(&workqueue_lock);
	}
	unlock_cpu_hotplug();
	kfree(wq);
}

static struct workqueue_struct *keventd_wq;

int fastcall schedule_work(struct work_struct *work)
{
	return queue_work(keventd_wq, work);
}

int schedule_delayed_work_on(int cpu,
			struct work_struct *work, unsigned long delay)
{
	return 0;
}

int keventd_up(void)
{
	return keventd_wq != NULL;
}

void init_workqueues(void)
{
	hotcpu_notifier(workqueue_cpu_callback, 0);
	keventd_wq = create_workqueue("events");
	BUG_ON(!keventd_wq);
}

