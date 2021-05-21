#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <asm/atomic.h>
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/moduleparam.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/rcupdate.h>
#include <linux/cpu.h>

/* Definition for rcupdate control block. */
struct rcu_ctrlblk rcu_ctrlblk = 
	{ .cur = -300, .completed = -300 };
struct rcu_ctrlblk rcu_bh_ctrlblk =
	{ .cur = -300, .completed = -300 };

/* Bookkeeping of the progress of the grace period */
struct rcu_state {
	spinlock_t	lock; /* Guard this struct and writes to rcu_ctrlblk */
	cpumask_t	cpumask; /* CPUs that need to switch in order    */
	                              /* for current batch to proceed.        */
};

static struct rcu_state rcu_state ____cacheline_maxaligned_in_smp =
	  {.lock = SPIN_LOCK_UNLOCKED, .cpumask = CPU_MASK_NONE };
static struct rcu_state rcu_bh_state ____cacheline_maxaligned_in_smp =
	  {.lock = SPIN_LOCK_UNLOCKED, .cpumask = CPU_MASK_NONE };

DEFINE_PER_CPU(struct rcu_data, rcu_data) = { 0L };
DEFINE_PER_CPU(struct rcu_data, rcu_bh_data) = { 0L };

/* Fake initialization required by compiler */
static DEFINE_PER_CPU(struct tasklet_struct, rcu_tasklet) = {NULL};
static int maxbatch = 10;

void fastcall call_rcu(struct rcu_head *head,
				void (*func)(struct rcu_head *rcu))
{
	unsigned long flags;
	struct rcu_data *rdp;

	head->func = func;
	head->next = NULL;
	local_irq_save(flags);
	rdp = &__get_cpu_var(rcu_data);
	*rdp->nxttail = head;
	rdp->nxttail = &head->next;
	local_irq_restore(flags);
}

/*
 * Invoke the completed RCU callbacks. They are expected to be in
 * a per-cpu list.
 */
static void rcu_do_batch(struct rcu_data *rdp)
{
	struct rcu_head *next, *list;
	int count = 0;

	list = rdp->donelist;
	while (list) {
		next = rdp->donelist = list->next;
		list->func(list);
		list = next;
		if (++count >= maxbatch)
			break;
	}
	if (!rdp->donelist)
		rdp->donetail = &rdp->donelist;
	else
		tasklet_schedule(&per_cpu(rcu_tasklet, rdp->cpu));
}

static void rcu_start_batch(struct rcu_ctrlblk *rcp, struct rcu_state *rsp,
				int next_pending)
{
    if (next_pending)
		rcp->next_pending = 1;

	if (rcp->next_pending &&
			rcp->completed == rcp->cur) {
		/* Can't change, since spin lock held. */
		cpus_andnot(rsp->cpumask, cpu_online_map, nohz_cpu_mask);

		rcp->next_pending = 0;
		/* next_pending == 0 must be visible in __rcu_process_callbacks()
		 * before it can see new value of cur.
		 */
		smp_wmb();
		rcp->cur++;
	}
}

/*
 * cpu went through a quiescent state since the beginning of the grace period.
 * Clear it from the cpu mask and complete the grace period if it was the last
 * cpu. Start another grace period if someone has further entries pending
 */
static void cpu_quiet(int cpu, struct rcu_ctrlblk *rcp, struct rcu_state *rsp)
{
	cpu_clear(cpu, rsp->cpumask);
	if (cpus_empty(rsp->cpumask)) {
		/* batch completed ! */
		rcp->completed = rcp->cur;
		rcu_start_batch(rcp, rsp, 0);
	}
}

/*
 * Check if the cpu has gone through a quiescent state (say context
 * switch). If so and if it already hasn't done so in this RCU
 * quiescent cycle, then indicate that it has done so.
 */
static void rcu_check_quiescent_state(struct rcu_ctrlblk *rcp,
			struct rcu_state *rsp, struct rcu_data *rdp)
{
    if (rdp->quiescbatch != rcp->cur) {
		/* start new grace period: */
		rdp->qs_pending = 1;
		rdp->passed_quiesc = 0;
		rdp->quiescbatch = rcp->cur;
		return;
	}

	/* Grace period already completed for this cpu?
	 * qs_pending is checked instead of the actual bitmap to avoid
	 * cacheline trashing.
	 */
	if (!rdp->qs_pending)
		return;

	/* 
	 * Was there a quiescent state since the beginning of the grace
	 * period? If no, then exit and wait for the next call.
	 */
	if (!rdp->passed_quiesc)
		return;
	rdp->qs_pending = 0;

	spin_lock(&rsp->lock);
	/*
	 * rdp->quiescbatch/rcp->cur and the cpu bitmap can come out of sync
	 * during cpu startup. Ignore the quiescent state.
	 */
	if (likely(rdp->quiescbatch == rcp->cur))
		cpu_quiet(rdp->cpu, rcp, rsp);

	spin_unlock(&rsp->lock);
}

#ifdef CONFIG_HOTPLUG_CPU

#else

static void rcu_offline_cpu(int cpu)
{
}

#endif

/*
 * This does the RCU processing work from tasklet context. 
 */
static void __rcu_process_callbacks(struct rcu_ctrlblk *rcp,
			struct rcu_state *rsp, struct rcu_data *rdp)
{
    if (rdp->curlist && !rcu_batch_before(rcp->completed, rdp->batch)) {
		*rdp->donetail = rdp->curlist;
		rdp->donetail = rdp->curtail;
		rdp->curlist = NULL;
		rdp->curtail = &rdp->curlist;
	}
    local_irq_disable();
    if (rdp->nxtlist && !rdp->curlist) {
		rdp->curlist = rdp->nxtlist;
		rdp->curtail = rdp->nxttail;
		rdp->nxtlist = NULL;
		rdp->nxttail = &rdp->nxtlist;
		local_irq_enable();

		/*
		 * start the next batch of callbacks
		 */

		/* determine batch number */
		rdp->batch = rcp->cur + 1;
		/* see the comment and corresponding wmb() in
		 * the rcu_start_batch()
		 */
		smp_rmb();

		if (!rcp->next_pending) {
			/* and start it/schedule start if it's a new batch */
			spin_lock(&rsp->lock);
			rcu_start_batch(rcp, rsp, 1);
			spin_unlock(&rsp->lock);
		}
	} else {
		local_irq_enable();
	}
    rcu_check_quiescent_state(rcp, rsp, rdp);
	if (rdp->donelist)
		rcu_do_batch(rdp);
}

static void rcu_process_callbacks(unsigned long unused)
{
	__rcu_process_callbacks(&rcu_ctrlblk, &rcu_state,
				&__get_cpu_var(rcu_data));
	__rcu_process_callbacks(&rcu_bh_ctrlblk, &rcu_bh_state,
				&__get_cpu_var(rcu_bh_data));
}

void rcu_check_callbacks(int cpu, int user)
{
	if (user || 
	    (idle_cpu(cpu) && !in_softirq() && 
				hardirq_count() <= (1 << HARDIRQ_SHIFT))) {
		rcu_qsctr_inc(cpu);
		rcu_bh_qsctr_inc(cpu);
	} else if (!in_softirq())
		rcu_bh_qsctr_inc(cpu);
	tasklet_schedule(&per_cpu(rcu_tasklet, cpu));
}

static void rcu_init_percpu_data(int cpu, struct rcu_ctrlblk *rcp,
						struct rcu_data *rdp)
{
	memset(rdp, 0, sizeof(*rdp));
	rdp->curtail = &rdp->curlist;
	rdp->nxttail = &rdp->nxtlist;
	rdp->donetail = &rdp->donelist;
	rdp->quiescbatch = rcp->completed;
	rdp->qs_pending = 0;
	rdp->cpu = cpu;
}

static void __devinit rcu_online_cpu(int cpu)
{
    struct rcu_data *rdp = &per_cpu(rcu_data, cpu);
    struct rcu_data *bh_rdp = &per_cpu(rcu_bh_data, cpu);

    rcu_init_percpu_data(cpu, &rcu_ctrlblk, rdp);
    rcu_init_percpu_data(cpu, &rcu_bh_ctrlblk, bh_rdp);
    tasklet_init(&per_cpu(rcu_tasklet, cpu), rcu_process_callbacks, 0UL);
}

static int __devinit rcu_cpu_notify(struct notifier_block *self, 
				unsigned long action, void *hcpu)
{
    long cpu = (long)hcpu;
    switch (action) {
        case CPU_UP_PREPARE:
            rcu_online_cpu(cpu);
            break;
        case CPU_DEAD:
            rcu_offline_cpu(cpu);
            break;
        default:
            break;
    }
    return NOTIFY_OK;
}

static struct notifier_block __devinitdata rcu_nb = {
	.notifier_call	= rcu_cpu_notify,
};

/*
 * Initializes rcu mechanism.  Assumed to be called early.
 * That is before local timer(SMP) or jiffie timer (uniproc) is setup.
 * Note that rcu_qsctr and friends are implicitly
 * initialized due to the choice of ``0'' for RCU_CTR_INVALID.
 */
void __init rcu_init(void)
{
    rcu_cpu_notify(&rcu_nb, CPU_UP_PREPARE,
			(void *)(long)smp_processor_id());
    /* Register notifier for non-boot CPUs */
	register_cpu_notifier(&rcu_nb);
}

struct rcu_synchronize {
	struct rcu_head head;
	struct completion completion;
};

static void wakeme_after_rcu(struct rcu_head  *head)
{
	struct rcu_synchronize *rcu;

	rcu = container_of(head, struct rcu_synchronize, head);
	complete(&rcu->completion);
}

void synchronize_kernel(void)
{
	struct rcu_synchronize rcu;

	init_completion(&rcu.completion);
	/* Will wake me after RCU finished */
	call_rcu(&rcu.head, wakeme_after_rcu);

	/* Wait for it */
	wait_for_completion(&rcu.completion);
}

EXPORT_SYMBOL(synchronize_kernel);