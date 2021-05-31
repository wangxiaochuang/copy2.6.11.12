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

/*
 * Convert user-nice values [ -20 ... 0 ... 19 ]
 * to static priority [ MAX_RT_PRIO..MAX_PRIO-1 ],
 * and back.
 */
#define NICE_TO_PRIO(nice)	(MAX_RT_PRIO + (nice) + 20)
#define PRIO_TO_NICE(prio)	((prio) - MAX_RT_PRIO - 20)
#define TASK_NICE(p)		PRIO_TO_NICE((p)->static_prio)

/*
 * 'User priority' is the nice value converted to something we
 * can work with better when scaling various scheduler parameters,
 * it's a [ 0 ... 39 ] range.
 */
#define USER_PRIO(p)		((p)-MAX_RT_PRIO)
#define TASK_USER_PRIO(p)	USER_PRIO((p)->static_prio)
#define MAX_USER_PRIO		(USER_PRIO(MAX_PRIO))

/*
 * Some helpers for converting nanosecond timing to jiffy resolution
 */
#define NS_TO_JIFFIES(TIME)	((TIME) / (1000000000 / HZ))
#define JIFFIES_TO_NS(TIME)	((TIME) * (1000000000 / HZ))

/*
 * These are the 'tuning knobs' of the scheduler:
 *
 * Minimum timeslice is 5 msecs (or 1 jiffy, whichever is larger),
 * default timeslice is 100 msecs, maximum timeslice is 800 msecs.
 * Timeslices get refilled after they expire.
 */
#define MIN_TIMESLICE		max(5 * HZ / 1000, 1)
#define DEF_TIMESLICE		(100 * HZ / 1000)
#define ON_RUNQUEUE_WEIGHT	 30
#define CHILD_PENALTY		 95
#define PARENT_PENALTY		100
#define EXIT_WEIGHT		  3
#define PRIO_BONUS_RATIO	 25
#define MAX_BONUS		(MAX_USER_PRIO * PRIO_BONUS_RATIO / 100)
#define INTERACTIVE_DELTA	  2
#define MAX_SLEEP_AVG		(DEF_TIMESLICE * MAX_BONUS)
#define STARVATION_LIMIT	(MAX_SLEEP_AVG)
#define NS_MAX_SLEEP_AVG	(JIFFIES_TO_NS(MAX_SLEEP_AVG))

/*
 * If a task is 'interactive' then we reinsert it in the active
 * array after it has expired its current timeslice. (it will not
 * continue to run immediately, it will still roundrobin with
 * other interactive tasks.)
 *
 * This part scales the interactivity limit depending on niceness.
 *
 * We scale it linearly, offset by the INTERACTIVE_DELTA delta.
 * Here are a few examples of different nice levels:
 *
 *  TASK_INTERACTIVE(-20): [1,1,1,1,1,1,1,1,1,0,0]
 *  TASK_INTERACTIVE(-10): [1,1,1,1,1,1,1,0,0,0,0]
 *  TASK_INTERACTIVE(  0): [1,1,1,1,0,0,0,0,0,0,0]
 *  TASK_INTERACTIVE( 10): [1,1,0,0,0,0,0,0,0,0,0]
 *  TASK_INTERACTIVE( 19): [0,0,0,0,0,0,0,0,0,0,0]
 *
 * (the X axis represents the possible -5 ... 0 ... +5 dynamic
 *  priority range a task can explore, a value of '1' means the
 *  task is rated interactive.)
 *
 * Ie. nice +19 tasks can never get 'interactive' enough to be
 * reinserted into the active array. And only heavily CPU-hog nice -20
 * tasks will be expired. Default nice 0 tasks are somewhere between,
 * it takes some effort for them to get interactive, but it's not
 * too hard.
 */

#define CURRENT_BONUS(p) \
	(NS_TO_JIFFIES((p)->sleep_avg) * MAX_BONUS / \
		MAX_SLEEP_AVG)

#define GRANULARITY	(10 * HZ / 1000 ? : 1)

#ifdef CONFIG_SMP
#define TIMESLICE_GRANULARITY(p)	(GRANULARITY * \
		(1 << (((MAX_BONUS - CURRENT_BONUS(p)) ? : 1) - 1)) * \
			num_online_cpus())
#else
#define TIMESLICE_GRANULARITY(p)	(GRANULARITY * \
		(1 << (((MAX_BONUS - CURRENT_BONUS(p)) ? : 1) - 1)))
#endif

#define SCALE(v1,v1_max,v2_max) \
	(v1) * (v2_max) / (v1_max)

#define DELTA(p) \
	(SCALE(TASK_NICE(p), 40, MAX_BONUS) + INTERACTIVE_DELTA)

#define TASK_INTERACTIVE(p) \
	((p)->prio <= (p)->static_prio - DELTA(p))

#define INTERACTIVE_SLEEP(p) \
	(JIFFIES_TO_NS(MAX_SLEEP_AVG * \
		(MAX_BONUS / 2 + DELTA((p)) + 1) / MAX_BONUS - 1))

#define TASK_PREEMPTS_CURR(p, rq) \
	((p)->prio < (rq)->curr->prio)

/*
 * task_timeslice() scales user-nice values [ -20 ... 0 ... 19 ]
 * to time slice values: [800ms ... 100ms ... 5ms]
 *
 * The higher a thread's priority, the bigger timeslices
 * it gets during one round of execution. But even the lowest
 * priority thread gets MIN_TIMESLICE worth of execution time.
 */

#define SCALE_PRIO(x, prio) \
	max(x * (MAX_PRIO - prio) / (MAX_USER_PRIO/2), MIN_TIMESLICE)

static unsigned int task_timeslice(task_t *p)
{
	if (p->static_prio < NICE_TO_PRIO(0))
		return SCALE_PRIO(DEF_TIMESLICE*4, p->static_prio);
	else
		return SCALE_PRIO(DEF_TIMESLICE, p->static_prio);
}
#define task_hot(p, now, sd) ((long long) ((now) - (p)->last_ran)	\
				< (long long) (sd)->cache_hot_time)

/*
 * These are the runqueue data structures:
 */

#define BITMAP_SIZE ((((MAX_PRIO+1+7)/8)+sizeof(long)-1)/sizeof(long))

typedef struct runqueue runqueue_t;

struct prio_array {
	unsigned int nr_active;
	unsigned long bitmap[BITMAP_SIZE];
	struct list_head queue[MAX_PRIO];
};

/*
 * This is the main, per-CPU runqueue data structure.
 *
 * Locking rule: those places that want to lock multiple runqueues
 * (such as the load balancing or the thread migration code), lock
 * acquire operations must be ordered by ascending &runqueue.
 */
struct runqueue {
	spinlock_t lock;

	/*
	 * nr_running and cpu_load should be in the same cacheline because
	 * remote CPUs use both these fields when doing load calculation.
	 */
	unsigned long nr_running;
#ifdef CONFIG_SMP
	unsigned long cpu_load;
#endif
	unsigned long long nr_switches;

	/*
	 * This is part of a global counter where only the total sum
	 * over all CPUs matters. A task can increase this counter on
	 * one CPU and if it got migrated afterwards it may decrease
	 * it on another CPU. Always updated under the runqueue lock:
	 */
	unsigned long nr_uninterruptible;

	unsigned long expired_timestamp;
	unsigned long long timestamp_last_tick;
	task_t *curr, *idle;
	struct mm_struct *prev_mm;
	prio_array_t *active, *expired, arrays[2];
	int best_expired_prio;
	atomic_t nr_iowait;

#ifdef CONFIG_SMP
	struct sched_domain *sd;

	/* For active balancing */
	int active_balance;
	int push_cpu;

	task_t *migration_thread;
	struct list_head migration_queue;
#endif

#ifdef CONFIG_SCHEDSTATS
	/* latency stats */
	struct sched_info rq_sched_info;

	/* sys_sched_yield() stats */
	unsigned long yld_exp_empty;
	unsigned long yld_act_empty;
	unsigned long yld_both_empty;
	unsigned long yld_cnt;

	/* schedule() stats */
	unsigned long sched_noswitch;
	unsigned long sched_switch;
	unsigned long sched_cnt;
	unsigned long sched_goidle;

	/* pull_task() stats */
	unsigned long pt_gained[MAX_IDLE_TYPES];
	unsigned long pt_lost[MAX_IDLE_TYPES];

	/* active_load_balance() stats */
	unsigned long alb_cnt;
	unsigned long alb_lost;
	unsigned long alb_gained;
	unsigned long alb_failed;

	/* try_to_wake_up() stats */
	unsigned long ttwu_cnt;
	unsigned long ttwu_attempts;
	unsigned long ttwu_moved;

	/* wake_up_new_task() stats */
	unsigned long wunt_cnt;
	unsigned long wunt_moved;

	/* sched_migrate_task() stats */
	unsigned long smt_cnt;

	/* sched_balance_exec() stats */
	unsigned long sbe_cnt;
#endif
};

static DEFINE_PER_CPU(struct runqueue, runqueues);

#define for_each_domain(cpu, domain) \
	for (domain = cpu_rq(cpu)->sd; domain; domain = domain->parent)

#define cpu_rq(cpu)		(&per_cpu(runqueues, (cpu)))
#define this_rq()		(&__get_cpu_var(runqueues))
#define task_rq(p)		cpu_rq(task_cpu(p))
#define cpu_curr(cpu)		(cpu_rq(cpu)->curr)

#ifndef prepare_arch_switch
# define prepare_arch_switch(rq, next)	do { } while (0)
# define finish_arch_switch(rq, next)	spin_unlock_irq(&(rq)->lock)
# define task_running(rq, p)		((rq)->curr == (p))
#endif

static runqueue_t *task_rq_lock(task_t *p, unsigned long *flags)
	__acquires(rq->lock)
{
	struct runqueue *rq;

repeat_lock_task:
	local_irq_save(*flags);
	rq = task_rq(p);
	spin_lock(&rq->lock);
	if (unlikely(rq != task_rq(p))) {
		spin_unlock_irqrestore(&rq->lock, *flags);
		goto repeat_lock_task;
	}
	return rq;
}

static inline void task_rq_unlock(runqueue_t *rq, unsigned long *flags)
	__releases(rq->lock)
{
	spin_unlock_irqrestore(&rq->lock, *flags);
}


#ifdef CONFIG_SCHEDSTATS

# define schedstat_inc(rq, field)	do { (rq)->field++; } while (0)
# define schedstat_add(rq, field, amt)	do { (rq)->field += (amt); } while (0)
#else /* !CONFIG_SCHEDSTATS */
#error "!CONFIG_SCHEDSTATS"
#endif

#ifdef CONFIG_SCHEDSTATS

static int schedstat_open(struct inode *inode, struct file *file)
{
	return 0;
}

struct file_operations proc_schedstat_operations = {
	.open    = schedstat_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

# define schedstat_inc(rq, field)	do { (rq)->field++; } while (0)
# define schedstat_add(rq, field, amt)	do { (rq)->field += (amt); } while (0)
#else /* !CONFIG_SCHEDSTATS */
# define schedstat_inc(rq, field)	do { } while (0)
# define schedstat_add(rq, field, amt)	do { } while (0)
#endif

/*
 * rq_lock - lock a given runqueue and disable interrupts.
 */
static runqueue_t *this_rq_lock(void)
	__acquires(rq->lock)
{
	runqueue_t *rq;

	local_irq_disable();
	rq = this_rq();
	spin_lock(&rq->lock);

	return rq;
}

#ifdef CONFIG_SCHED_SMT
static int cpu_and_siblings_are_idle(int cpu)
{
	int sib;
	for_each_cpu_mask(sib, cpu_sibling_map[cpu]) {
		if (idle_cpu(sib))
			continue;
		return 0;
	}

	return 1;
}
#else
#error "CONFIG_SCHED_SMT"
#endif

#ifdef CONFIG_SCHEDSTATS
static inline void sched_info_dequeued(task_t *t)
{
	t->sched_info.last_queued = 0;
}

static inline void sched_info_arrive(task_t *t)
{
	unsigned long now = jiffies, diff = 0;
	struct runqueue *rq = task_rq(t);

	if (t->sched_info.last_queued)
		diff = now - t->sched_info.last_queued;
	sched_info_dequeued(t);
	t->sched_info.run_delay += diff;
	t->sched_info.last_arrival = now;
	t->sched_info.pcnt++;

	if (!rq)
		return;

	rq->rq_sched_info.run_delay += diff;
	rq->rq_sched_info.pcnt++;
}

static inline void sched_info_queued(task_t *t)
{
	if (!t->sched_info.last_queued)
		t->sched_info.last_queued = jiffies;
}

static inline void sched_info_depart(task_t *t)
{
	struct runqueue *rq = task_rq(t);
	unsigned long diff = jiffies - t->sched_info.last_arrival;

	t->sched_info.cpu_time += diff;

	if (rq)
		rq->rq_sched_info.cpu_time += diff;
}

static inline void sched_info_switch(task_t *prev, task_t *next)
{
	struct runqueue *rq = task_rq(prev);

	/*
	 * prev now departs the cpu.  It's not interesting to record
	 * stats about how efficient we were at scheduling the idle
	 * process, however.
	 */
	if (prev != rq->idle)
		sched_info_depart(prev);

	if (next != rq->idle)
		sched_info_arrive(next);
}

#else
#error "!CONFIG_SCHEDSTATS"
#endif

static void dequeue_task(struct task_struct *p, prio_array_t *array)
{
	array->nr_active--;
	list_del(&p->run_list);
	if (list_empty(array->queue + p->prio))
		__clear_bit(p->prio, array->bitmap);
}

static void enqueue_task(struct task_struct *p, prio_array_t *array)
{
	sched_info_queued(p);
	list_add_tail(&p->run_list, array->queue + p->prio);
	__set_bit(p->prio, array->bitmap);
	array->nr_active++;
	p->array = array;
}

static void requeue_task(struct task_struct *p, prio_array_t *array)
{
	list_move_tail(&p->run_list, array->queue + p->prio);
}

static inline void enqueue_task_head(struct task_struct *p, prio_array_t *array)
{
	list_add(&p->run_list, array->queue + p->prio);
	__set_bit(p->prio, array->bitmap);
	array->nr_active++;
	p->array = array;
}

static int effective_prio(task_t *p)
{
	int bonus, prio;

	if (rt_task(p))
		return p->prio;

	bonus = CURRENT_BONUS(p) - MAX_BONUS / 2;

	prio = p->static_prio - bonus;
	if (prio < MAX_RT_PRIO)
		prio = MAX_RT_PRIO;
	if (prio > MAX_PRIO-1)
		prio = MAX_PRIO-1;
	return prio;
}

static inline void __activate_task(task_t *p, runqueue_t *rq)
{
	enqueue_task(p, rq->active);
	rq->nr_running++;
}

static inline void __activate_idle_task(task_t *p, runqueue_t *rq)
{
	enqueue_task_head(p, rq->active);
	rq->nr_running++;
}

static void recalc_task_prio(task_t *p, unsigned long long now)
{
	unsigned long long __sleep_time = now - p->timestamp;
	unsigned long sleep_time;

	if (__sleep_time > NS_MAX_SLEEP_AVG)
		sleep_time = NS_MAX_SLEEP_AVG;
	else
		sleep_time = (unsigned long)__sleep_time;

	if (likely(sleep_time > 0)) {
		/*
		 * User tasks that sleep a long time are categorised as
		 * idle and will get just interactive status to stay active &
		 * prevent them suddenly becoming cpu hogs and starving
		 * other processes.
		 */
		if (p->mm && p->activated != -1 &&
			sleep_time > INTERACTIVE_SLEEP(p)) {
				p->sleep_avg = JIFFIES_TO_NS(MAX_SLEEP_AVG -
						DEF_TIMESLICE);
		} else {
			/*
			 * The lower the sleep avg a task has the more
			 * rapidly it will rise with sleep time.
			 */
			sleep_time *= (MAX_BONUS - CURRENT_BONUS(p)) ? : 1;

			/*
			 * Tasks waking from uninterruptible sleep are
			 * limited in their sleep_avg rise as they
			 * are likely to be waiting on I/O
			 */
			if (p->activated == -1 && p->mm) {
				if (p->sleep_avg >= INTERACTIVE_SLEEP(p))
					sleep_time = 0;
				else if (p->sleep_avg + sleep_time >=
						INTERACTIVE_SLEEP(p)) {
					p->sleep_avg = INTERACTIVE_SLEEP(p);
					sleep_time = 0;
				}
			}

			/*
			 * This code gives a bonus to interactive tasks.
			 *
			 * The boost works by updating the 'average sleep time'
			 * value here, based on ->timestamp. The more time a
			 * task spends sleeping, the higher the average gets -
			 * and the higher the priority boost gets as well.
			 */
			p->sleep_avg += sleep_time;

			if (p->sleep_avg > NS_MAX_SLEEP_AVG)
				p->sleep_avg = NS_MAX_SLEEP_AVG;
		}
	}

	p->prio = effective_prio(p);
}

static void activate_task(task_t *p, runqueue_t *rq, int local)
{
	unsigned long long now;

	now = sched_clock();
#ifdef CONFIG_SMP
	if (!local) {
		runqueue_t *this_rq = this_rq();
		now = (now - this_rq->timestamp_last_tick)
			+ rq->timestamp_last_tick;
	}
#endif

	recalc_task_prio(p, now);

	if (!p->activated) {
		if (in_interrupt()) {
			p->activated = 2;
		} else {
			p->activated = 1;
		}
	}
	p->timestamp = now;

	__activate_task(p, rq);
}

static void deactivate_task(struct task_struct *p, runqueue_t *rq)
{
	rq->nr_running--;
	dequeue_task(p, p->array);
	p->array = NULL;
}

#ifdef CONFIG_SMP
static void resched_task(task_t *p)
{
	int need_resched, nrpolling;

	assert_spin_locked(&task_rq(p)->lock);

	/* minimise the chance of sending an interrupt to poll_idle() */
	nrpolling = test_tsk_thread_flag(p, TIF_POLLING_NRFLAG);
	need_resched = test_and_set_tsk_thread_flag(p,TIF_NEED_RESCHED);
	nrpolling |= test_tsk_thread_flag(p,TIF_POLLING_NRFLAG);

	if (!need_resched && !nrpolling && (task_cpu(p) != smp_processor_id()))
		smp_send_reschedule(task_cpu(p));
}
#else
#error "!CONFIG_SMP"
#endif

inline int task_curr(const task_t *p)
{
	return cpu_curr(task_cpu(p)) == p;
}

#ifdef CONFIG_SMP

enum request_type {
	REQ_MOVE_TASK,
	REQ_SET_DOMAIN,
};

typedef struct {
	struct list_head list;
	enum request_type type;

	/* For REQ_MOVE_TASK */
	task_t *task;
	int dest_cpu;

	/* For REQ_SET_DOMAIN */
	struct sched_domain *sd;

	struct completion done;
} migration_req_t;

static int migrate_task(task_t *p, int dest_cpu, migration_req_t *req)
{
	runqueue_t *rq = task_rq(p);

	if (!p->array && !task_running(rq, p)) {
		set_task_cpu(p, dest_cpu);
		return 0;
	}

	init_completion(&req->done);
	req->type = REQ_MOVE_TASK;
	req->task = p;
	req->dest_cpu = dest_cpu;
	list_add(&req->list, &rq->migration_queue);
	return 1;
}

void wait_task_inactive(task_t * p)
{
	unsigned long flags;
	runqueue_t *rq;
	int preempted;

repeat:
	rq = task_rq_lock(p, &flags);
	if (unlikely(p->array || task_running(rq, p))) {
		preempted = !task_running(rq, p);
		task_rq_unlock(rq, &flags);
		cpu_relax();
		if (preempted)
			yield();
		goto repeat;
	}
	task_rq_unlock(rq, &flags);
}

void kick_process(task_t *p)
{
	int cpu;

	preempt_disable();
	cpu = task_cpu(p);
	if ((cpu != smp_processor_id()) && task_curr(p))
		smp_send_reschedule(cpu);
	preempt_enable();
}

static inline unsigned long source_load(int cpu)
{
	runqueue_t *rq = cpu_rq(cpu);
	unsigned long load_now = rq->nr_running * SCHED_LOAD_SCALE;

	return min(rq->cpu_load, load_now);
}

static inline unsigned long target_load(int cpu)
{
	runqueue_t *rq = cpu_rq(cpu);
	unsigned long load_now = rq->nr_running * SCHED_LOAD_SCALE;

	return max(rq->cpu_load, load_now);
}

#endif

#if defined(ARCH_HAS_SCHED_WAKE_IDLE)
static int wake_idle(int cpu, task_t *p)
{
	cpumask_t tmp;
	struct sched_domain *sd;
	int i;

	if (idle_cpu(cpu))
		return cpu;

	for_each_domain(cpu, sd) {
		if (sd->flags & SD_WAKE_IDLE) {
			cpus_and(tmp, sd->span, cpu_online_map);
			cpus_and(tmp, tmp, p->cpus_allowed);
			for_each_cpu_mask(i, tmp) {
				if (idle_cpu(i))
					return i;
			}
		}
		else break;
	}
	return cpu;
}
#else
#error "!ARCH_HAS_SCHED_WAKE_IDLE"
#endif

static int try_to_wake_up(task_t * p, unsigned int state, int sync)
{
	int cpu, this_cpu, success = 0;
	unsigned long flags;
	long old_state;
	runqueue_t *rq;
#ifdef CONFIG_SMP
	unsigned long load, this_load;
	struct sched_domain *sd;
	int new_cpu;
#endif

	rq = task_rq_lock(p, &flags);
	schedstat_inc(rq, ttwu_cnt);
	old_state = p->state;
	if (!(old_state & state))
		goto out;

	if (p->array)
		goto out_running;

	cpu = task_cpu(p);
	this_cpu = smp_processor_id();

#ifdef CONFIG_SMP
	if (unlikely(task_running(rq, p)))
		goto out_activate;

	new_cpu = cpu;

	if (cpu == this_cpu || unlikely(!cpu_isset(this_cpu, p->cpus_allowed)))
		goto out_set_cpu;

	load = source_load(cpu);
	this_load = target_load(this_cpu);

	if (sync)
		this_load -= SCHED_LOAD_SCALE;

	if (load < SCHED_LOAD_SCALE / 2 && this_load > SCHED_LOAD_SCALE / 2)	
		goto out_set_cpu;

	new_cpu = this_cpu;

	for_each_domain(this_cpu, sd) {
		unsigned int imbalance;

		imbalance = sd->imbalance_pct + (sd->imbalance_pct - 100) / 2;

		if ((sd->flags & SD_WAKE_AFFINE) &&
				!task_hot(p, rq->timestamp_last_tick, sd)) {
            if (cpu_isset(cpu, sd->span)) {
				schedstat_inc(sd, ttwu_wake_affine);
				goto out_set_cpu;
			}
		} else if ((sd->flags & SD_WAKE_BALANCE) &&
				imbalance * this_load <= 100 * load) {
            
			if (cpu_isset(cpu, sd->span)) {
				schedstat_inc(sd, ttwu_wake_balance);
				goto out_set_cpu;
			}
		}
	}

	new_cpu = cpu;
out_set_cpu:
	schedstat_inc(rq, ttwu_attempts);
	new_cpu = wake_idle(new_cpu, p);
	if (new_cpu != cpu) {
		schedstat_inc(rq, ttwu_moved);
		set_task_cpu(p, new_cpu);
		task_rq_unlock(rq, &flags);
		rq = task_rq_lock(p, &flags);
		old_state = p->state;
		if (!(old_state & state))
			goto out;
		if (p->array)
			goto out_running;

		this_cpu = smp_processor_id();
		cpu = task_cpu(p);
	}

out_activate:
#endif
	if (old_state == TASK_UNINTERRUPTIBLE) {
		rq->nr_uninterruptible--;
		p->activated = -1;
	}

	activate_task(p, rq, cpu == this_cpu);
	if (!sync || cpu != this_cpu) {
		if (TASK_PREEMPTS_CURR(p, rq))
			resched_task(rq->curr);
	}
	success = 1;

out_running:
	p->state = TASK_RUNNING;
out:
	task_rq_unlock(rq, &flags);

	return success;
}

int fastcall wake_up_process(task_t * p)
{
	return try_to_wake_up(p, TASK_STOPPED | TASK_TRACED |
				 TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE, 0);
}

EXPORT_SYMBOL(wake_up_process);

int fastcall wake_up_state(task_t *p, unsigned int state)
{
	return try_to_wake_up(p, state, 0);
}

#ifdef CONFIG_SMP
static int find_idlest_cpu(struct task_struct *p, int this_cpu,
			   struct sched_domain *sd);
#endif

void fastcall sched_fork(task_t *p)
{
	p->state = TASK_RUNNING;
	INIT_LIST_HEAD(&p->run_list);
	p->array = NULL;
	spin_lock_init(&p->switch_lock);
#ifdef CONFIG_SCHEDSTATS
	memset(&p->sched_info, 0, sizeof(p->sched_info));
#endif
#ifdef CONFIG_PREEMPT
#error "CONFIG_PREEMPT"
#endif

	local_irq_disable();
	p->time_slice = (current->time_slice + 1) >> 1;

	p->first_time_slice = 1;
	current->time_slice >>= 1;
	p->timestamp = sched_clock();
	if (unlikely(!current->time_slice)) {
		current->time_slice = 1;
		preempt_disable();
		scheduler_tick();
		local_irq_enable();
		preempt_enable();
	} else
		local_irq_enable();
}

void fastcall wake_up_new_task(task_t * p, unsigned long clone_flags)
{
	unsigned long flags;
	int this_cpu, cpu;
	runqueue_t *rq, *this_rq;

	rq = task_rq_lock(p, &flags);
	cpu = task_cpu(p);
	this_cpu = smp_processor_id();

	BUG_ON(p->state != TASK_RUNNING);

	schedstat_inc(rq, wunt_cnt);

	p->sleep_avg = JIFFIES_TO_NS(CURRENT_BONUS(p) *
		CHILD_PENALTY / 100 * MAX_SLEEP_AVG / MAX_BONUS);

	p->prio = effective_prio(p);

	if (likely(cpu == this_cpu)) {
		if (!(clone_flags & CLONE_VM)) {
			if (unlikely(!current->array))
				__activate_task(p, rq);
			else {
				p->prio = current->prio;
				list_add_tail(&p->run_list, &current->run_list);
				p->array = current->array;
				p->array->nr_active++;
				rq->nr_running++;
			}
			set_need_resched();
		} else
			__activate_task(p, rq);
		this_rq = rq;
	} else {
		this_rq = cpu_rq(this_cpu);

		p->timestamp = (p->timestamp - this_rq->timestamp_last_tick)
					+ rq->timestamp_last_tick;
		__activate_task(p, rq);
		if (TASK_PREEMPTS_CURR(p, rq))
			resched_task(rq->curr);

		schedstat_inc(rq, wunt_moved);
		/*
		 * Parent and child are on different CPUs, now get the
		 * parent runqueue to update the parent's ->sleep_avg:
		 */
		task_rq_unlock(rq, &flags);
		this_rq = task_rq_lock(current, &flags);
	}
	current->sleep_avg = JIFFIES_TO_NS(CURRENT_BONUS(current) *
		PARENT_PENALTY / 100 * MAX_SLEEP_AVG / MAX_BONUS);
	task_rq_unlock(this_rq, &flags);
}

void fastcall sched_exit(task_t * p)
{
	unsigned long flags;
	runqueue_t *rq;

	/*
	 * If the child was a (relative-) CPU hog then decrease
	 * the sleep_avg of the parent as well.
	 */
	rq = task_rq_lock(p->parent, &flags);
	if (p->first_time_slice) {
		p->parent->time_slice += p->time_slice;
		if (unlikely(p->parent->time_slice > task_timeslice(p)))
			p->parent->time_slice = task_timeslice(p);
	}
	if (p->sleep_avg < p->parent->sleep_avg)
		p->parent->sleep_avg = p->parent->sleep_avg /
		(EXIT_WEIGHT + 1) * EXIT_WEIGHT + p->sleep_avg /
		(EXIT_WEIGHT + 1);
	task_rq_unlock(rq, &flags);
}

static void finish_task_switch(task_t *prev)
	__releases(rq->lock)
{
	runqueue_t *rq = this_rq();
	struct mm_struct *mm = rq->prev_mm;
	unsigned long prev_task_flags;

	rq->prev_mm = NULL;
	
	prev_task_flags = prev->flags;
	finish_arch_switch(rq, prev);
	if (mm)
		mmdrop(mm);
	if (unlikely(prev_task_flags & PF_DEAD))
		put_task_struct(prev);
}

/**
 * schedule_tail - first thing a freshly forked thread must call.
 * @prev: the thread we just switched away from.
 */
asmlinkage void schedule_tail(task_t *prev)
	__releases(rq->lock)
{
	finish_task_switch(prev);

	if (current->set_child_tid)
		put_user(current->pid, current->set_child_tid);
}

static inline
task_t * context_switch(runqueue_t *rq, task_t *prev, task_t *next)
{
	struct mm_struct *mm = next->mm;
	struct mm_struct *oldmm = prev->active_mm;

	if (unlikely(!mm)) {
		next->active_mm = oldmm;
		atomic_inc(&oldmm->mm_count);
		enter_lazy_tlb(oldmm, next);
	} else
		switch_mm(oldmm, mm, next);

	if (unlikely(!prev->mm)) {
		prev->active_mm = NULL;
		WARN_ON(rq->prev_mm);
		rq->prev_mm = oldmm;
	}

	/* Here we just switch the register state and the stack. */
	switch_to(prev, next, prev);

	return prev;
}

unsigned long nr_running(void)
{
	unsigned long i, sum = 0;

	for_each_online_cpu(i)
		sum += cpu_rq(i)->nr_running;

	return sum;
}

unsigned long nr_uninterruptible(void)
{
	unsigned long i, sum = 0;

	for_each_cpu(i)
		sum += cpu_rq(i)->nr_uninterruptible;

	/*
	 * Since we read the counters lockless, it might be slightly
	 * inaccurate. Do not allow it to go below zero though:
	 */
	if (unlikely((long)sum < 0))
		sum = 0;

	return sum;
}








#ifdef CONFIG_SMP	//p 1450

static void double_rq_lock(runqueue_t *rq1, runqueue_t *rq2)
	__acquires(rq1->lock)
	__acquires(rq2->lock)
{
	if (rq1 == rq2) {
		spin_lock(&rq1->lock);
		__acquire(rq2->lock);	/* Fake it out ;) */
	} else {
		if (rq1 < rq2) {
			spin_lock(&rq1->lock);
			spin_lock(&rq2->lock);
		} else {
			spin_lock(&rq2->lock);
			spin_lock(&rq1->lock);
		}
	}
}

static void double_rq_unlock(runqueue_t *rq1, runqueue_t *rq2)
	__releases(rq1->lock)
	__releases(rq2->lock)
{
	spin_unlock(&rq1->lock);
	if (rq1 != rq2)
		spin_unlock(&rq2->lock);
	else
		__release(rq2->lock);
}

static void double_lock_balance(runqueue_t *this_rq, runqueue_t *busiest)
	__releases(this_rq->lock)
	__acquires(busiest->lock)
	__acquires(this_rq->lock)
{
	if (unlikely(!spin_trylock(&busiest->lock))) {
		if (busiest < this_rq) {
			spin_unlock(&this_rq->lock);
			spin_lock(&busiest->lock);
			spin_lock(&this_rq->lock);
		} else
			spin_lock(&busiest->lock);
	}
}

static int move_tasks(runqueue_t *this_rq, int this_cpu, runqueue_t *busiest,
		      unsigned long max_nr_move, struct sched_domain *sd,
		      enum idle_type idle)
{
	panic("in move_tasks function");
	return 0;
}

static struct sched_group *
find_busiest_group(struct sched_domain *sd, int this_cpu,
		   unsigned long *imbalance, enum idle_type idle)
{
	struct sched_group *busiest = NULL, *this = NULL, *group = sd->groups;
	unsigned long max_load, avg_load, total_load, this_load, total_pwr;

	max_load = this_load = total_load = total_pwr = 0;

	do {
		unsigned long load;
		int local_group;
		int i, nr_cpus = 0;

		local_group = cpu_isset(this_cpu, group->cpumask);

		/* Tally up the load of all CPUs in the group */
		avg_load = 0;

		for_each_cpu_mask(i, group->cpumask) {
			/* Bias balancing toward cpus of our domain */
			if (local_group)
				load = target_load(i);
			else
				load = source_load(i);

			nr_cpus++;
			avg_load += load;
		}

		if (!nr_cpus)
			goto nextgroup;

		total_load += avg_load;
		total_pwr += group->cpu_power;

		/* Adjust by relative CPU power of the group */
		avg_load = (avg_load * SCHED_LOAD_SCALE) / group->cpu_power;

		if (local_group) {
			this_load = avg_load;
			this = group;
			goto nextgroup;
		} else if (avg_load > max_load) {
			max_load = avg_load;
			busiest = group;
		}
nextgroup:
		group = group->next;
	} while (group != sd->groups);

	if (!busiest || this_load >= max_load)
		goto out_balanced;

	avg_load = (SCHED_LOAD_SCALE * total_load) / total_pwr;

	if (this_load >= avg_load ||
			100*max_load <= sd->imbalance_pct*this_load)
		goto out_balanced;

	/*
	 * We're trying to get all the cpus to the average_load, so we don't
	 * want to push ourselves above the average load, nor do we wish to
	 * reduce the max loaded cpu below the average load, as either of these
	 * actions would just result in more rebalancing later, and ping-pong
	 * tasks around. Thus we look for the minimum possible imbalance.
	 * Negative imbalances (*we* are more loaded than anyone else) will
	 * be counted as no imbalance for these purposes -- we can't fix that
	 * by pulling tasks to us.  Be careful of negative numbers as they'll
	 * appear as very large values with unsigned longs.
	 */
	*imbalance = min(max_load - avg_load, avg_load - this_load);

	/* How much load to actually move to equalise the imbalance */
	*imbalance = (*imbalance * min(busiest->cpu_power, this->cpu_power))
				/ SCHED_LOAD_SCALE;

	if (*imbalance < SCHED_LOAD_SCALE - 1) {
		unsigned long pwr_now = 0, pwr_move = 0;
		unsigned long tmp;

		if (max_load - this_load >= SCHED_LOAD_SCALE*2) {
			*imbalance = 1;
			return busiest;
		}

		/*
		 * OK, we don't have enough imbalance to justify moving tasks,
		 * however we may be able to increase total CPU power used by
		 * moving them.
		 */

		pwr_now += busiest->cpu_power*min(SCHED_LOAD_SCALE, max_load);
		pwr_now += this->cpu_power*min(SCHED_LOAD_SCALE, this_load);
		pwr_now /= SCHED_LOAD_SCALE;

		/* Amount of load we'd subtract */
		tmp = SCHED_LOAD_SCALE*SCHED_LOAD_SCALE/busiest->cpu_power;
		if (max_load > tmp)
			pwr_move += busiest->cpu_power*min(SCHED_LOAD_SCALE,
							max_load - tmp);

		/* Amount of load we'd add */
		tmp = SCHED_LOAD_SCALE*SCHED_LOAD_SCALE/this->cpu_power;
		if (max_load < tmp)
			tmp = max_load;
		pwr_move += this->cpu_power*min(SCHED_LOAD_SCALE, this_load + tmp);
		pwr_move /= SCHED_LOAD_SCALE;

		/* Move if we gain another 8th of a CPU worth of throughput */
		if (pwr_move < pwr_now + SCHED_LOAD_SCALE / 8)
			goto out_balanced;

		*imbalance = 1;
		return busiest;
	}

	/* Get rid of the scaling factor, rounding down as we divide */
	*imbalance = (*imbalance + 1) / SCHED_LOAD_SCALE;

	return busiest;

out_balanced:
	if (busiest && (idle == NEWLY_IDLE ||
			(idle == SCHED_IDLE && max_load > SCHED_LOAD_SCALE)) ) {
		*imbalance = 1;
		return busiest;
	}

	*imbalance = 0;
	return NULL;
}

static runqueue_t *find_busiest_queue(struct sched_group *group)
{
	unsigned long load, max_load = 0;
	runqueue_t *busiest = NULL;
	int i;

	for_each_cpu_mask(i, group->cpumask) {
		load = source_load(i);

		if (load > max_load) {
			max_load = load;
			busiest = cpu_rq(i);
		}
	}

	return busiest;
}

static int load_balance(int this_cpu, runqueue_t *this_rq,
			struct sched_domain *sd, enum idle_type idle)
{
	struct sched_group *group;
	runqueue_t *busiest;
	unsigned long imbalance;
	int nr_moved;

	spin_lock(&this_rq->lock);
	schedstat_inc(sd, lb_cnt[idle]);

	group = find_busiest_group(sd, this_cpu, &imbalance, idle);
	if (!group) {
		schedstat_inc(sd, lb_nobusyg[idle]);
		goto out_balanced;
	}

	busiest = find_busiest_queue(group);
	if (!busiest) {
		schedstat_inc(sd, lb_nobusyq[idle]);
		goto out_balanced;
	}

	if (unlikely(busiest == this_rq)) {
		WARN_ON(1);
		goto out_balanced;
	}

	schedstat_add(sd, lb_imbalance[idle], imbalance);

	nr_moved = 0;
	if (busiest->nr_running > 1) {
		/*
		 * Attempt to move tasks. If find_busiest_group has found
		 * an imbalance but busiest->nr_running <= 1, the group is
		 * still unbalanced. nr_moved simply stays zero, so it is
		 * correctly treated as an imbalance.
		 */
		double_lock_balance(this_rq, busiest);
		nr_moved = move_tasks(this_rq, this_cpu, busiest,
						imbalance, sd, idle);
		spin_unlock(&busiest->lock);
	}
	spin_unlock(&this_rq->lock);

	if (!nr_moved) {
		schedstat_inc(sd, lb_failed[idle]);
		sd->nr_balance_failed++;

		if (unlikely(sd->nr_balance_failed > sd->cache_nice_tries+2)) {
			int wake = 0;

			spin_lock(&busiest->lock);
			if (!busiest->active_balance) {
				busiest->active_balance = 1;
				busiest->push_cpu = this_cpu;
				wake = 1;
			}
			spin_unlock(&busiest->lock);
			if (wake)
				wake_up_process(busiest->migration_thread);

			/*
			 * We've kicked active balancing, reset the failure
			 * counter.
			 */
			sd->nr_balance_failed = sd->cache_nice_tries;
		}

		/*
		 * We were unbalanced, but unsuccessful in move_tasks(),
		 * so bump the balance_interval to lessen the lock contention.
		 */
		if (sd->balance_interval < sd->max_interval)
			sd->balance_interval++;
	} else {
		sd->nr_balance_failed = 0;

		/* We were unbalanced, so reset the balancing interval */
		sd->balance_interval = sd->min_interval;
	}

	return nr_moved;

out_balanced:
	spin_unlock(&this_rq->lock);

	/* tune up the balancing interval */
	if (sd->balance_interval < sd->max_interval)
		sd->balance_interval *= 2;

	return 0;
}

static int load_balance_newidle(int this_cpu, runqueue_t *this_rq,
				struct sched_domain *sd)
{
	struct sched_group *group;
	runqueue_t *busiest = NULL;
	unsigned long imbalance;
	int nr_moved = 0;

	schedstat_inc(sd, lb_cnt[NEWLY_IDLE]);
	group = find_busiest_group(sd, this_cpu, &imbalance, NEWLY_IDLE);
	if (!group) {
		schedstat_inc(sd, lb_nobusyg[NEWLY_IDLE]);
		goto out;
	}

	busiest = find_busiest_queue(group);
	if (!busiest || busiest == this_rq) {
		schedstat_inc(sd, lb_nobusyq[NEWLY_IDLE]);
		goto out;
	}

	/* Attempt to move tasks */
	double_lock_balance(this_rq, busiest);

	schedstat_add(sd, lb_imbalance[NEWLY_IDLE], imbalance);
	nr_moved = move_tasks(this_rq, this_cpu, busiest,
					imbalance, sd, NEWLY_IDLE);
	if (!nr_moved)
		schedstat_inc(sd, lb_failed[NEWLY_IDLE]);

	spin_unlock(&busiest->lock);

out:
	return nr_moved;
}

/*
 * idle_balance is called by schedule() if this_cpu is about to become
 * idle. Attempts to pull tasks from other CPUs.
 */
static inline void idle_balance(int this_cpu, runqueue_t *this_rq)
{
	struct sched_domain *sd;

	for_each_domain(this_cpu, sd) {
		if (sd->flags & SD_BALANCE_NEWIDLE) {
			if (load_balance_newidle(this_cpu, this_rq, sd)) {
				/* We've pulled tasks over so stop searching */
				break;
			}
		}
	}
}

static void active_load_balance(runqueue_t *busiest_rq, int busiest_cpu)
{
	struct sched_domain *sd;
	struct sched_group *cpu_group;
	runqueue_t *target_rq;
	cpumask_t visited_cpus;
	int cpu;

	schedstat_inc(busiest_rq, alb_cnt);

	visited_cpus = CPU_MASK_NONE;
	for_each_domain(busiest_cpu, sd) {
		if (!(sd->flags & SD_LOAD_BALANCE))
			break;

		cpu_group = sd->groups;
		do {
			for_each_cpu_mask(cpu, cpu_group->cpumask) {
				if (busiest_rq->nr_running <= 1)
					/* no more tasks left to move */
					return;
				if (cpu_isset(cpu, visited_cpus))
					continue;
				cpu_set(cpu, visited_cpus);
				if (!cpu_and_siblings_are_idle(cpu) || cpu == busiest_cpu)
					continue;

				target_rq = cpu_rq(cpu);
				/*
				 * This condition is "impossible", if it occurs
				 * we need to fix it.  Originally reported by
				 * Bjorn Helgaas on a 128-cpu setup.
				 */
				BUG_ON(busiest_rq == target_rq);

				/* move a task from busiest_rq to target_rq */
				double_lock_balance(busiest_rq, target_rq);
				if (move_tasks(target_rq, cpu, busiest_rq,
						1, sd, SCHED_IDLE)) {
					schedstat_inc(busiest_rq, alb_lost);
					schedstat_inc(target_rq, alb_gained);
				} else {
					schedstat_inc(busiest_rq, alb_failed);
				}
				spin_unlock(&target_rq->lock);
			}
			cpu_group = cpu_group->next;
		} while (cpu_group != sd->groups);
	}
}

#define CPU_OFFSET(cpu) (HZ * cpu / NR_CPUS)

static void rebalance_tick(int this_cpu, runqueue_t *this_rq,
			   enum idle_type idle)
{
	unsigned long old_load, this_load;
	unsigned long j = jiffies + CPU_OFFSET(this_cpu);
	struct sched_domain *sd;

	old_load = this_rq->cpu_load;
	this_load = this_rq->nr_running * SCHED_LOAD_SCALE;

	if (this_load > old_load)
		old_load++;
	this_rq->cpu_load = (old_load + this_load) / 2;

	for_each_domain(this_cpu, sd) {
		unsigned long interval;

		if (!(sd->flags & SD_LOAD_BALANCE))
			continue;

		interval = sd->balance_interval;
		if (idle != SCHED_IDLE)
			interval *= sd->busy_factor;

		interval = msecs_to_jiffies(interval);
		if (unlikely(!interval))
			interval = 1;

		if (j - sd->last_balance >= interval) {
			if (load_balance(this_cpu, this_rq, sd, idle)) {
				idle = NOT_IDLE;
			}
			sd->last_balance += interval;
		}
	}
}

#else
#error "CONFIG_SMP"
#endif

static inline int wake_priority_sleeper(runqueue_t *rq)
{
	int ret = 0;
#ifdef CONFIG_SCHED_SMT
	spin_lock(&rq->lock);
	if (rq->nr_running) {
		resched_task(rq->idle);
		ret = 1;
	}
	spin_unlock(&rq->lock);
#endif
	return ret;
}

DEFINE_PER_CPU(struct kernel_stat, kstat);

EXPORT_PER_CPU_SYMBOL(kstat);

#define EXPIRED_STARVING(rq) \
	((STARVATION_LIMIT && ((rq)->expired_timestamp && \
		(jiffies - (rq)->expired_timestamp >= \
			STARVATION_LIMIT * ((rq)->nr_running) + 1))) || \
			((rq)->curr->static_prio > (rq)->best_expired_prio))

static inline void account_it_virt(struct task_struct * p, cputime_t cputime)
{
	cputime_t it_virt = p->it_virt_value;

	if (cputime_gt(it_virt, cputime_zero) &&
	    cputime_gt(cputime, cputime_zero)) {
		if (cputime_ge(cputime, it_virt)) {
			it_virt = cputime_add(it_virt, p->it_virt_incr);
			send_sig(SIGVTALRM, p, 1);
		}
		it_virt = cputime_sub(it_virt, cputime);
		p->it_virt_value = it_virt;
	}
}

static void account_it_prof(struct task_struct *p, cputime_t cputime)
{
	cputime_t it_prof = p->it_prof_value;

	if (cputime_gt(it_prof, cputime_zero) &&
	    cputime_gt(cputime, cputime_zero)) {
		if (cputime_ge(cputime, it_prof)) {
			it_prof = cputime_add(it_prof, p->it_prof_incr);
			send_sig(SIGPROF, p, 1);
		}
		it_prof = cputime_sub(it_prof, cputime);
		p->it_prof_value = it_prof;
	}
}

static void check_rlimit(struct task_struct *p, cputime_t cputime)
{
	cputime_t total, tmp;
	unsigned long secs;

	total = cputime_add(p->utime, p->stime);
	secs = cputime_to_secs(total);
	if (unlikely(secs >= p->signal->rlim[RLIMIT_CPU].rlim_cur)) {
		/* Send SIGXCPU every second. */
		tmp = cputime_sub(total, cputime);
		if (cputime_to_secs(tmp) < secs)
			send_sig(SIGXCPU, p, 1);
		/* and SIGKILL when we go over max.. */
		if (secs >= p->signal->rlim[RLIMIT_CPU].rlim_max)
			send_sig(SIGKILL, p, 1);
	}
}
void account_user_time(struct task_struct *p, cputime_t cputime)
{
	struct cpu_usage_stat *cpustat = &kstat_this_cpu.cpustat;
	cputime64_t tmp;

	p->utime = cputime_add(p->utime, cputime);

	/* Check for signals (SIGVTALRM, SIGPROF, SIGXCPU & SIGKILL). */
	check_rlimit(p, cputime);
	account_it_virt(p, cputime);
	account_it_prof(p, cputime);

	/* Add user time to cpustat. */
	tmp = cputime_to_cputime64(cputime);
	if (TASK_NICE(p) > 0)
		cpustat->nice = cputime64_add(cpustat->nice, tmp);
	else
		cpustat->user = cputime64_add(cpustat->user, tmp);
}

void account_system_time(struct task_struct *p, int hardirq_offset,
			 cputime_t cputime)
{
	struct cpu_usage_stat *cpustat = &kstat_this_cpu.cpustat;
	runqueue_t *rq = this_rq();
	cputime64_t tmp;

	p->stime = cputime_add(p->stime, cputime);

	/* Check for signals (SIGPROF, SIGXCPU & SIGKILL). */
	if (likely(p->signal && p->exit_state < EXIT_ZOMBIE)) {
		check_rlimit(p, cputime);
		account_it_prof(p, cputime);
	}

	/* Add system time to cpustat. */
	tmp = cputime_to_cputime64(cputime);
	if (hardirq_count() - hardirq_offset)
		cpustat->irq = cputime64_add(cpustat->irq, tmp);
	else if (softirq_count())
		cpustat->softirq = cputime64_add(cpustat->softirq, tmp);
	else if (p != rq->idle)
		cpustat->system = cputime64_add(cpustat->system, tmp);
	else if (atomic_read(&rq->nr_iowait) > 0)
		cpustat->iowait = cputime64_add(cpustat->iowait, tmp);
	else
		cpustat->idle = cputime64_add(cpustat->idle, tmp);
}

void account_steal_time(struct task_struct *p, cputime_t steal)
{
	struct cpu_usage_stat *cpustat = &kstat_this_cpu.cpustat;
	cputime64_t tmp = cputime_to_cputime64(steal);
	runqueue_t *rq = this_rq();

	if (p == rq->idle) {
		p->stime = cputime_add(p->stime, steal);
		if (atomic_read(&rq->nr_iowait) > 0)
			cpustat->iowait = cputime64_add(cpustat->iowait, tmp);
		else
			cpustat->idle = cputime64_add(cpustat->idle, tmp);
	} else
		cpustat->steal = cputime64_add(cpustat->steal, tmp);
}

void scheduler_tick(void)
{
	int cpu = smp_processor_id();
	runqueue_t *rq = this_rq();
	task_t *p = current;

	rq->timestamp_last_tick = sched_clock();

	if (p == rq->idle) {
		if (wake_priority_sleeper(rq))
			goto out;
		rebalance_tick(cpu, rq, SCHED_IDLE);
		return;
	}
	
	if (p->array != rq->active) {
		set_tsk_need_resched(p);
		goto out;
	}
	spin_lock(&rq->lock);

	if (rt_task(p)) {
		if ((p->policy == SCHED_RR) && !--p->time_slice) {
			p->time_slice = task_timeslice(p);
			p->first_time_slice = 0;
			set_tsk_need_resched(p);

			/* put it at the end of the queue: */
			requeue_task(p, rq->active);
		}
		goto out_unlock;
	}
	if (!--p->time_slice) {
		dequeue_task(p, rq->active);
		set_tsk_need_resched(p);
		p->prio = effective_prio(p);
		p->time_slice = task_timeslice(p);
		p->first_time_slice = 0;

		if (!rq->expired_timestamp)
			rq->expired_timestamp = jiffies;
		if (!TASK_INTERACTIVE(p) || EXPIRED_STARVING(rq)) {
			enqueue_task(p, rq->expired);
			if (p->static_prio < rq->best_expired_prio)
				rq->best_expired_prio = p->static_prio;
		} else
			enqueue_task(p, rq->active);
	} else {
		if (TASK_INTERACTIVE(p) && !((task_timeslice(p) -
			p->time_slice) % TIMESLICE_GRANULARITY(p)) &&
			(p->time_slice >= TIMESLICE_GRANULARITY(p)) &&
			(p->array == rq->active)) {

			requeue_task(p, rq->active);
			set_tsk_need_resched(p);
		}
	}
out_unlock:
	spin_unlock(&rq->lock);
out:
	rebalance_tick(cpu, rq, NOT_IDLE);
}

#ifdef CONFIG_SCHED_SMT
static inline void wake_sleeping_dependent(int this_cpu, runqueue_t *this_rq)
{
	struct sched_domain *sd = this_rq->sd;
	cpumask_t sibling_map;
	int i;

	if (!(sd->flags & SD_SHARE_CPUPOWER))
		return;

	/*
	 * Unlock the current runqueue because we have to lock in
	 * CPU order to avoid deadlocks. Caller knows that we might
	 * unlock. We keep IRQs disabled.
	 */
	spin_unlock(&this_rq->lock);

	sibling_map = sd->span;

	for_each_cpu_mask(i, sibling_map)
		spin_lock(&cpu_rq(i)->lock);
	/*
	 * We clear this CPU from the mask. This both simplifies the
	 * inner loop and keps this_rq locked when we exit:
	 */
	cpu_clear(this_cpu, sibling_map);

	for_each_cpu_mask(i, sibling_map) {
		runqueue_t *smt_rq = cpu_rq(i);

		/*
		 * If an SMT sibling task is sleeping due to priority
		 * reasons wake it up now.
		 */
		if (smt_rq->curr == smt_rq->idle && smt_rq->nr_running)
			resched_task(smt_rq->idle);
	}

	for_each_cpu_mask(i, sibling_map)
		spin_unlock(&cpu_rq(i)->lock);
	/*
	 * We exit with this_cpu's rq still held and IRQs
	 * still disabled:
	 */
}

static inline int dependent_sleeper(int this_cpu, runqueue_t *this_rq)
{
	struct sched_domain *sd = this_rq->sd;
	cpumask_t sibling_map;
	prio_array_t *array;
	int ret = 0, i;
	task_t *p;

	if (!(sd->flags & SD_SHARE_CPUPOWER))
		return 0;

	/*
	 * The same locking rules and details apply as for
	 * wake_sleeping_dependent():
	 */
	spin_unlock(&this_rq->lock);
	sibling_map = sd->span;
	for_each_cpu_mask(i, sibling_map)
		spin_lock(&cpu_rq(i)->lock);
	cpu_clear(this_cpu, sibling_map);

	/*
	 * Establish next task to be run - it might have gone away because
	 * we released the runqueue lock above:
	 */
	if (!this_rq->nr_running)
		goto out_unlock;
	array = this_rq->active;
	if (!array->nr_active)
		array = this_rq->expired;
	BUG_ON(!array->nr_active);

	p = list_entry(array->queue[sched_find_first_bit(array->bitmap)].next,
		task_t, run_list);

	for_each_cpu_mask(i, sibling_map) {
		runqueue_t *smt_rq = cpu_rq(i);
		task_t *smt_curr = smt_rq->curr;

		/*
		 * If a user task with lower static priority than the
		 * running task on the SMT sibling is trying to schedule,
		 * delay it till there is proportionately less timeslice
		 * left of the sibling task to prevent a lower priority
		 * task from using an unfair proportion of the
		 * physical cpu's resources. -ck
		 */
		if (((smt_curr->time_slice * (100 - sd->per_cpu_gain) / 100) >
			task_timeslice(p) || rt_task(smt_curr)) &&
			p->mm && smt_curr->mm && !rt_task(p))
				ret = 1;

		/*
		 * Reschedule a lower priority task on the SMT sibling,
		 * or wake it up if it has been put to sleep for priority
		 * reasons.
		 */
		if ((((p->time_slice * (100 - sd->per_cpu_gain) / 100) >
			task_timeslice(smt_curr) || rt_task(p)) &&
			smt_curr->mm && p->mm && !rt_task(smt_curr)) ||
			(smt_curr == smt_rq->idle && smt_rq->nr_running))
				resched_task(smt_curr);
	}
out_unlock:
	for_each_cpu_mask(i, sibling_map)
		spin_unlock(&cpu_rq(i)->lock);
	return ret;
}
#else
#endif

asmlinkage void __sched schedule(void) {
	long *switch_count;
	task_t *prev, *next;
	runqueue_t *rq;
	prio_array_t *array;
	struct list_head *queue;
	unsigned long long now;
	unsigned long run_time;
	int cpu, idx;

	if (likely(!current->exit_state)) {
		if (unlikely(in_atomic())) {
			printk(KERN_ERR "scheduling while atomic: "
				"%s/0x%08x/%d\n",
				current->comm, preempt_count(), current->pid);
			dump_stack();
		}
	}
	profile_hit(SCHED_PROFILING, __builtin_return_address(0));

need_resched:
	preempt_disable();
	prev = current;
	release_kernel_lock(prev);
need_resched_nonpreemptible:
	rq = this_rq();

	if (unlikely(prev == rq->idle) && prev->state != TASK_RUNNING) {
		printk(KERN_ERR "bad: scheduling from the idle thread!\n");
		dump_stack();
	}

	schedstat_inc(rq, sched_cnt);
	now = sched_clock();
	if (likely(now - prev->timestamp < NS_MAX_SLEEP_AVG))
		run_time = now - prev->timestamp;
	else
		run_time = NS_MAX_SLEEP_AVG;

	run_time /= (CURRENT_BONUS(prev) ? : 1);

	spin_lock_irq(&rq->lock);

	if (unlikely(prev->flags & PF_DEAD))
		prev->state = EXIT_DEAD;

	switch_count = &prev->nivcsw;
	if (prev->state && !(preempt_count() & PREEMPT_ACTIVE)) {
		switch_count = &prev->nvcsw;
		if (unlikely((prev->state & TASK_INTERRUPTIBLE) &&
				unlikely(signal_pending(prev))))
			prev->state = TASK_RUNNING;
		else {
			if (prev->state == TASK_UNINTERRUPTIBLE)
				rq->nr_uninterruptible++;
			deactivate_task(prev, rq);
		}
	}
	cpu = smp_processor_id();
	if (unlikely(!rq->nr_running)) {
go_idle:
		idle_balance(cpu, rq);
		if (!rq->nr_running) {
			next = rq->idle;
			rq->expired_timestamp = 0;
			wake_sleeping_dependent(cpu, rq);
			/*
			 * wake_sleeping_dependent() might have released
			 * the runqueue, so break out if we got new
			 * tasks meanwhile:
			 */
			if (!rq->nr_running)
				goto switch_tasks;
		}
	} else {
		if (dependent_sleeper(cpu, rq)) {
			next = rq->idle;
			goto switch_tasks;
		}
		/*
		 * dependent_sleeper() releases and reacquires the runqueue
		 * lock, hence go into the idle loop if the rq went
		 * empty meanwhile:
		 */
		if (unlikely(!rq->nr_running))
			goto go_idle;
	}

	array = rq->active;
	if (unlikely(!array->nr_active)) {
		/*
		 * Switch the active and expired arrays.
		 */
		schedstat_inc(rq, sched_switch);
		rq->active = rq->expired;
		rq->expired = array;
		array = rq->active;
		rq->expired_timestamp = 0;
		rq->best_expired_prio = MAX_PRIO;
	} else
		schedstat_inc(rq, sched_noswitch);

	idx = sched_find_first_bit(array->bitmap);
	queue = array->queue + idx;
	next = list_entry(queue->next, task_t, run_list);

	if (!rt_task(next) && next->activated > 0) {
		unsigned long long delta = now - next->timestamp;

		if (next->activated == 1)
			delta = delta * (ON_RUNQUEUE_WEIGHT * 128 / 100) / 128;

		array = next->array;
		dequeue_task(next, array);
		recalc_task_prio(next, next->timestamp + delta);
		enqueue_task(next, array);
	}
	next->activated = 0;
switch_tasks:
	if (next == rq->idle)
		schedstat_inc(rq, sched_goidle);
	prefetch(next);
	clear_tsk_need_resched(prev);
	rcu_qsctr_inc(task_cpu(prev));

	prev->sleep_avg -= run_time;
	if ((long)prev->sleep_avg <= 0)
		prev->sleep_avg = 0;
	prev->timestamp = prev->last_ran = now;

	sched_info_switch(prev, next);
	if (likely(prev != next)) {
		next->timestamp = now;
		rq->nr_switches++;
		rq->curr = next;
		++*switch_count;

		prepare_arch_switch(rq, next);
		prev = context_switch(rq, prev, next);
		barrier();

		finish_task_switch(prev);
	} else
		spin_unlock_irq(&rq->lock);

	prev = current;
	if (unlikely(reacquire_kernel_lock(prev) < 0))
		goto need_resched_nonpreemptible;
	preempt_enable_no_resched();
	if (unlikely(test_thread_flag(TIF_NEED_RESCHED)))
		goto need_resched;
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

void fastcall __wake_up_sync(wait_queue_head_t *q, unsigned int mode, int nr_exclusive)
{
	unsigned long flags;
	int sync = 1;

	if (unlikely(!q))
		return;

	if (unlikely(!nr_exclusive))
		sync = 0;

	spin_lock_irqsave(&q->lock, flags);
	__wake_up_common(q, mode, nr_exclusive, sync, NULL);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL_GPL(__wake_up_sync);	/* For internal use only */

void fastcall complete(struct completion *x)
{
	unsigned long flags;

	spin_lock_irqsave(&x->wait.lock, flags);
	x->done++;
	__wake_up_common(&x->wait, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE,
			 1, 0, NULL);
	spin_unlock_irqrestore(&x->wait.lock, flags);
}
EXPORT_SYMBOL(complete);

void fastcall __sched wait_for_completion(struct completion *x)
{
	might_sleep();
	spin_lock_irq(&x->wait.lock);
	if (!x->done) {
		DECLARE_WAITQUEUE(wait, current);

		wait.flags |= WQ_FLAG_EXCLUSIVE;
		__add_wait_queue_tail(&x->wait, &wait);
		do {
			__set_current_state(TASK_UNINTERRUPTIBLE);
			spin_unlock_irq(&x->wait.lock);
			schedule();
			spin_lock_irq(&x->wait.lock);
		} while (!x->done);
		__remove_wait_queue(&x->wait, &wait);
	}
	x->done--;
	spin_unlock_irq(&x->wait.lock);
}
EXPORT_SYMBOL(wait_for_completion);

void fastcall __sched interruptible_sleep_on(wait_queue_head_t *q)
{
}

EXPORT_SYMBOL(interruptible_sleep_on);

long fastcall __sched interruptible_sleep_on_timeout(wait_queue_head_t *q, long timeout)
{
	return 0;
}

EXPORT_SYMBOL(interruptible_sleep_on_timeout);

void fastcall __sched sleep_on(wait_queue_head_t *q)
{
}

EXPORT_SYMBOL(sleep_on);

long fastcall __sched sleep_on_timeout(wait_queue_head_t *q, long timeout)
{
	return 0;
}

EXPORT_SYMBOL(sleep_on_timeout);

void set_user_nice(task_t *p, long nice)
{
	unsigned long flags;
	prio_array_t *array;
	runqueue_t *rq;
	int old_prio, new_prio, delta;

	if (TASK_NICE(p) == nice || nice < -20 || nice > 19)
		return;

	rq = task_rq_lock(p, &flags);

	if (rt_task(p)) {
		p->static_prio = NICE_TO_PRIO(nice);
		goto out_unlock;
	}

	array = p->array;
	if (array)
		dequeue_task(p, array);

	old_prio = p->prio;
	new_prio = NICE_TO_PRIO(nice);
	delta = new_prio - old_prio;
	p->static_prio = NICE_TO_PRIO(nice);
	p->prio += delta;

	if (array) {
		enqueue_task(p, array);
		if (delta < 0 || (delta > 0 && task_running(rq, p)))
			resched_task(rq->curr);
	}
out_unlock:
	task_rq_unlock(rq, &flags);
}

EXPORT_SYMBOL(set_user_nice);

#ifdef __ARCH_WANT_SYS_NICE

asmlinkage long sys_nice(int increment)
{
	return 0;
}

#endif

int task_prio(const task_t *p)
{
	return p->prio - MAX_RT_PRIO;
}

int task_nice(const task_t *p)
{
	return TASK_NICE(p);
}

int idle_cpu(int cpu)
{
	return cpu_curr(cpu) == cpu_rq(cpu)->idle;
}

EXPORT_SYMBOL_GPL(idle_cpu);

task_t *idle_task(int cpu)
{
	return cpu_rq(cpu)->idle;
}

static void __setscheduler(struct task_struct *p, int policy, int prio)
{
	BUG_ON(p->array);
	p->policy = policy;
	p->rt_priority = prio;
	if (policy != SCHED_NORMAL)
		p->prio = MAX_USER_RT_PRIO - 1 - p->rt_priority;
	else
		p->prio = p->static_prio;
}

/*
 * Represents all cpu's present in the system
 * In systems capable of hotplug, this map could dynamically grow
 * as new cpu's are detected in the system via any platform specific
 * method, such as ACPI for e.g.
 */

cpumask_t cpu_present_map;
EXPORT_SYMBOL(cpu_present_map);

asmlinkage long sys_sched_yield(void)
{
	runqueue_t *rq = this_rq_lock();
	prio_array_t *array = current->array;
	prio_array_t *target = rq->expired;

	schedstat_inc(rq, yld_cnt);

	if (rt_task(current))
		target = rq->active;

	if (current->array->nr_active == 1) {
		schedstat_inc(rq, yld_act_empty);
		if (!rq->expired->nr_active)
			schedstat_inc(rq, yld_both_empty);
	} else if (!rq->expired->nr_active)
		schedstat_inc(rq, yld_exp_empty);

	if (array != target) {
		dequeue_task(current, array);
		enqueue_task(current, target);
	} else
		requeue_task(current, array);

	/*
	 * Since we are going to call schedule() anyway, there's
	 * no need to preempt or enable interrupts:
	 */
	__release(rq->lock);
	_raw_spin_unlock(&rq->lock);
	preempt_enable_no_resched();

	schedule();

	return 0;
}

static inline void __cond_resched(void)
{
	do {
		add_preempt_count(PREEMPT_ACTIVE);
		schedule();
		sub_preempt_count(PREEMPT_ACTIVE);
	} while (need_resched());
}

int __sched cond_resched(void)
{
	if (need_resched()) {
		__cond_resched();
		return 1;
	}
	return 0;
}

EXPORT_SYMBOL(cond_resched);

int cond_resched_lock(spinlock_t * lock)
{
#if defined(CONFIG_SMP) && defined(CONFIG_PREEMPT)
	if (lock->break_lock) {
		lock->break_lock = 0;
		spin_unlock(lock);
		cpu_relax();
		spin_lock(lock);
	}
#endif
	if (need_resched()) {
		_raw_spin_unlock(lock);
		preempt_enable_no_resched();
		__cond_resched();
		spin_lock(lock);
		return 1;
	}
	return 0;
}

EXPORT_SYMBOL(cond_resched_lock);


void __sched yield(void)
{
	set_current_state(TASK_RUNNING);
	sys_sched_yield();
}

EXPORT_SYMBOL(yield);

void __sched io_schedule(void)
{
	struct runqueue *rq = &per_cpu(runqueues, _smp_processor_id());

	atomic_inc(&rq->nr_iowait);
	schedule();
	atomic_dec(&rq->nr_iowait);
}

EXPORT_SYMBOL(io_schedule);

void __devinit init_idle(task_t *idle, int cpu) {
	runqueue_t *rq = cpu_rq(cpu);
	unsigned long flags;

	idle->sleep_avg = 0;
	idle->array = NULL;
	idle->prio = MAX_PRIO;
	idle->state = TASK_RUNNING;
	set_task_cpu(idle, cpu);

	spin_lock_irqsave(&rq->lock, flags);
	rq->curr = rq->idle = idle;
	set_tsk_need_resched(idle);
	spin_unlock_irqrestore(&rq->lock, flags);

#if defined(CONFIG_PREEMPT) && !defined(CONFIG_PREEMPT_BKL)
#error "CONFIG_PREEMPT"
#else
	idle->thread_info->preempt_count = 0;
#endif
}

/*
 * In a system that switches off the HZ timer nohz_cpu_mask
 * indicates which cpus entered this state. This is used
 * in the rcu update to wait only for active cpus. For system
 * which do not switch off the HZ timer nohz_cpu_mask should
 * always be CPU_MASK_NONE.
 */
cpumask_t nohz_cpu_mask = CPU_MASK_NONE;

#ifdef CONFIG_SMP

int set_cpus_allowed(task_t *p, cpumask_t new_mask)
{
	unsigned long flags;
	int ret = 0;
	migration_req_t req;
	runqueue_t *rq;

	rq = task_rq_lock(p, &flags);
	if (!cpus_intersects(new_mask, cpu_online_map)) {
		ret = -EINVAL;
		goto out;
	}

	p->cpus_allowed = new_mask;
	/* Can the task run on the task's current CPU? If so, we're done */
	if (cpu_isset(task_cpu(p), new_mask))
		goto out;

	if (migrate_task(p, any_online_cpu(new_mask), &req)) {
		/* Need help from migration thread: drop lock and wait. */
		task_rq_unlock(rq, &flags);
		wake_up_process(rq->migration_thread);
		wait_for_completion(&req.done);
		tlb_migrate_finish(p->mm);
		return 0;
	}
out:
	task_rq_unlock(rq, &flags);
	return ret;
}

EXPORT_SYMBOL_GPL(set_cpus_allowed);

static void __migrate_task(struct task_struct *p, int src_cpu, int dest_cpu)
{
	runqueue_t *rq_dest, *rq_src;

	if (unlikely(cpu_is_offline(dest_cpu)))
		return;

	rq_src = cpu_rq(src_cpu);
	rq_dest = cpu_rq(dest_cpu);

	double_rq_lock(rq_src, rq_dest);
	/* Already moved. */
	if (task_cpu(p) != src_cpu)
		goto out;
	/* Affinity changed (again). */
	if (!cpu_isset(dest_cpu, p->cpus_allowed))
		goto out;

	set_task_cpu(p, dest_cpu);
	if (p->array) {
		/*
		 * Sync timestamp with rq_dest's before activating.
		 * The same thing could be achieved by doing this step
		 * afterwards, and pretending it was a local activate.
		 * This way is cleaner and logically correct.
		 */
		p->timestamp = p->timestamp - rq_src->timestamp_last_tick
				+ rq_dest->timestamp_last_tick;
		deactivate_task(p, rq_src);
		activate_task(p, rq_dest, 0);
		if (TASK_PREEMPTS_CURR(p, rq_dest))
			resched_task(rq_dest->curr);
	}

out:
	double_rq_unlock(rq_src, rq_dest);
}

/*
 * migration_thread - this is a highprio system thread that performs
 * thread migration by bumping thread off CPU then 'pushing' onto
 * another runqueue.
 */
static int migration_thread(void * data)
{
	runqueue_t *rq;
	int cpu = (long) data;

	rq = cpu_rq(cpu);
	BUG_ON(rq->migration_thread != current);

	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		struct list_head *head;
		migration_req_t *req;

		if (current->flags & PF_FREEZE)	
			refrigerator(PF_FREEZE);

		spin_lock_irq(&rq->lock);

		if (cpu_is_offline(cpu)) {
			spin_unlock_irq(&rq->lock);
			goto wait_to_die;
		}

		if (rq->active_balance) {
			active_load_balance(rq, cpu);
			rq->active_balance = 0;
		}

		head = &rq->migration_queue;

		if (list_empty(head)) {
			spin_unlock_irq(&rq->lock);
			schedule();
			set_current_state(TASK_INTERRUPTIBLE);
			continue;
		}
		req = list_entry(head->next, migration_req_t, list);
		list_del_init(head->next);

		if (req->type == REQ_MOVE_TASK) {
			spin_unlock(&rq->lock);
			__migrate_task(req->task, cpu, req->dest_cpu);
			local_irq_enable();
		} else if (req->type == REQ_SET_DOMAIN) {
			rq->sd = req->sd;
			spin_unlock_irq(&rq->lock);
		} else {
			spin_unlock_irq(&rq->lock);
			WARN_ON(1);
		}

		complete(&req->done);
	}
	__set_current_state(TASK_RUNNING);
	return 0;

wait_to_die:
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

/*
 * migration_call - callback that gets triggered when a CPU is added.
 * Here we can start up the necessary migration thread for the new CPU.
 */
static int migration_call(struct notifier_block *nfb, unsigned long action,
			  void *hcpu)
{
	int cpu = (long) hcpu;
	struct task_struct *p;
	struct runqueue *rq;
	unsigned long flags;

	switch (action) {
	case CPU_UP_PREPARE:
		p = kthread_create(migration_thread, hcpu, "migration/%d",cpu);
		if (IS_ERR(p))
			return NOTIFY_BAD;
		p->flags |= PF_NOFREEZE;
		kthread_bind(p, cpu);
		rq = task_rq_lock(p, &flags);
		__setscheduler(p, SCHED_FIFO, MAX_RT_PRIO-1);
		task_rq_unlock(rq, &flags);
		cpu_rq(cpu)->migration_thread = p;
		break;
	case CPU_ONLINE:	
		wake_up_process(cpu_rq(cpu)->migration_thread);
		break;
#ifdef CONFIG_HOTPLUG_CPU
#error "CONFIG_HOTPLUG_CPU"
#endif
	}
	return NOTIFY_OK;
}

/* Register at highest priority so that task migration (migrate_all_tasks)
 * happens before everything else.
 */
static struct notifier_block __devinitdata migration_notifier = {
	.notifier_call = migration_call,
	.priority = 10
};

int __init migration_init(void)
{
	void *cpu = (void *)(long)smp_processor_id();
	/* Start one for boot CPU. */
	migration_call(&migration_notifier, CPU_UP_PREPARE, cpu);
	migration_call(&migration_notifier, CPU_ONLINE, cpu);
	register_cpu_notifier(&migration_notifier);
	return 0;
}

#endif

#ifdef CONFIG_SMP
#define SCHED_DOMAIN_DEBUG
#ifdef SCHED_DOMAIN_DEBUG
static void sched_domain_debug(struct sched_domain *sd, int cpu)
{
	int level = 0;

	printk(KERN_DEBUG "CPU%d attaching sched-domain:\n", cpu);

	do {
		int i;
		char str[NR_CPUS];
		struct sched_group *group = sd->groups;
		cpumask_t groupmask;

		cpumask_scnprintf(str, NR_CPUS, sd->span);
		cpus_clear(groupmask);

		printk(KERN_DEBUG);
		for (i = 0; i < level + 1; i++)
			printk(" ");
		printk("domain %d: ", level);

		if (!(sd->flags & SD_LOAD_BALANCE)) {
			printk("does not load-balance\n");
			if (sd->parent)
				printk(KERN_ERR "ERROR: !SD_LOAD_BALANCE domain has parent");
			break;
		}

		printk("span %s\n", str);

		if (!cpu_isset(cpu, sd->span))
			printk(KERN_ERR "ERROR: domain->span does not contain CPU%d\n", cpu);
		if (!cpu_isset(cpu, group->cpumask))
			printk(KERN_ERR "ERROR: domain->groups does not contain CPU%d\n", cpu);

		printk(KERN_DEBUG);
		for (i = 0; i < level + 2; i++)
			printk(" ");
		printk("groups:");
		do {
			if (!group) {
				printk("\n");
				printk(KERN_ERR "ERROR: group is NULL\n");
				break;
			}

			if (!group->cpu_power) {
				printk("\n");
				printk(KERN_ERR "ERROR: domain->cpu_power not set\n");
			}

			if (!cpus_weight(group->cpumask)) {
				printk("\n");
				printk(KERN_ERR "ERROR: empty group\n");
			}

			if (cpus_intersects(groupmask, group->cpumask)) {
				printk("\n");
				printk(KERN_ERR "ERROR: repeated CPUs\n");
			}

			cpus_or(groupmask, groupmask, group->cpumask);

			cpumask_scnprintf(str, NR_CPUS, group->cpumask);
			printk(" %s", str);

			group = group->next;
		} while (group != sd->groups);
		printk("\n");

		if (!cpus_equal(sd->span, groupmask))
			printk(KERN_ERR "ERROR: groups don't span domain->span\n");

		level++;
		sd = sd->parent;

		if (sd) {
			if (!cpus_subset(groupmask, sd->span))
				printk(KERN_ERR "ERROR: parent span is not a superset of domain->span\n");
		}

	} while (sd);
}
#else
#define sched_domain_debug(sd, cpu) {}
#endif

void __devinit cpu_attach_domain(struct sched_domain *sd, int cpu)
{
	migration_req_t req;
	unsigned long flags;
	runqueue_t *rq = cpu_rq(cpu);
	int local = 1;

	sched_domain_debug(sd, cpu);

	spin_lock_irqsave(&rq->lock, flags);

	if (cpu == smp_processor_id() || !cpu_online(cpu)) {
		rq->sd = sd;
	} else {
		init_completion(&req.done);
		req.type = REQ_SET_DOMAIN;
		req.sd = sd;
		list_add(&req.list, &rq->migration_queue);
		local = 0;
	}

	spin_unlock_irqrestore(&rq->lock, flags);

	if (!local) {
		wake_up_process(rq->migration_thread);
		wait_for_completion(&req.done);
	}
}

/* cpus with isolated domains */
cpumask_t __devinitdata cpu_isolated_map = CPU_MASK_NONE;

void __devinit init_sched_build_groups(struct sched_group groups[],
			cpumask_t span, int (*group_fn)(int cpu))
{
	struct sched_group *first = NULL, *last = NULL;
	cpumask_t covered = CPU_MASK_NONE;
	int i;

	for_each_cpu_mask(i, span) {
		int group = group_fn(i);
		struct sched_group *sg = &groups[group];
		int j;

		if (cpu_isset(i, covered))
			continue;

		sg->cpumask = CPU_MASK_NONE;
		sg->cpu_power = 0;

		for_each_cpu_mask(j, span) {
			if (group_fn(j) != group)
				continue;
			
			cpu_set(j, covered);
			cpu_set(j, sg->cpumask);
		}
		if (!first)
			first = sg;
		if (last)
			last->next = sg;
		last = sg;
	}
	last->next = first;
}

#ifdef ARCH_HAS_SCHED_DOMAIN
#error "ARCH_HAS_SCHED_DOMAIN"
#else
#ifdef CONFIG_SCHED_SMT
static DEFINE_PER_CPU(struct sched_domain, cpu_domains);
static struct sched_group sched_group_cpus[NR_CPUS];
static int __devinit cpu_to_cpu_group(int cpu)
{
	return cpu;
}
#endif

static DEFINE_PER_CPU(struct sched_domain, phys_domains);
static struct sched_group sched_group_phys[NR_CPUS];
static int __devinit cpu_to_phys_group(int cpu)
{
#ifdef CONFIG_SCHED_SMT
	return first_cpu(cpu_sibling_map[cpu]);
#else
	return cpu;
#endif
}

/*
 * Set up scheduler domains and groups.  Callers must hold the hotplug lock.
 */
static void __devinit arch_init_sched_domains(void)
{
	int i;
	cpumask_t cpu_default_map;

#if defined(CONFIG_SCHED_SMT) && defined(CONFIG_NUMA)
#error "CONFIG_SCHED_SMT && CONFIG_NUMA"
#endif

	cpus_complement(cpu_default_map, cpu_isolated_map);
	cpus_and(cpu_default_map, cpu_default_map, cpu_online_map);

	for_each_cpu_mask(i, cpu_default_map) {
		int group;
		struct sched_domain *sd = NULL, *p;
		cpumask_t nodemask = node_to_cpumask(cpu_to_node(i));

		cpus_and(nodemask, nodemask, cpu_default_map);
#ifdef CONFIG_NUMA
#error "CONFIG_NUMA"
#endif

		p = sd;
		sd = &per_cpu(phys_domains, i);
		group = cpu_to_phys_group(i);
		*sd = SD_CPU_INIT;
		sd->span = nodemask;
		sd->parent = p;
		sd->groups = &sched_group_phys[group];

#ifdef CONFIG_SCHED_SMT
		p = sd;
		sd = &per_cpu(cpu_domains, i);
		group = cpu_to_cpu_group(i);
		*sd = SD_SIBLING_INIT;
		sd->span = cpu_sibling_map[i];
		cpus_and(sd->span, sd->span, cpu_default_map);
		sd->parent = p;
		sd->groups = &sched_group_cpus[group];
#endif
	}

#ifdef CONFIG_SCHED_SMT
	/* Set up CPU (sibling) groups */
	for_each_online_cpu(i) {
		cpumask_t this_sibling_map = cpu_sibling_map[i];
		cpus_and(this_sibling_map, this_sibling_map, cpu_default_map);
		if (i != first_cpu(this_sibling_map))
			continue;

		init_sched_build_groups(sched_group_cpus, this_sibling_map,
						&cpu_to_cpu_group);
	}
#endif

	/* Set up physical groups */
	for (i = 0; i < MAX_NUMNODES; i++) {
		cpumask_t nodemask = node_to_cpumask(i);

		cpus_and(nodemask, nodemask, cpu_default_map);
		if (cpus_empty(nodemask))
			continue;

		init_sched_build_groups(sched_group_phys, nodemask,
						&cpu_to_phys_group);
	}
#ifdef CONFIG_NUMA
#error "CONFIG_NUMA"
#endif

	/* Calculate CPU power for physical packages and nodes */
	for_each_cpu_mask(i, cpu_default_map) {
		int power;
		struct sched_domain *sd;
#ifdef CONFIG_SCHED_SMT
		sd = &per_cpu(cpu_domains, i);
		power = SCHED_LOAD_SCALE;
		sd->groups->cpu_power = power;
#endif

		sd = &per_cpu(phys_domains, i);
		power = SCHED_LOAD_SCALE + SCHED_LOAD_SCALE *
				(cpus_weight(sd->groups->cpumask)-1) / 10;
		sd->groups->cpu_power = power;

#ifdef CONFIG_NUMA
		if (i == first_cpu(sd->groups->cpumask)) {
			/* Only add "power" once for each physical package. */
			sd = &per_cpu(node_domains, i);
			sd->groups->cpu_power += power;
		}
#endif
	}

	/* Attach the domains */
	for_each_online_cpu(i) {
		struct sched_domain *sd;
#ifdef CONFIG_SCHED_SMT
		sd = &per_cpu(cpu_domains, i);
#else
		sd = &per_cpu(phys_domains, i);
#endif
		cpu_attach_domain(sd, i);
	}
}

#ifdef CONFIG_HOTPLUG_CPU
#error "CONFIG_HOTPLUG_CPU"
#endif

#endif /* ARCH_HAS_SCHED_DOMAIN */

static struct sched_domain sched_domain_dummy;

void __init sched_init_smp(void)
{
	lock_cpu_hotplug();
	arch_init_sched_domains();
	unlock_cpu_hotplug();
	/* XXX: Theoretical race here - CPU may be hotplugged now */
	hotcpu_notifier(update_sched_domains, 0);
}

#else

#endif /* CONFIG_SMP */

void __init sched_init(void)
{
	runqueue_t *rq;
	int i, j, k;

	// 每个cpu的运行队列相关数据结构初始化
	for (i = 0; i < NR_CPUS; i++) {
		prio_array_t *array;

		rq = cpu_rq(i);
		spin_lock_init(&rq->lock);
		rq->active = rq->arrays;
		rq->expired = rq->arrays + 1;
		rq->best_expired_prio = MAX_PRIO;
#ifdef CONFIG_SMP
		rq->sd = &sched_domain_dummy;
		rq->cpu_load = 0;
		rq->active_balance = 0;
		rq->push_cpu = 0;
		rq->migration_thread = NULL;
		INIT_LIST_HEAD(&rq->migration_queue);
#endif
		atomic_set(&rq->nr_iowait, 0);

		for (j = 0; j < 2; j++) {
			array = rq->arrays + j;
			for (k = 0; k < MAX_PRIO; k++) {
				INIT_LIST_HEAD(array->queue + k);
				__clear_bit(k, array->bitmap);
			}
			__set_bit(MAX_PRIO, array->bitmap);
		}
	}

	atomic_inc(&init_mm.mm_count);
	enter_lazy_tlb(&init_mm, current);

	init_idle(current, smp_processor_id());
}