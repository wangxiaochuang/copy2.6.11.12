#include <linux/config.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/tty.h>
#include <linux/binfmts.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/ptrace.h>
#include <asm/param.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/siginfo.h>

static kmem_cache_t *sigqueue_cachep;

#ifdef SIGEMT
#define M_SIGEMT	M(SIGEMT)
#else
#define M_SIGEMT	0
#endif

#if SIGRTMIN > BITS_PER_LONG
#define M(sig) (1ULL << ((sig)-1))
#else
#define M(sig) (1UL << ((sig)-1))
#endif
#define T(sig, mask) (M(sig) & (mask))

#define SIG_KERNEL_ONLY_MASK (\
	M(SIGKILL)   |  M(SIGSTOP)                                   )

#define SIG_KERNEL_STOP_MASK (\
	M(SIGSTOP)   |  M(SIGTSTP)   |  M(SIGTTIN)   |  M(SIGTTOU)   )

#define SIG_KERNEL_COREDUMP_MASK (\
        M(SIGQUIT)   |  M(SIGILL)    |  M(SIGTRAP)   |  M(SIGABRT)   | \
        M(SIGFPE)    |  M(SIGSEGV)   |  M(SIGBUS)    |  M(SIGSYS)    | \
        M(SIGXCPU)   |  M(SIGXFSZ)   |  M_SIGEMT                     )

#define SIG_KERNEL_IGNORE_MASK (\
        M(SIGCONT)   |  M(SIGCHLD)   |  M(SIGWINCH)  |  M(SIGURG)    )

#define sig_kernel_only(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_ONLY_MASK))
#define sig_kernel_coredump(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_COREDUMP_MASK))
#define sig_kernel_ignore(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_IGNORE_MASK))
#define sig_kernel_stop(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_STOP_MASK))

#define sig_user_defined(t, signr) \
	(((t)->sighand->action[(signr)-1].sa.sa_handler != SIG_DFL) &&	\
	 ((t)->sighand->action[(signr)-1].sa.sa_handler != SIG_IGN))

#define sig_fatal(t, signr) \
	(!T(signr, SIG_KERNEL_IGNORE_MASK|SIG_KERNEL_STOP_MASK) && \
	 (t)->sighand->action[(signr)-1].sa.sa_handler == SIG_DFL)

static int sig_ignored(struct task_struct *t, int sig)
{
	void __user * handler;

	/*
	 * Tracers always want to know about signals..
	 */
	if (t->ptrace & PT_PTRACED)
		return 0;

	/*
	 * Blocked signals are never ignored, since the
	 * signal handler may change by the time it is
	 * unblocked.
	 */
	if (sigismember(&t->blocked, sig))
		return 0;

	/* Is it explicitly or implicitly ignored? */
	handler = t->sighand->action[sig-1].sa.sa_handler;
	return   handler == SIG_IGN ||
		(handler == SIG_DFL && sig_kernel_ignore(sig));
}

static inline int has_pending_signals(sigset_t *signal, sigset_t *blocked)
{
	unsigned long ready;
	long i;

	switch (_NSIG_WORDS) {
	default:
		for (i = _NSIG_WORDS, ready = 0; --i >= 0 ;)
			ready |= signal->sig[i] &~ blocked->sig[i];
		break;

	case 4: ready  = signal->sig[3] &~ blocked->sig[3];
		ready |= signal->sig[2] &~ blocked->sig[2];
		ready |= signal->sig[1] &~ blocked->sig[1];
		ready |= signal->sig[0] &~ blocked->sig[0];
		break;

	case 2: ready  = signal->sig[1] &~ blocked->sig[1];
		ready |= signal->sig[0] &~ blocked->sig[0];
		break;

	case 1: ready  = signal->sig[0] &~ blocked->sig[0];
	}
	return ready !=	0;
}

#define PENDING(p,b) has_pending_signals(&(p)->signal, (b))

fastcall void recalc_sigpending_tsk(struct task_struct *t)
{
	if (t->signal->group_stop_count > 0 ||
	    PENDING(&t->pending, &t->blocked) ||
	    PENDING(&t->signal->shared_pending, &t->blocked))
		set_tsk_thread_flag(t, TIF_SIGPENDING);
	else
		clear_tsk_thread_flag(t, TIF_SIGPENDING);
}

void recalc_sigpending(void)
{
	recalc_sigpending_tsk(current);
}

static int
next_signal(struct sigpending *pending, sigset_t *mask)
{
	return 0;
}

static struct sigqueue *__sigqueue_alloc(struct task_struct *t, int flags)
{
	struct sigqueue *q = NULL;

	if (atomic_read(&t->user->sigpending) <
			t->signal->rlim[RLIMIT_SIGPENDING].rlim_cur)
		q = kmem_cache_alloc(sigqueue_cachep, flags);
	if (q) {
		INIT_LIST_HEAD(&q->list);
		q->flags = 0;
		q->lock = NULL;
		q->user = get_uid(t->user);
		atomic_inc(&q->user->sigpending);
	}
	return(q);
}

static inline void __sigqueue_free(struct sigqueue *q)
{
	if (q->flags & SIGQUEUE_PREALLOC)
		return;
	atomic_dec(&q->user->sigpending);
	free_uid(q->user);
	kmem_cache_free(sigqueue_cachep, q);
}

static void flush_sigqueue(struct sigpending *queue)
{
	struct sigqueue *q;

	sigemptyset(&queue->signal);
	while (!list_empty(&queue->list)) {
		q = list_entry(queue->list.next, struct sigqueue, list);
		list_del_init(&q->list);
		__sigqueue_free(q);
	}
}

/*
 * Flush all pending signals for a task.
 */

void
flush_signals(struct task_struct *t)
{
	unsigned long flags;

	spin_lock_irqsave(&t->sighand->siglock, flags);
	clear_tsk_thread_flag(t,TIF_SIGPENDING);
	flush_sigqueue(&t->pending);
	flush_sigqueue(&t->signal->shared_pending);
	spin_unlock_irqrestore(&t->sighand->siglock, flags);
}

void __exit_sighand(struct task_struct *tsk)
{
	struct sighand_struct * sighand = tsk->sighand;

	/* Ok, we're done with the signal handlers */
	tsk->sighand = NULL;
	if (atomic_dec_and_test(&sighand->count))
		kmem_cache_free(sighand_cachep, sighand);
}

void exit_sighand(struct task_struct *tsk)
{
	write_lock_irq(&tasklist_lock);
	__exit_sighand(tsk);
	write_unlock_irq(&tasklist_lock);
}

void __exit_signal(struct task_struct *tsk)
{
	struct signal_struct * sig = tsk->signal;
	struct sighand_struct * sighand = tsk->sighand;

	if (!sig)
		BUG();
	if (!atomic_read(&sig->count))
		BUG();
	spin_lock(&sighand->siglock);
	if (atomic_dec_and_test(&sig->count)) {
		if (tsk == sig->curr_target)
			sig->curr_target = next_thread(tsk);
		tsk->signal = NULL;
		spin_unlock(&sighand->siglock);
		flush_sigqueue(&sig->shared_pending);
	} else {
		if (sig->group_exit_task && atomic_read(&sig->count) == sig->notify_count) {
			wake_up_process(sig->group_exit_task);
			sig->group_exit_task = NULL;
		}
		if (tsk == sig->curr_target)
			sig->curr_target = next_thread(tsk);
		tsk->signal = NULL;

		sig->utime = cputime_add(sig->utime, tsk->utime);
		sig->stime = cputime_add(sig->stime, tsk->stime);
		sig->min_flt += tsk->min_flt;
		sig->maj_flt += tsk->maj_flt;
		sig->nvcsw += tsk->nvcsw;
		sig->nivcsw += tsk->nivcsw;
		spin_unlock(&sighand->siglock);
		sig = NULL;	/* Marker for below.  */
	}
	clear_tsk_thread_flag(tsk,TIF_SIGPENDING);
	flush_sigqueue(&tsk->pending);
	if (sig) {
		exit_itimers(sig);
		kmem_cache_free(signal_cachep, sig);
	}
}

void exit_signal(struct task_struct *tsk)
{
	write_lock_irq(&tasklist_lock);
	__exit_signal(tsk);
	write_unlock_irq(&tasklist_lock);
}

void signal_wake_up(struct task_struct *t, int resume)
{
	unsigned int mask;

	set_tsk_thread_flag(t, TIF_SIGPENDING);

	mask = TASK_INTERRUPTIBLE;
	if (resume)
		mask |= TASK_STOPPED | TASK_TRACED;
	if (!wake_up_state(t, mask))
		kick_process(t);
}

static int send_signal(int sig, struct siginfo *info, struct task_struct *t,
			struct sigpending *signals)
{
	struct sigqueue * q = NULL;
	int ret = 0;

	/*
	 * fast-pathed signals for kernel-internal things like SIGSTOP
	 * or SIGKILL.
	 */
	if ((unsigned long)info == 2)
		goto out_set;

	/* Real-time signals must be queued if sent by sigqueue, or
	   some other real-time mechanism.  It is implementation
	   defined whether kill() does so.  We attempt to do so, on
	   the principle of least surprise, but since kill is not
	   allowed to fail with EAGAIN when low on memory we just
	   make sure at least one signal gets delivered and don't
	   pass on the info struct.  */

	q = __sigqueue_alloc(t, GFP_ATOMIC);
	if (q) {
		list_add_tail(&q->list, &signals->list);
		switch ((unsigned long) info) {
		case 0:
			q->info.si_signo = sig;
			q->info.si_errno = 0;
			q->info.si_code = SI_USER;
			q->info.si_pid = current->pid;
			q->info.si_uid = current->uid;
			break;
		case 1:
			q->info.si_signo = sig;
			q->info.si_errno = 0;
			q->info.si_code = SI_KERNEL;
			q->info.si_pid = 0;
			q->info.si_uid = 0;
			break;
		default:
			copy_siginfo(&q->info, info);
			break;
		}
	} else {
		if (sig >= SIGRTMIN && info && (unsigned long)info != 1
		   && info->si_code != SI_USER)
		/*
		 * Queue overflow, abort.  We may abort if the signal was rt
		 * and sent by user using something other than kill().
		 */
			return -EAGAIN;
		if (((unsigned long)info > 1) && (info->si_code == SI_TIMER))
			/*
			 * Set up a return to indicate that we dropped 
			 * the signal.
			 */
			ret = info->si_sys_private;
	}

out_set:
	sigaddset(&signals->signal, sig);
	return ret;
}

#define LEGACY_QUEUE(sigptr, sig) \
	(((sig) < SIGRTMIN) && sigismember(&(sigptr)->signal, (sig)))

static int
specific_send_sig_info(int sig, struct siginfo *info, struct task_struct *t)
{
	int ret = 0;

	if (!irqs_disabled())
		BUG();
	assert_spin_locked(&t->sighand->siglock);

	if (((unsigned long)info > 2) && (info->si_code == SI_TIMER))
		/*
		 * Set up a return to indicate that we dropped the signal.
		 */
		ret = info->si_sys_private;

	/* Short-circuit ignored signals.  */
	if (sig_ignored(t, sig))
		goto out;

	/* Support queueing exactly one non-rt signal, so that we
	   can get more detailed information about the cause of
	   the signal. */
	if (LEGACY_QUEUE(&t->pending, sig))
		goto out;

	ret = send_signal(sig, info, t, &t->pending);
	if (!ret && !sigismember(&t->blocked, sig))
		signal_wake_up(t, sig == SIGKILL);
out:
	return ret;
}

int
send_sig_info(int sig, struct siginfo *info, struct task_struct *p)
{
	int ret;
	unsigned long flags;

	/*
	 * Make sure legacy kernel users don't send in bad values
	 * (normal paths check this in check_kill_permission).
	 */
	if (sig < 0 || sig > _NSIG)
		return -EINVAL;

	/*
	 * We need the tasklist lock even for the specific
	 * thread case (when we don't need to follow the group
	 * lists) in order to avoid races with "p->sighand"
	 * going away or changing from under us.
	 */
	read_lock(&tasklist_lock);  
	spin_lock_irqsave(&p->sighand->siglock, flags);
	ret = specific_send_sig_info(sig, info, p);
	spin_unlock_irqrestore(&p->sighand->siglock, flags);
	read_unlock(&tasklist_lock);
	return ret;
}

int
send_sig(int sig, struct task_struct *p, int priv)
{
	return send_sig_info(sig, (void*)(long)(priv != 0), p);
}

int kill_proc(pid_t pid, int sig, int priv) {
	return 0;
}

static void
do_notify_parent_cldstop(struct task_struct *tsk, struct task_struct *parent,
			 int why)
{
	panic("in do_notify_parent_cldstop function");
}

static void ptrace_stop(int exit_code, int nostop_code, siginfo_t *info)
{
	if (current->signal->group_stop_count > 0)
		--current->signal->group_stop_count;

	current->last_siginfo = info;
	current->exit_code = exit_code;

	set_current_state(TASK_TRACED);
	spin_unlock_irq(&current->sighand->siglock);
	read_lock(&tasklist_lock);
	if (likely(current->ptrace & PT_PTRACED) &&
	    likely(current->parent != current->real_parent ||
		   !(current->ptrace & PT_ATTACHED)) &&
	    (likely(current->parent->signal != current->signal) ||
	     !unlikely(current->signal->flags & SIGNAL_GROUP_EXIT))) {
		do_notify_parent_cldstop(current, current->parent,
					 CLD_TRAPPED);
		read_unlock(&tasklist_lock);
		schedule();
	} else {
		/*
		 * By the time we got the lock, our tracer went away.
		 * Don't stop here.
		 */
		read_unlock(&tasklist_lock);
		set_current_state(TASK_RUNNING);
		current->exit_code = nostop_code;
	}

	spin_lock_irq(&current->sighand->siglock);
	current->last_siginfo = NULL;

	/*
	 * Queued signals ignored us while we were stopped for tracing.
	 * So check for any that we should take before resuming user mode.
	 */
	recalc_sigpending();
}

void ptrace_notify(int exit_code)
{
	siginfo_t info;

	BUG_ON((exit_code & (0x7f | ~0xffff)) != SIGTRAP);

	memset(&info, 0, sizeof info);
	info.si_signo = SIGTRAP;
	info.si_code = exit_code;
	info.si_pid = current->pid;
	info.si_uid = current->uid;

	/* Let the debugger run.  */
	spin_lock_irq(&current->sighand->siglock);
	ptrace_stop(exit_code, 0, &info);
	spin_unlock_irq(&current->sighand->siglock);
}

long do_no_restart_syscall(struct restart_block *param)
{
	return -EINTR;
}

int sigprocmask(int how, sigset_t *set, sigset_t *oldset)
{
	int error;
	sigset_t old_block;

	spin_lock_irq(&current->sighand->siglock);
	old_block = current->blocked;
	error = 0;
	switch(how) {
	case SIG_BLOCK:
		sigorsets(&current->blocked, &current->blocked, set);
		break;
	case SIG_UNBLOCK:
		signandsets(&current->blocked, &current->blocked, set);
		break;
	case SIG_SETMASK:
		current->blocked = *set;
		break;
	default:
		error = -EINVAL;
	}
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
	if (oldset)
		*oldset = old_block;
	return error;
}

void __init signals_init(void)
{
	sigqueue_cachep =
		kmem_cache_create("sigqueue",
				  sizeof(struct sigqueue),
				  __alignof__(struct sigqueue),
				  SLAB_PANIC, NULL, NULL);
}