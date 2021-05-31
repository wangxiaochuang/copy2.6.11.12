#include <linux/config.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/smp_lock.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/tty.h>
#include <linux/namespace.h>
#include <linux/key.h>
#include <linux/security.h>
#include <linux/cpu.h>
#include <linux/acct.h>
#include <linux/file.h>
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/profile.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/mempolicy.h>
#include <linux/syscalls.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/pgtable.h>
#include <asm/mmu_context.h>

static void __unhash_process(struct task_struct *p)
{
	nr_threads--;
	detach_pid(p, PIDTYPE_PID);
	detach_pid(p, PIDTYPE_TGID);
	if (thread_group_leader(p)) {
		detach_pid(p, PIDTYPE_PGID);
		detach_pid(p, PIDTYPE_SID);
		if (p->pid)
			__get_cpu_var(process_counts)--;
	}
	REMOVE_LINKS(p);
}

void release_task(struct task_struct * p)
{
	int zap_leader;
	task_t *leader;
	struct dentry *proc_dentry;

repeat: 
	atomic_dec(&p->user->processes);
	spin_lock(&p->proc_lock);
	proc_dentry = proc_pid_unhash(p);
	write_lock_irq(&tasklist_lock);
	if (unlikely(p->ptrace))
		__ptrace_unlink(p);
	BUG_ON(!list_empty(&p->ptrace_list) || !list_empty(&p->ptrace_children));
	__exit_signal(p);
	__exit_sighand(p);
	__unhash_process(p);

	/*
	 * If we are the last non-leader member of the thread
	 * group, and the leader is zombie, then notify the
	 * group leader's parent process. (if it wants notification.)
	 */
	zap_leader = 0;
	leader = p->group_leader;
	if (leader != p && thread_group_empty(leader) && leader->exit_state == EXIT_ZOMBIE) {
		BUG_ON(leader->exit_signal == -1);
		do_notify_parent(leader, leader->exit_signal);
		/*
		 * If we were the last child thread and the leader has
		 * exited already, and the leader's parent ignores SIGCHLD,
		 * then we are the one who should release the leader.
		 *
		 * do_notify_parent() will have marked it self-reaping in
		 * that case.
		 */
		zap_leader = (leader->exit_signal == -1);
	}

	sched_exit(p);
	write_unlock_irq(&tasklist_lock);
	spin_unlock(&p->proc_lock);
	proc_pid_flush(proc_dentry);
	release_thread(p);
	put_task_struct(p);

	p = leader;
	if (unlikely(zap_leader))
		goto repeat;
}

/* we are using it only for SMP init */

void unhash_process(struct task_struct *p)
{
	struct dentry *proc_dentry;

	spin_lock(&p->proc_lock);
	proc_dentry = proc_pid_unhash(p);
	write_lock_irq(&tasklist_lock);
	__unhash_process(p);
	write_unlock_irq(&tasklist_lock);
	spin_unlock(&p->proc_lock);
	proc_pid_flush(proc_dentry);
}

int session_of_pgrp(int pgrp)
{
	struct task_struct *p;
	int sid = -1;

	read_lock(&tasklist_lock);
	do_each_task_pid(pgrp, PIDTYPE_PGID, p) {
		if (p->signal->session > 0) {
			sid = p->signal->session;
			goto out;
		}
	} while_each_task_pid(pgrp, PIDTYPE_PGID, p);
	p = find_task_by_pid(pgrp);
	if (p)
		sid = p->signal->session;
out:
	read_unlock(&tasklist_lock);
	
	return sid;
}

static int will_become_orphaned_pgrp(int pgrp, task_t *ignored_task)
{
	struct task_struct *p;
	int ret = 1;

	do_each_task_pid(pgrp, PIDTYPE_PGID, p) {
		if (p == ignored_task
				|| p->exit_state
				|| p->real_parent->pid == 1)
			continue;
		if (process_group(p->real_parent) != pgrp
			    && p->real_parent->signal->session == p->signal->session) {
			ret = 0;
			break;
		}
	} while_each_task_pid(pgrp, PIDTYPE_PGID, p);
	return ret;	/* (sighing) "Often!" */
}

int is_orphaned_pgrp(int pgrp)
{
	int retval;

	read_lock(&tasklist_lock);
	retval = will_become_orphaned_pgrp(pgrp, NULL);
	read_unlock(&tasklist_lock);

	return retval;
}

static inline int has_stopped_jobs(int pgrp)
{
	int retval = 0;
	struct task_struct *p;

	do_each_task_pid(pgrp, PIDTYPE_PGID, p) {
		if (p->state != TASK_STOPPED)
			continue;

		/* If p is stopped by a debugger on a signal that won't
		   stop it, then don't count p as stopped.  This isn't
		   perfect but it's a good approximation.  */
		if (unlikely (p->ptrace)
		    && p->exit_code != SIGSTOP
		    && p->exit_code != SIGTSTP
		    && p->exit_code != SIGTTOU
		    && p->exit_code != SIGTTIN)
			continue;

		retval = 1;
		break;
	} while_each_task_pid(pgrp, PIDTYPE_PGID, p);
	return retval;
}

void reparent_to_init(void)
{
	panic("in reparent_to_init function");
}

static inline void close_files(struct files_struct * files)
{
	int i, j;

	j = 0;
	for (;;) {
		unsigned long set;
		i = j * __NFDBITS;
		if (i >= files->max_fdset || i >= files->max_fds)
			break;
		set = files->open_fds->fds_bits[j++];
		while (set) {
			if (set & 1) {
				struct file *file = xchg(&files->fd[i], NULL);
				if (file)
					filp_close(file, files);
			}
			i++;
			set >>= 1;
		}
	}
}

struct files_struct *get_files_struct(struct task_struct *task)
{
	struct files_struct *files;

	task_lock(task);
	files = task->files;
	if (files)
		atomic_inc(&files->count);
	task_unlock(task);

	return files;
}

void fastcall put_files_struct(struct files_struct *files)
{
    if (atomic_dec_and_test(&files->count)) {
        close_files(files);
        if (files->fd != &files->fd_array[0])
            free_fd_array(files->fd, files->max_fds);
        if (files->max_fdset > __FD_SETSIZE) {
            free_fdset(files->open_fds, files->max_fdset);
            free_fdset(files->close_on_exec, files->max_fdset);
        }
        kmem_cache_free(files_cachep, files);
    }
}

EXPORT_SYMBOL(put_files_struct);

static inline void __exit_files(struct task_struct *tsk)
{
	struct files_struct * files = tsk->files;

	if (files) {
		task_lock(tsk);
		tsk->files = NULL;
		task_unlock(tsk);
		put_files_struct(files);
	}
}

void exit_files(struct task_struct *tsk)
{
	__exit_files(tsk);
}

static inline void __put_fs_struct(struct fs_struct *fs)
{
	/* No need to hold fs->lock if we are killing it */
	if (atomic_dec_and_test(&fs->count)) {
		dput(fs->root);
		mntput(fs->rootmnt);
		dput(fs->pwd);
		mntput(fs->pwdmnt);
		if (fs->altroot) {
			dput(fs->altroot);
			mntput(fs->altrootmnt);
		}
		kmem_cache_free(fs_cachep, fs);
	}
}

void put_fs_struct(struct fs_struct *fs)
{
	__put_fs_struct(fs);
}

static inline void __exit_fs(struct task_struct *tsk)
{
	struct fs_struct * fs = tsk->fs;

	if (fs) {
		task_lock(tsk);
		tsk->fs = NULL;
		task_unlock(tsk);
		__put_fs_struct(fs);
	}
}

void exit_fs(struct task_struct *tsk)
{
	__exit_fs(tsk);
}

EXPORT_SYMBOL_GPL(exit_fs);

void exit_mm(struct task_struct * tsk)
{
	struct mm_struct *mm = tsk->mm;

	mm_release(tsk, mm);
	if (!mm)
		return;
	/*
	 * Serialize with any possible pending coredump.
	 * We must hold mmap_sem around checking core_waiters
	 * and clearing tsk->mm.  The core-inducing thread
	 * will increment core_waiters for each thread in the
	 * group with ->mm != NULL.
	 */
	down_read(&mm->mmap_sem);
	if (mm->core_waiters) {
		up_read(&mm->mmap_sem);
		down_write(&mm->mmap_sem);
		if (!--mm->core_waiters)
			complete(mm->core_startup_done);
		up_write(&mm->mmap_sem);

		wait_for_completion(&mm->core_done);
		down_read(&mm->mmap_sem);
	}
	atomic_inc(&mm->mm_count);
	if (mm != tsk->active_mm) BUG();
	/* more a memory barrier than a real lock */
	task_lock(tsk);
	tsk->mm = NULL;
	up_read(&mm->mmap_sem);
	enter_lazy_tlb(mm, current);
	task_unlock(tsk);
	mmput(mm);
}

static inline void forget_original_parent(struct task_struct * father,
					  struct list_head *to_release)
{
	struct task_struct *p, *reaper = father;
	struct list_head *_p, *_n;

	do {
		reaper = next_thread(reaper);
		if (reaper == father) {
			reaper = child_reaper;
			break;
		}
	} while (reaper->exit_state);

	/*
	 * There are only two places where our children can be:
	 *
	 * - in our child list
	 * - in our ptraced child list
	 *
	 * Search them and reparent children.
	 */
	list_for_each_safe(_p, _n, &father->children) {
		int ptrace;
		panic("in forget_original_parent function");
	}
	list_for_each_safe(_p, _n, &father->ptrace_children) {
		p = list_entry(_p,struct task_struct,ptrace_list);
		panic("in forget_original_parent function");
	}
}

static void exit_notify(struct task_struct *tsk)
{
	int state;
	struct task_struct *t;
	struct list_head ptrace_dead, *_p, *_n;

	if (signal_pending(tsk) && !(tsk->signal->flags & SIGNAL_GROUP_EXIT)
	    && !thread_group_empty(tsk)) {

		read_lock(&tasklist_lock);
		spin_lock_irq(&tsk->sighand->siglock);
		for (t = next_thread(tsk); t != tsk; t = next_thread(t))
			if (!signal_pending(t) && !(t->flags & PF_EXITING)) {
				recalc_sigpending_tsk(t);
				if (signal_pending(t))
					signal_wake_up(t, 0);
			}
		spin_unlock_irq(&tsk->sighand->siglock);
		read_unlock(&tasklist_lock);
	}

	write_lock_irq(&tasklist_lock);

	INIT_LIST_HEAD(&ptrace_dead);
	forget_original_parent(tsk, &ptrace_dead);
	BUG_ON(!list_empty(&tsk->children));
	BUG_ON(!list_empty(&tsk->ptrace_children));

	t = tsk->real_parent;
	
	if ((process_group(t) != process_group(tsk)) &&
	    (t->signal->session == tsk->signal->session) &&
	    will_become_orphaned_pgrp(process_group(tsk), tsk) &&
	    has_stopped_jobs(process_group(tsk))) {
		__kill_pg_info(SIGHUP, (void *)1, process_group(tsk));
		__kill_pg_info(SIGCONT, (void *)1, process_group(tsk));
	}

	if (tsk->exit_signal != SIGCHLD && tsk->exit_signal != -1 &&
	    ( tsk->parent_exec_id != t->self_exec_id  ||
	      tsk->self_exec_id != tsk->parent_exec_id)
	    && !capable(CAP_KILL))
		tsk->exit_signal = SIGCHLD;


	/* If something other than our normal parent is ptracing us, then
	 * send it a SIGCHLD instead of honoring exit_signal.  exit_signal
	 * only has special meaning to our real parent.
	 */
	if (tsk->exit_signal != -1 && thread_group_empty(tsk)) {
		int signal = tsk->parent == tsk->real_parent ? tsk->exit_signal : SIGCHLD;
		do_notify_parent(tsk, signal);
	} else if (tsk->ptrace) {
		do_notify_parent(tsk, SIGCHLD);
	}

	state = EXIT_ZOMBIE;
	if (tsk->exit_signal == -1 &&
	    (likely(tsk->ptrace == 0) ||
	     unlikely(tsk->parent->signal->flags & SIGNAL_GROUP_EXIT)))
		state = EXIT_DEAD;
	tsk->exit_state = state;

	/*
	 * Clear these here so that update_process_times() won't try to deliver
	 * itimer, profile or rlimit signals to this task while it is in late exit.
	 */
	tsk->it_virt_value = cputime_zero;
	tsk->it_prof_value = cputime_zero;

	write_unlock_irq(&tasklist_lock);

	list_for_each_safe(_p, _n, &ptrace_dead) {
		list_del_init(_p);
		t = list_entry(_p,struct task_struct,ptrace_list);
		release_task(t);
	}

	/* If the process is dead, release it - nobody will wait for it */
	if (state == EXIT_DEAD)
		release_task(tsk);

	/* PF_DEAD causes final put_task_struct after we schedule. */
	preempt_disable();
	tsk->flags |= PF_DEAD;
}

fastcall NORET_TYPE void do_exit(long code)
{
	struct task_struct *tsk = current;
	int group_dead;

	profile_task_exit(tsk);

	if (unlikely(in_interrupt()))
		panic("Aiee, killing interrupt handler!");
	if (unlikely(!tsk->pid))
		panic("Attempted to kill the idle task!");
	if (unlikely(tsk->pid == 1))
		panic("Attempted to kill init!");
	if (tsk->io_context)
		exit_io_context();

	if (unlikely(current->ptrace & PT_TRACE_EXIT)) {
		current->ptrace_message = code;
		ptrace_notify((PTRACE_EVENT_EXIT << 8) | SIGTRAP);
	}

	tsk->flags |= PF_EXITING;
	del_timer_sync(&tsk->real_timer);

	if (unlikely(in_atomic()))
		printk(KERN_INFO "note: %s[%d] exited with preempt_count %d\n",
				current->comm, current->pid,
				preempt_count());

	acct_update_integrals();
	update_mem_hiwater();
	group_dead = atomic_dec_and_test(&tsk->signal->live);
	if (group_dead)
		acct_process(code);
	exit_mm(tsk);

	exit_sem(tsk);
	__exit_files(tsk);
	__exit_fs(tsk);
	exit_namespace(tsk);
	exit_thread();
	exit_keys(tsk);

	if (group_dead && tsk->signal->leader)
		disassociate_ctty(1);

	module_put(tsk->thread_info->exec_domain->module);
	if (tsk->binfmt)
		module_put(tsk->binfmt->module);

	tsk->exit_code = code;
	exit_notify(tsk);
#ifdef CONFIG_NUMA
	mpol_free(tsk->mempolicy);
	tsk->mempolicy = NULL;
#endif

	BUG_ON(!(current->flags & PF_DEAD));
	schedule();
	BUG();
	/* Avoid "noreturn function does return".  */
	for (;;) ;
}

task_t fastcall *next_thread(const task_t *p)
{
	return pid_task(p->pids[PIDTYPE_TGID].pid_list.next, PIDTYPE_TGID);
}

EXPORT_SYMBOL(next_thread);