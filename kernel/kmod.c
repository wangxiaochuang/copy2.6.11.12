#define __KERNEL_SYSCALLS__

#include <linux/config.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/kmod.h>
#include <linux/smp_lock.h>
#include <linux/slab.h>
#include <linux/namespace.h>
#include <linux/completion.h>
#include <linux/file.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/uaccess.h>

extern int max_threads;

static struct workqueue_struct *khelper_wq;

struct subprocess_info {
	struct completion *complete;
	char *path;
	char **argv;
	char **envp;
	int wait;
	int retval;
};

static int ____call_usermodehelper(void *data)
{
	struct subprocess_info *sub_info = data;
	int retval;

	/* Unblock all signals. */
	flush_signals(current);
	spin_lock_irq(&current->sighand->siglock);
	flush_signal_handlers(current, 1);
	sigemptyset(&current->blocked);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	/* We can run anywhere, unlike our parent keventd(). */
	set_cpus_allowed(current, CPU_MASK_ALL);

	retval = -EPERM;
	if (current->fs->root)
		retval = execve(sub_info->path, sub_info->argv,sub_info->envp);

	/* Exec failed? */
	sub_info->retval = retval;
	do_exit(0);
}

static int wait_for_helper(void *data)
{
	panic("in wait_for_helper function");
	return 0;
}

static void __call_usermodehelper(void *data)
{
	struct subprocess_info *sub_info = data;
	pid_t pid;

	/* CLONE_VFORK: wait until the usermode helper has execve'd
	 * successfully We need the data structures to stay around
	 * until that is done.  */
	if (sub_info->wait)
		pid = kernel_thread(wait_for_helper, sub_info,
				    CLONE_FS | CLONE_FILES | SIGCHLD);
	else
		pid = kernel_thread(____call_usermodehelper, sub_info,
				    CLONE_VFORK | SIGCHLD);

	if (pid < 0) {
		sub_info->retval = pid;
		complete(sub_info->complete);
	} else if (!sub_info->wait)
		complete(sub_info->complete);
}

int call_usermodehelper(char *path, char **argv, char **envp, int wait)
{
	DECLARE_COMPLETION(done);
	struct subprocess_info sub_info = {
		.complete	= &done,
		.path		= path,
		.argv		= argv,
		.envp		= envp,
		.wait		= wait,
		.retval		= 0,
	};
	DECLARE_WORK(work, __call_usermodehelper, &sub_info);

	if (!khelper_wq)
		return -EBUSY;

	if (path[0] == '\0')
		return 0;

	queue_work(khelper_wq, &work);
	wait_for_completion(&done);
	return sub_info.retval;
}

EXPORT_SYMBOL(call_usermodehelper);

void __init usermodehelper_init(void)
{
	khelper_wq = create_singlethread_workqueue("khelper");
	BUG_ON(!khelper_wq);
}