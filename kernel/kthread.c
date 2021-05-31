#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/unistd.h>
#include <linux/file.h>
#include <linux/module.h>
#include <asm/semaphore.h>

/*
 * We dont want to execute off keventd since it might
 * hold a semaphore our callers hold too:
 */
static struct workqueue_struct *helper_wq;

struct kthread_create_info
{
	/* Information passed to kthread() from keventd. */
	int (*threadfn)(void *data);
	void *data;
	struct completion started;

	/* Result passed back to kthread_create() from keventd. */
	struct task_struct *result;
	struct completion done;
};

struct kthread_stop_info
{
	struct task_struct *k;
	int err;
	struct completion done;
};

static DECLARE_MUTEX(kthread_stop_lock);
static struct kthread_stop_info kthread_stop_info;

int kthread_should_stop(void)
{
	return (kthread_stop_info.k == current);
}
EXPORT_SYMBOL(kthread_should_stop);

static void kthread_exit_files(void)
{
    struct fs_struct *fs;
	struct task_struct *tsk = current;

    exit_fs(tsk);
    fs = init_task.fs;
    tsk->fs = fs;
    atomic_inc(&fs->count);
    exit_files(tsk);
    current->files = init_task.files;
    atomic_inc(&tsk->files->count);
}

static int kthread(void *_create)
{
    struct kthread_create_info *create = _create;
	int (*threadfn)(void *data);
	void *data;
	sigset_t blocked;
	int ret = -EINTR;

    kthread_exit_files();

    threadfn = create->threadfn;
    data = create->data;

    sigfillset(&blocked);
    sigprocmask(SIG_BLOCK, &blocked, NULL);
    flush_signals(current);

    set_cpus_allowed(current, CPU_MASK_ALL);

    __set_current_state(TASK_INTERRUPTIBLE);
    complete(&create->started);
    schedule();

    if (!kthread_should_stop())
        ret = threadfn(data);
    if (kthread_should_stop()) {
        kthread_stop_info.err = ret;
        complete(&kthread_stop_info.done);
    }
    return 0;
}

static void keventd_create_kthread(void *_create)
{
    struct kthread_create_info *create = _create;
    int pid;

    pid = kernel_thread(kthread, create, CLONE_FS | CLONE_FILES | SIGCHLD);
    if (pid < 0) {
        create->result = ERR_PTR(pid);
    } else {
        wait_for_completion(&create->started);
        create->result = find_task_by_pid(pid);
    }
    complete(&create->done);
}

struct task_struct *kthread_create(int (*threadfn)(void *data),
				   void *data,
				   const char namefmt[],
				   ...)
{
    struct kthread_create_info create;
    DECLARE_WORK(work, keventd_create_kthread, &create);

    create.threadfn = threadfn;
    create.data = data;
    init_completion(&create.started);
    init_completion(&create.done);

    if (!helper_wq) {
        work.func(work.data);
    } else {
        queue_work(helper_wq, &work);
        wait_for_completion(&create.done);
    }
    if (!IS_ERR(create.result)) {
        va_list args;
        va_start(args, namefmt);
        vsnprintf(create.result->comm, sizeof(create.result->comm),
			  namefmt, args);
        va_end(args);
    }
    return create.result;
}
EXPORT_SYMBOL(kthread_create);

void kthread_bind(struct task_struct *k, unsigned int cpu)
{
    BUG_ON(k->state != TASK_INTERRUPTIBLE);
    wait_task_inactive(k);
    set_task_cpu(k, cpu);
    k->cpus_allowed = cpumask_of_cpu(cpu);
}
EXPORT_SYMBOL(kthread_bind);

int kthread_stop(struct task_struct *k)
{
    int ret;

	down(&kthread_stop_lock);

    get_task_struct(k);

    /* Must init completion *before* thread sees kthread_stop_info.k */
	init_completion(&kthread_stop_info.done);
	wmb();

    /* Now set kthread_should_stop() to true, and wake it up. */
    kthread_stop_info.k = k;
    wake_up_process(k);
    put_task_struct(k);

    /* Once it dies, reset stop ptr, gather result and we're done. */
	wait_for_completion(&kthread_stop_info.done);
	kthread_stop_info.k = NULL;
	ret = kthread_stop_info.err;
	up(&kthread_stop_lock);

	return ret;
}

EXPORT_SYMBOL(kthread_stop);
