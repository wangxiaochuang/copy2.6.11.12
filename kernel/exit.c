#include <linux/config.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/smp_lock.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/tty.h>

fastcall NORET_TYPE void do_exit(long code)
{
    for(;;);
}

task_t fastcall *next_thread(const task_t *p)
{
	return pid_task(p->pids[PIDTYPE_TGID].pid_list.next, PIDTYPE_TGID);
}

EXPORT_SYMBOL(next_thread);