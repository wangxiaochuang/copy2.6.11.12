#include <linux/proc_fs.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/stop_machine.h>
#include <asm/semaphore.h>

/* This protects CPUs going up and down... */
DECLARE_MUTEX(cpucontrol);

static struct notifier_block *cpu_chain;

/* Need to know about CPUs going up/down? */
int register_cpu_notifier(struct notifier_block *nb)
{
	int ret;

	if ((ret = down_interruptible(&cpucontrol)) != 0)
		return ret;
	ret = notifier_chain_register(&cpu_chain, nb);
	up(&cpucontrol);
	return ret;
}
EXPORT_SYMBOL(register_cpu_notifier);