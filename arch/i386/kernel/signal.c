#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include <linux/unistd.h>
#include <linux/stddef.h>
#include <linux/personality.h>
#include <linux/suspend.h>
#include <linux/ptrace.h>
#include <linux/elf.h>
#include <asm/processor.h>
#include <asm/ucontext.h>
#include <asm/uaccess.h>
#include <asm/i387.h>
#include "sigframe.h"

/*
 * notification of userspace execution resumption
 * - triggered by current->work.notify_resume
 */
__attribute__((regparm(3)))
void do_notify_resume(struct pt_regs *regs, sigset_t *oldset,
		      __u32 thread_info_flags)
{

}