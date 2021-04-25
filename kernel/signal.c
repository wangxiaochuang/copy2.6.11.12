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

int kill_proc(pid_t pid, int sig, int priv) {
	return 0;
}

long do_no_restart_syscall(struct restart_block *param)
{
	return -EINTR;
}