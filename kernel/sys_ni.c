
#include <linux/linkage.h>
#include <linux/errno.h>

#include <asm/unistd.h>

/*
 * Non-implemented system calls get redirected here.
 */
asmlinkage long sys_ni_syscall(void)
{
	return -ENOSYS;
}