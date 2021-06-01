#include <linux/config.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/smp_lock.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/module.h>

#include <asm/uaccess.h>
#include <asm/ioctls.h>

asmlinkage long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    return 0;
}