#include "ext2.h"
#include <linux/time.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <asm/uaccess.h>


int ext2_ioctl (struct inode * inode, struct file * filp, unsigned int cmd,
		unsigned long arg)
{
	panic("in ext2_ioctl");
	return 0;
}