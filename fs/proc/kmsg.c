/*
 *  linux/fs/proc/kmsg.c
 *
 *  Copyright (C) 1992  by Linus Torvalds
 *
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/poll.h>
#include <linux/fs.h>

#include <asm/uaccess.h>
#include <asm/io.h>

extern wait_queue_head_t log_wait;


static int kmsg_open(struct inode * inode, struct file * file)
{
	return 0;
}

static int kmsg_release(struct inode * inode, struct file * file)
{
	return 0;
}

static ssize_t kmsg_read(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	return 0;
}

static unsigned int kmsg_poll(struct file *file, poll_table *wait)
{
	return 0;
}


struct file_operations proc_kmsg_operations = {
	.read		= kmsg_read,
	.poll		= kmsg_poll,
	.open		= kmsg_open,
	.release	= kmsg_release,
};
