#undef DEBUG

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <asm/uaccess.h>

#include "sysfs.h"

static ssize_t
read(struct file * file, char __user * userbuf, size_t count, loff_t * off)
{
    return 0;
}

static ssize_t write(struct file * file, const char __user * userbuf,
		     size_t count, loff_t * off)
{
    return 0;
}

static int mmap(struct file *file, struct vm_area_struct *vma)
{
    return 0;
}

static int open(struct inode * inode, struct file * file)
{
    return 0;
}

static int release(struct inode * inode, struct file * file)
{
    return 0;
}

struct file_operations bin_fops = {
	.read		= read,
	.write		= write,
	.mmap		= mmap,
	.llseek		= generic_file_llseek,
	.open		= open,
	.release	= release,
};