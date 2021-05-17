#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/pipe_fs_i.h>

static int fifo_open(struct inode *inode, struct file *filp)
{
    return 0;
}

struct file_operations def_fifo_fops = {
	.open		= fifo_open,	/* will set read or write pipe_fops */
};