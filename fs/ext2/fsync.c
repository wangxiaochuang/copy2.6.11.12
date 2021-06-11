#include "ext2.h"
#include <linux/smp_lock.h>
#include <linux/buffer_head.h>		/* for fsync_inode_buffers() */


/*
 *	File may be NULL when we are called. Perhaps we shouldn't
 *	even pass file to fsync ?
 */

int ext2_sync_file(struct file *file, struct dentry *dentry, int datasync)
{
	panic("in ext2_sync_file");
	return 0;
}