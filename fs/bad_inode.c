#include <linux/fs.h>
#include <linux/module.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/smp_lock.h>
#include <linux/namei.h>

static int bad_follow_link(struct dentry *dent, struct nameidata *nd)
{
	nd_set_link(nd, ERR_PTR(-EIO));
	return 0;
}

static int return_EIO(void)
{
	return -EIO;
}

#define EIO_ERROR ((void *) (return_EIO))

static struct file_operations bad_file_ops =
{
	.llseek		= EIO_ERROR,
	.aio_read	= EIO_ERROR,
	.read		= EIO_ERROR,
	.write		= EIO_ERROR,
	.aio_write	= EIO_ERROR,
	.readdir	= EIO_ERROR,
	.poll		= EIO_ERROR,
	.ioctl		= EIO_ERROR,
	.mmap		= EIO_ERROR,
	.open		= EIO_ERROR,
	.flush		= EIO_ERROR,
	.release	= EIO_ERROR,
	.fsync		= EIO_ERROR,
	.aio_fsync	= EIO_ERROR,
	.fasync		= EIO_ERROR,
	.lock		= EIO_ERROR,
	.readv		= EIO_ERROR,
	.writev		= EIO_ERROR,
	.sendfile	= EIO_ERROR,
	.sendpage	= EIO_ERROR,
	.get_unmapped_area = EIO_ERROR,
};

struct inode_operations bad_inode_ops =
{
	.create		= EIO_ERROR,
	.lookup		= EIO_ERROR,
	.link		= EIO_ERROR,
	.unlink		= EIO_ERROR,
	.symlink	= EIO_ERROR,
	.mkdir		= EIO_ERROR,
	.rmdir		= EIO_ERROR,
	.mknod		= EIO_ERROR,
	.rename		= EIO_ERROR,
	.readlink	= EIO_ERROR,
	.follow_link	= bad_follow_link,
	.truncate	= EIO_ERROR,
	.permission	= EIO_ERROR,
	.getattr	= EIO_ERROR,
	.setattr	= EIO_ERROR,
	.setxattr	= EIO_ERROR,
	.getxattr	= EIO_ERROR,
	.listxattr	= EIO_ERROR,
	.removexattr	= EIO_ERROR,
};

void make_bad_inode(struct inode * inode) 
{
	remove_inode_hash(inode);

	inode->i_mode = S_IFREG;
	inode->i_atime = inode->i_mtime = inode->i_ctime =
		current_fs_time(inode->i_sb);
	inode->i_op = &bad_inode_ops;	
	inode->i_fop = &bad_file_ops;	
}
EXPORT_SYMBOL(make_bad_inode);

int is_bad_inode(struct inode * inode) 
{
	return (inode->i_op == &bad_inode_ops);	
}

EXPORT_SYMBOL(is_bad_inode);