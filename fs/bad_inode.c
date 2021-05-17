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

int is_bad_inode(struct inode * inode) 
{
	return (inode->i_op == &bad_inode_ops);	
}

EXPORT_SYMBOL(is_bad_inode);