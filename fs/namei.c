#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/pagemap.h>
#include <linux/dnotify.h>
#include <linux/smp_lock.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <asm/namei.h>
#include <asm/uaccess.h>

int generic_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
    return 0;
}

int page_follow_link_light(struct dentry *dentry, struct nameidata *nd)
{
	return 0;
}

void page_put_link(struct dentry *dentry, struct nameidata *nd)
{
    panic("in page_put_link function");
}

int page_symlink(struct inode *inode, const char *symname, int len)
{
    return 0;
}

struct inode_operations page_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
};

EXPORT_SYMBOL(page_symlink_inode_operations);