#include <linux/pagemap.h>
#include "ext2.h"
#include "xattr.h"
#include "acl.h"

static inline void ext2_inc_count(struct inode *inode)
{
	inode->i_nlink++;
	mark_inode_dirty(inode);
}

static inline int ext2_add_nondir(struct dentry *dentry, struct inode *inode)
{
    panic("in ext2_add_nondir");
    return 0;
}

static struct dentry *ext2_lookup(struct inode * dir, struct dentry *dentry, struct nameidata *nd)
{
    panic("in ext2_lookup");
    return NULL;
}

struct dentry *ext2_get_parent(struct dentry *child)
{
    panic("in ext2_get_parent");
    return NULL;
}

static int ext2_create (struct inode * dir, struct dentry * dentry, int mode, struct nameidata *nd)
{
    panic("in ext2_create");
    return 0;
}

static int ext2_mknod (struct inode * dir, struct dentry *dentry, int mode, dev_t rdev)
{
    panic("in ext2_mknod");
    return 0;
}

static int ext2_symlink (struct inode * dir, struct dentry * dentry,
	const char * symname)
{
    panic("in ext2_symlink");
    return 0;
}

static int ext2_link (struct dentry * old_dentry, struct inode * dir,
	struct dentry *dentry)
{
    panic("in ext2_link");
    return 0;
}

static int ext2_mkdir(struct inode * dir, struct dentry * dentry, int mode)
{
    panic("in ext2_mkdir");
    return 0;
}

static int ext2_unlink(struct inode * dir, struct dentry *dentry)
{
    panic("in ext2_unlink");
    return 0;
}

static int ext2_rmdir (struct inode * dir, struct dentry *dentry)
{
    panic("in ext2_rmdir");
    return 0;
}

static int ext2_rename (struct inode * old_dir, struct dentry * old_dentry,
	struct inode * new_dir,	struct dentry * new_dentry )
{
    panic("in ext2_rename");
    return 0;
}

struct inode_operations ext2_dir_inode_operations = {
	.create		= ext2_create,
	.lookup		= ext2_lookup,
	.link		= ext2_link,
	.unlink		= ext2_unlink,
	.symlink	= ext2_symlink,
	.mkdir		= ext2_mkdir,
	.rmdir		= ext2_rmdir,
	.mknod		= ext2_mknod,
	.rename		= ext2_rename,
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.setattr	= ext2_setattr,
	.permission	= ext2_permission,
};

struct inode_operations ext2_special_inode_operations = {
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.setattr	= ext2_setattr,
	.permission	= ext2_permission,
};