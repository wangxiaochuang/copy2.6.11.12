#include "ext2.h"
#include "xattr.h"
#include <linux/namei.h>

static int ext2_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	panic("in ext2_follow_link");
	return 0;
}

struct inode_operations ext2_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
};

struct inode_operations ext2_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= ext2_follow_link,
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
};