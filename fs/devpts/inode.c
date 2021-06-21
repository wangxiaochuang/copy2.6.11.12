#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/tty.h>
#include <linux/devpts_fs.h>
#include <linux/xattr.h>

#define DEVPTS_SUPER_MAGIC 0x1cd1

extern struct xattr_handler devpts_xattr_security_handler;

static struct xattr_handler *devpts_xattr_handlers[] = {
#ifdef CONFIG_DEVPTS_FS_SECURITY
	&devpts_xattr_security_handler,
#endif
	NULL
};

static struct inode_operations devpts_file_inode_operations = {
#ifdef CONFIG_DEVPTS_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= generic_listxattr,
	.removexattr	= generic_removexattr,
#endif
};

static struct vfsmount *devpts_mnt;
static struct dentry *devpts_root;

static struct {
	int setuid;
	int setgid;
	uid_t   uid;
	gid_t   gid;
	umode_t mode;
} config = {.mode = 0600};

static int devpts_remount(struct super_block *sb, int *flags, char *data)
{
	int setuid = 0;
	int setgid = 0;
	uid_t uid = 0;
	gid_t gid = 0;
	umode_t mode = 0600;
	char *this_char;

	this_char = NULL;
	while ((this_char = strsep(&data, ",")) != NULL) {
		int n;
		char dummy;
		if (!*this_char)
			continue;
		if (sscanf(this_char, "uid=%i%c", &n, &dummy) == 1) {
			setuid = 1;
			uid = n;
		} else if (sscanf(this_char, "gid=%i%c", &n, &dummy) == 1) {
			setgid = 1;
			gid = n;
		} else if (sscanf(this_char, "mode=%o%c", &n, &dummy) == 1)
			mode = n & ~S_IFMT;
		else {
			printk("devpts: called with bogus options\n");
			return -EINVAL;
		}
	}
	config.setuid  = setuid;
	config.setgid  = setgid;
	config.uid     = uid;
	config.gid     = gid;
	config.mode    = mode;

	return 0;
}

static struct super_operations devpts_sops = {
	.statfs		= simple_statfs,
	.remount_fs	= devpts_remount,
};

static int
devpts_fill_super(struct super_block *s, void *data, int silent)
{
	struct inode * inode;

	s->s_blocksize = 1024;
	s->s_blocksize_bits = 10;
	s->s_magic = DEVPTS_SUPER_MAGIC;
	s->s_op = &devpts_sops;
	s->s_xattr = devpts_xattr_handlers;
	s->s_time_gran = 1;

	inode = new_inode(s);
	if (!inode)
		goto fail;
	inode->i_ino = 1;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	inode->i_blocks = 0;
	inode->i_blksize = 1024;
	inode->i_uid = inode->i_gid = 0;
	inode->i_mode = S_IFDIR | S_IRUGO | S_IXUGO | S_IWUSR;
	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;
	inode->i_nlink = 2;

	devpts_root = s->s_root = d_alloc_root(inode);
	if (s->s_root)
		return 0;
	
	printk("devpts: get root dentry failed\n");
	iput(inode);
fail:
	return -ENOMEM;
}

static struct super_block *devpts_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return get_sb_single(fs_type, flags, data, devpts_fill_super);
}

static struct file_system_type devpts_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "devpts",
	.get_sb		= devpts_get_sb,
	.kill_sb	= kill_anon_super,
};

static struct dentry *get_node(int num)
{
	char s[12];
	struct dentry *root = devpts_root;
	down(&root->d_inode->i_sem);
	return lookup_one_len(s, root, sprintf(s, "%d", num));
}

int devpts_pty_new(struct tty_struct *tty)
{
	panic("in devpts_pty_new");
	return 0;
}

struct tty_struct *devpts_get_tty(int number)
{
	struct dentry *dentry = get_node(number);
	struct tty_struct *tty;

	tty = NULL;
	if (!IS_ERR(dentry)) {
		if (dentry->d_inode)
			tty = dentry->d_inode->u.generic_ip;
		dput(dentry);
	}

	up(&devpts_root->d_inode->i_sem);

	return tty;
}

void devpts_pty_kill(int number)
{
	struct dentry *dentry = get_node(number);

	if (!IS_ERR(dentry)) {
		struct inode *inode = dentry->d_inode;
		if (inode) {
			inode->i_nlink--;
			d_delete(dentry);
			dput(dentry);
		}
		dput(dentry);
	}
	up(&devpts_root->d_inode->i_sem);
}

static int __init init_devpts_fs(void)
{
	int err = register_filesystem(&devpts_fs_type);
	if (!err) {
		devpts_mnt = kern_mount(&devpts_fs_type);
		if (IS_ERR(devpts_mnt))
			err = PTR_ERR(devpts_mnt);
	}
	return err;
}

static void __exit exit_devpts_fs(void)
{
	unregister_filesystem(&devpts_fs_type);
	mntput(devpts_mnt);
}

module_init(init_devpts_fs)
module_exit(exit_devpts_fs)
MODULE_LICENSE("GPL");