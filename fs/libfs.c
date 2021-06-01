#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/mount.h>
#include <linux/vfs.h>
#include <asm/uaccess.h>

int simple_getattr(struct vfsmount *mnt, struct dentry *dentry,
		   struct kstat *stat)
{
	return 0;
}

int simple_statfs(struct super_block *sb, struct kstatfs *buf)
{
	buf->f_type = sb->s_magic;
	buf->f_bsize = PAGE_CACHE_SIZE;
	buf->f_namelen = NAME_MAX;
	return 0;
}

static int simple_delete_dentry(struct dentry *dentry)
{
	return 1;
}

struct dentry *simple_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd)
{
	static struct dentry_operations simple_dentry_operations = {
		.d_delete = simple_delete_dentry,
	};

	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);
	dentry->d_op = &simple_dentry_operations;
	d_add(dentry, NULL);
	return NULL;
}

int simple_sync_file(struct file * file, struct dentry *dentry, int datasync)
{
	return 0;
}

int dcache_dir_open(struct inode *inode, struct file *file)
{
	return 0;
}

int dcache_dir_close(struct inode *inode, struct file *file)
{
	return 0;
}

loff_t dcache_dir_lseek(struct file *file, loff_t offset, int origin)
{
	return 0;
}

int dcache_readdir(struct file * filp, void * dirent, filldir_t filldir)
{
	return 0;
}

ssize_t generic_read_dir(struct file *filp, char __user *buf, size_t siz, loff_t *ppos)
{
	return -EISDIR;
}

struct file_operations simple_dir_operations = {
	.open		= dcache_dir_open,
	.release	= dcache_dir_close,
	.llseek		= dcache_dir_lseek,
	.read		= generic_read_dir,
	.readdir	= dcache_readdir,
};

struct inode_operations simple_dir_inode_operations = {
	.lookup		= simple_lookup,
};

/*
 * Common helper for pseudo-filesystems (sockfs, pipefs, bdev - stuff that
 * will never be mountable)
 */
struct super_block *
get_sb_pseudo(struct file_system_type *fs_type, char *name,
	struct super_operations *ops, unsigned long magic)
{
	struct super_block *s = sget(fs_type, NULL, set_anon_super, NULL);
	static struct super_operations default_ops = {.statfs = simple_statfs};
	struct dentry *dentry;
	struct inode *root;
	struct qstr d_name = {.name = name, .len = strlen(name)};

	if (IS_ERR(s))
		return s;

	s->s_flags = MS_NOUSER;
	s->s_maxbytes = ~0ULL;
	s->s_blocksize = 1024;
	s->s_blocksize_bits = 10;
	s->s_magic = magic;
	s->s_op = ops ? ops : &default_ops;
	s->s_time_gran = 1;
	root = new_inode(s);
	if (!root)
		goto Enomem;
	root->i_mode = S_IFDIR | S_IRUSR | S_IWUSR;
	root->i_uid = root->i_gid = 0;
	root->i_atime = root->i_mtime = root->i_ctime = CURRENT_TIME;
	dentry = d_alloc(NULL, &d_name);
	if (!dentry) {
		iput(root);
		goto Enomem;
	}
	dentry->d_sb = s;
	dentry->d_parent = dentry;
	d_instantiate(dentry, root);
	s->s_root = dentry;
	s->s_flags |= MS_ACTIVE;
	return s;

Enomem:
	up_write(&s->s_umount);
	deactivate_super(s);
	return ERR_PTR(-ENOMEM);
}

int simple_link(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;

	inode->i_ctime = dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	inode->i_nlink++;
	atomic_inc(&inode->i_count);
	dget(dentry);
	d_instantiate(dentry, inode);
	return 0;
}

static inline int simple_positive(struct dentry *dentry)
{
	return dentry->d_inode && !d_unhashed(dentry);
}

int simple_empty(struct dentry *dentry)
{
	struct dentry *child;
	int ret = 0;

	spin_lock(&dcache_lock);
	list_for_each_entry(child, &dentry->d_subdirs, d_child)
		if (simple_positive(child))
			goto out;
	ret = 1;
out:
	spin_unlock(&dcache_lock);
	return ret;
}

int simple_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	inode->i_ctime = dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	inode->i_nlink--;
	dput(dentry);
	return 0;
}

int simple_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (!simple_empty(dentry))
		return -ENOTEMPTY;

	dentry->d_inode->i_nlink--;
	simple_unlink(dir, dentry);
	dir->i_nlink--;
	return 0;
}

int simple_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	return 0;
}

int simple_readpage(struct file *file, struct page *page)
{
	panic("in simple_readpage function");
	return 0;
}

int simple_prepare_write(struct file *file, struct page *page,
			unsigned from, unsigned to)
{
	panic("in simple_prepare_write function");
	return 0;
}

int simple_commit_write(struct file *file, struct page *page,
			unsigned offset, unsigned to)
{
	panic("in simple_commit_write function");
	return 0;
}