#include <linux/config.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/acct.h>
#include <linux/blkdev.h>
#include <linux/quotaops.h>
#include <linux/namei.h>
#include <linux/buffer_head.h>		/* for fsync_super() */
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/vfs.h>
#include <linux/writeback.h>		/* for the emergency remount stuff */
#include <linux/idr.h>
#include <linux/kobject.h>
#include <asm/uaccess.h>

void get_filesystem(struct file_system_type *fs);
void put_filesystem(struct file_system_type *fs);
struct file_system_type *get_fs_type(const char *name);

LIST_HEAD(super_blocks);
DEFINE_SPINLOCK(sb_lock);

static struct super_block *alloc_super(void)
{
	struct super_block *s = kmalloc(sizeof(struct super_block),  GFP_USER);
	static struct super_operations default_op;

	if (s) {
		memset(s, 0, sizeof(struct super_block));
		if (security_sb_alloc(s)) {
			kfree(s);
			s = NULL;
			goto out;
		}
		INIT_LIST_HEAD(&s->s_dirty);
		INIT_LIST_HEAD(&s->s_io);
		INIT_LIST_HEAD(&s->s_files);
		INIT_LIST_HEAD(&s->s_instances);
		INIT_HLIST_HEAD(&s->s_anon);
		INIT_LIST_HEAD(&s->s_inodes);
		init_rwsem(&s->s_umount);
		sema_init(&s->s_lock, 1);
		down_write(&s->s_umount);
		s->s_count = S_BIAS;
		atomic_set(&s->s_active, 1);
		sema_init(&s->s_vfs_rename_sem,1);
		sema_init(&s->s_dquot.dqio_sem, 1);
		sema_init(&s->s_dquot.dqonoff_sem, 1);
		init_rwsem(&s->s_dquot.dqptr_sem);
		init_waitqueue_head(&s->s_wait_unfrozen);
		s->s_maxbytes = MAX_NON_LFS;
		s->dq_op = sb_dquot_ops;
		s->s_qcop = sb_quotactl_ops;
		s->s_op = &default_op;
		s->s_time_gran = 1000000000;
	}
out:
	return s;
}

static inline void destroy_super(struct super_block *s)
{
	security_sb_free(s);
	kfree(s);
}

int __put_super(struct super_block *sb)
{
	int ret = 0;

	if (!--sb->s_count) {
		destroy_super(sb);
		ret = 1;
	}
	return ret;
}

int __put_super_and_need_restart(struct super_block *sb)
{
	/* check for race with generic_shutdown_super() */
	if (list_empty(&sb->s_list)) {
		/* super block is removed, need to restart... */
		__put_super(sb);
		return 1;
	}
	/* can't be the last, since s_list is still in use */
	sb->s_count--;
	BUG_ON(sb->s_count == 0);
	return 0;
}

static void put_super(struct super_block *sb)
{
	spin_lock(&sb_lock);
	__put_super(sb);
	spin_unlock(&sb_lock);
}

void deactivate_super(struct super_block *s)
{
	struct file_system_type *fs = s->s_type;
	if (atomic_dec_and_lock(&s->s_active, &sb_lock)) {
		s->s_count -= S_BIAS-1;
		spin_unlock(&sb_lock);
		down_write(&s->s_umount);
		fs->kill_sb(s);
		put_filesystem(fs);
		put_super(s);
	}
}

EXPORT_SYMBOL(deactivate_super);

static int grab_super(struct super_block *s)
{
	s->s_count++;
	spin_unlock(&sb_lock);
	down_write(&s->s_umount);
	if (s->s_root) {
		spin_lock(&sb_lock);
		if (s->s_count > S_BIAS) {
			atomic_inc(&s->s_active);
			s->s_count--;
			spin_unlock(&sb_lock);
			return 1;
		}
		spin_unlock(&sb_lock);
	}
	up_write(&s->s_umount);
	put_super(s);
	yield();
	return 0;
}

void generic_shutdown_super(struct super_block *sb)
{
	struct dentry *root = sb->s_root;
	struct super_operations *sop = sb->s_op;

	if (root) {
		sb->s_root = NULL;
		shrink_dcache_parent(root);
		shrink_dcache_anon(&sb->s_anon);
		dput(root);
		fsync_super(sb);
		lock_super(sb);
		sb->s_flags &= ~MS_ACTIVE;
		/* bad name - it should be evict_inodes() */
		invalidate_inodes(sb);
		lock_kernel();

		if (sop->write_super && sb->s_dirt)
			sop->write_super(sb);
		if (sop->put_super)
			sop->put_super(sb);

		/* Forget any remaining inodes */
		if (invalidate_inodes(sb)) {
			printk("VFS: Busy inodes after unmount. "
			   "Self-destruct in 5 seconds.  Have a nice day...\n");
		}

		unlock_kernel();
		unlock_super(sb);
	}
	spin_lock(&sb_lock);
	/* should be initialized for __put_super_and_need_restart() */
	list_del_init(&sb->s_list);
	list_del(&sb->s_instances);
	spin_unlock(&sb_lock);
	up_write(&sb->s_umount);
}

EXPORT_SYMBOL(generic_shutdown_super);

/**
 *	sget	-	find or create a superblock
 *	@type:	filesystem type superblock should belong to
 *	@test:	comparison callback
 *	@set:	setup callback
 *	@data:	argument to each of them
 */
struct super_block *sget(struct file_system_type *type,
			int (*test)(struct super_block *,void *),
			int (*set)(struct super_block *,void *),
			void *data)
{
	struct super_block *s = NULL;
	struct list_head *p;
	int err;

retry:
	spin_lock(&sb_lock);
	if (test) list_for_each(p, &type->fs_supers) {
		struct super_block *old;
		old = list_entry(p, struct super_block, s_instances);
		if (!test(old, data))
			continue;
		if (!grab_super(old))
			goto retry;
		if (s)
			destroy_super(s);
		return old;
	}
	if (!s) {
		spin_unlock(&sb_lock);
		s = alloc_super();
		if (!s)
			return ERR_PTR(-ENOMEM);
		goto retry;
	}

	err = set(s, data);
	if (err) {
		spin_unlock(&sb_lock);
		destroy_super(s);
		return ERR_PTR(err);
	}
	s->s_type = type;
	strlcpy(s->s_id, type->name, sizeof(s->s_id));
	list_add_tail(&s->s_list, &super_blocks);
	list_add(&s->s_instances, &type->fs_supers);
	spin_unlock(&sb_lock);
	get_filesystem(type);
	return s;
}

EXPORT_SYMBOL(sget);

void drop_super(struct super_block *sb)
{
	up_read(&sb->s_umount);
	put_super(sb);
}


struct super_block * get_super(struct block_device *bdev)
{
	struct list_head *p;
	if (!bdev)
		return NULL;
rescan:
	spin_lock(&sb_lock);
	list_for_each(p, &super_blocks) {
		struct super_block *s = sb_entry(p);
		if (s->s_bdev == bdev) {
			s->s_count++;
			spin_unlock(&sb_lock);
			down_read(&s->s_umount);
			if (s->s_root)
				return s;
			drop_super(s);
			goto rescan;
		}
	}
	spin_unlock(&sb_lock);
	return NULL;
}

EXPORT_SYMBOL(get_super);
 
struct super_block * user_get_super(dev_t dev)
{
	panic("in user_get_super");
	return NULL;
}

EXPORT_SYMBOL(user_get_super);

asmlinkage long sys_ustat(unsigned dev, struct ustat __user * ubuf)
{
	panic("in sys_ustat");
}

static void mark_files_ro(struct super_block *sb)
{
	struct file *f;

	file_list_lock();
	list_for_each_entry(f, &sb->s_files, f_list) {
		if (S_ISREG(f->f_dentry->d_inode->i_mode) && file_count(f))
			f->f_mode &= ~FMODE_WRITE;
	}
	file_list_unlock();
}

int do_remount_sb(struct super_block *sb, int flags, void *data, int force)
{
	int retval;
	
	if (!(flags & MS_RDONLY) && bdev_read_only(sb->s_bdev))
		return -EACCES;
	if (flags & MS_RDONLY)
		acct_auto_close(sb);
	shrink_dcache_sb(sb);
	fsync_super(sb);

	if ((flags & MS_RDONLY) && !(sb->s_flags & MS_RDONLY)) {
		if (force)
			mark_files_ro(sb);
		else if (!fs_may_remount_ro(sb))
			return -EBUSY;
	}

	if (sb->s_op->remount_fs) {
		lock_super(sb);
		retval = sb->s_op->remount_fs(sb, &flags, data);
		unlock_super(sb);
		if (retval)
			return retval;
	}
	sb->s_flags = (sb->s_flags & ~MS_RMT_MASK) | (flags & MS_RMT_MASK);
	return 0;
}

/*
 * Unnamed block devices are dummy devices used by virtual
 * filesystems which don't use real block-devices.  -- jrs
 */

static struct idr unnamed_dev_idr;
static DEFINE_SPINLOCK(unnamed_dev_lock);/* protects the above */

int set_anon_super(struct super_block *s, void *data)
{
	int dev;
	int error;
retry:
	if (idr_pre_get(&unnamed_dev_idr, GFP_ATOMIC) == 0)
		return -ENOMEM;
	spin_lock(&unnamed_dev_lock);
	error = idr_get_new(&unnamed_dev_idr, NULL, &dev);
	spin_unlock(&unnamed_dev_lock);
	if (error == -EAGAIN)
		/* We raced and lost with another CPU. */
		goto retry;
	else if (error)
		return -EAGAIN;

	if ((dev & MAX_ID_MASK) == (1 << MINORBITS)) {
		spin_lock(&unnamed_dev_lock);
		idr_remove(&unnamed_dev_idr, dev);
		spin_unlock(&unnamed_dev_lock);
		return -EMFILE;
	}
	s->s_dev = MKDEV(0, dev & MINORMASK);
	return 0;
}

EXPORT_SYMBOL(set_anon_super);

void kill_anon_super(struct super_block *sb)
{
	int slot = MINOR(sb->s_dev);

	generic_shutdown_super(sb);
	spin_lock(&unnamed_dev_lock);
	idr_remove(&unnamed_dev_idr, slot);
	spin_unlock(&unnamed_dev_lock);
}

EXPORT_SYMBOL(kill_anon_super);

void __init unnamed_dev_init(void)
{
	idr_init(&unnamed_dev_idr);
}

void kill_litter_super(struct super_block *sb)
{
	if (sb->s_root)
		d_genocide(sb->s_root);
	kill_anon_super(sb);
}

EXPORT_SYMBOL(kill_litter_super);

static int set_bdev_super(struct super_block *s, void *data)
{
	s->s_bdev = data;
	s->s_dev = s->s_bdev->bd_dev;
	return 0;
}

static int test_bdev_super(struct super_block *s, void *data)
{
	return (void *)s->s_bdev == data;
}

static void bdev_uevent(struct block_device *bdev, enum kobject_action action)
{
	if (bdev->bd_disk) {
		if (bdev->bd_part)
			kobject_uevent(&bdev->bd_part->kobj, action, NULL);
		else
			kobject_uevent(&bdev->bd_disk->kobj, action, NULL);
	}
}

struct super_block *get_sb_bdev(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data,
	int (*fill_super)(struct super_block *, void *, int))
{
	struct block_device *bdev;
	struct super_block *s;
	int error = 0;

	bdev = open_bdev_excl(dev_name, flags, fs_type);
	if (IS_ERR(bdev))
		return (struct super_block *)bdev;

	down(&bdev->bd_mount_sem);
	s = sget(fs_type, test_bdev_super, set_bdev_super, bdev);
	up(&bdev->bd_mount_sem);
	if (IS_ERR(s))
		goto out;

	if (s->s_root) {
		if ((flags ^ s->s_flags) & MS_RDONLY) {
			up_write(&s->s_umount);
			deactivate_super(s);
			s = ERR_PTR(-EBUSY);
		}
		goto out;
	} else {
		char b[BDEVNAME_SIZE];

		s->s_flags = flags;
		strlcpy(s->s_id, bdevname(bdev, b), sizeof(s->s_id));
		s->s_old_blocksize = block_size(bdev);
		sb_set_blocksize(s, s->s_old_blocksize);
		error = fill_super(s, data, flags & MS_VERBOSE ? 1 : 0);
		if (error) {
			up_write(&s->s_umount);
			deactivate_super(s);
			s = ERR_PTR(error);
		} else {
			s->s_flags |= MS_ACTIVE;
			bdev_uevent(bdev, KOBJ_MOUNT);
		}
	}

	return s;

out:
	close_bdev_excl(bdev);
	return s;
}

EXPORT_SYMBOL(get_sb_bdev);

void kill_block_super(struct super_block *sb)
{
	struct block_device *bdev = sb->s_bdev;

	bdev_uevent(bdev, KOBJ_UMOUNT);
	generic_shutdown_super(sb);
	set_blocksize(bdev, sb->s_old_blocksize);
	close_bdev_excl(bdev);
}

struct super_block *get_sb_nodev(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int))
{
	int error;
	struct super_block *s = sget(fs_type, NULL, set_anon_super, NULL);

	if (IS_ERR(s))
		return s;

	s->s_flags = flags;

	error = fill_super(s, data, flags & MS_VERBOSE ? 1 : 0);
	if (error) {
		up_write(&s->s_umount);
		deactivate_super(s);
		return ERR_PTR(error);
	}
	s->s_flags |= MS_ACTIVE;
	return s;
}

EXPORT_SYMBOL(get_sb_nodev);

static int compare_single(struct super_block *s, void *p)
{
	return 1;
}

struct super_block *get_sb_single(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int))
{
	struct super_block *s;
	int error;

	s = sget(fs_type, compare_single, set_anon_super, NULL);
	if (IS_ERR(s))
		return s;
	if (!s->s_root) {
		s->s_flags = flags;
		error = fill_super(s, data, flags & MS_VERBOSE ? 1 : 0);
		if (error) {
			up_write(&s->s_umount);
			deactivate_super(s);
			return ERR_PTR(error);
		}
		s->s_flags |= MS_ACTIVE;
	}
	do_remount_sb(s, flags, data, 0);
	return s;
}

EXPORT_SYMBOL(get_sb_single);

struct vfsmount *
do_kern_mount(const char *fstype, int flags, const char *name, void *data)
{
	struct file_system_type *type = get_fs_type(fstype);
	struct super_block *sb = ERR_PTR(-ENOMEM);
	struct vfsmount *mnt;
	int error;
	char *secdata = NULL;

	if (!type)
		return ERR_PTR(-ENODEV);

	mnt = alloc_vfsmnt(name);
	if (!mnt)
		goto out;

	if (data) {
		secdata = alloc_secdata();
		if (!secdata) {
			sb = ERR_PTR(-ENOMEM);
			goto out_mnt;
		}

		error = security_sb_copy_data(type, data, secdata);
		if (error) {
			sb = ERR_PTR(error);
			goto out_free_secdata;
		}
	}

	sb = type->get_sb(type, flags, name, data);
	if (IS_ERR(sb))
		goto out_free_secdata;
	error = security_sb_kern_mount(sb, secdata);
 	if (error)
 		goto out_sb;
	mnt->mnt_sb = sb;
	mnt->mnt_root = dget(sb->s_root);
	mnt->mnt_mountpoint = sb->s_root;
	mnt->mnt_parent = mnt;
	mnt->mnt_namespace = current->namespace;
	up_write(&sb->s_umount);
	put_filesystem(type);
	return mnt;
out_sb:
	up_write(&sb->s_umount);
	deactivate_super(sb);
	sb = ERR_PTR(error);
out_free_secdata:
	free_secdata(secdata);
out_mnt:
	free_vfsmnt(mnt);
out:
	put_filesystem(type);
	return (struct vfsmount *)sb;
}

struct vfsmount *kern_mount(struct file_system_type *type)
{
	return do_kern_mount(type->name, 0, type->name, NULL);
}

EXPORT_SYMBOL(kern_mount);