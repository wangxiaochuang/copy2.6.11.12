#include <linux/config.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/quotaops.h>
#include <linux/acct.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/namespace.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

extern int __init init_rootfs(void);

#ifdef CONFIG_SYSFS
extern int __init sysfs_init(void);
#else
#error "!CONFIG_SYSFS"
#endif

/* spinlock for vfsmount related operations, inplace of dcache_lock */
 __cacheline_aligned_in_smp DEFINE_SPINLOCK(vfsmount_lock);

static struct list_head *mount_hashtable;
static int hash_mask, hash_bits;
static kmem_cache_t *mnt_cache;

static inline unsigned long hash(struct vfsmount *mnt, struct dentry *dentry)
{
	unsigned long tmp = ((unsigned long) mnt / L1_CACHE_BYTES);
	tmp += ((unsigned long) dentry / L1_CACHE_BYTES);
	tmp = tmp + (tmp >> hash_bits);
	return tmp & hash_mask;
}

struct vfsmount *alloc_vfsmnt(const char *name)
{
	struct vfsmount *mnt = kmem_cache_alloc(mnt_cache, GFP_KERNEL);
	if (mnt) {
		memset(mnt, 0, sizeof(struct vfsmount));
		atomic_set(&mnt->mnt_count, 1);
		INIT_LIST_HEAD(&mnt->mnt_hash);
		INIT_LIST_HEAD(&mnt->mnt_child);
		INIT_LIST_HEAD(&mnt->mnt_mounts);
		INIT_LIST_HEAD(&mnt->mnt_list);
		INIT_LIST_HEAD(&mnt->mnt_fslink);
		if (name) {
			int size = strlen(name)+1;
			char *newname = kmalloc(size, GFP_KERNEL);
			if (newname) {
				memcpy(newname, name, size);
				mnt->mnt_devname = newname;
			}
		}
	}
	return mnt;
}

void free_vfsmnt(struct vfsmount *mnt)
{
	kfree(mnt->mnt_devname);
	kmem_cache_free(mnt_cache, mnt);
}

struct vfsmount *lookup_mnt(struct vfsmount *mnt, struct dentry *dentry)
{
	struct list_head *head = mount_hashtable + hash(mnt, dentry);
	struct list_head *tmp = head;
	struct vfsmount *p, *found = NULL;

	spin_lock(&vfsmount_lock);
	for (;;) {
		tmp = tmp->next;
		p = NULL;
		if (tmp == head)
			break;
		p = list_entry(tmp, struct vfsmount, mnt_hash);
		if (p->mnt_parent == mnt && p->mnt_mountpoint == dentry) {
			found = mntget(p);
			break;
		}
	}
	spin_unlock(&vfsmount_lock);
	return found;
}

static inline int check_mnt(struct vfsmount *mnt)
{
	return mnt->mnt_namespace == current->namespace;
}

static void detach_mnt(struct vfsmount *mnt, struct nameidata *old_nd)
{
	old_nd->dentry = mnt->mnt_mountpoint;
	old_nd->mnt = mnt->mnt_parent;
	mnt->mnt_parent = mnt;
	mnt->mnt_mountpoint = mnt->mnt_root;
	list_del_init(&mnt->mnt_child);
	list_del_init(&mnt->mnt_hash);
	old_nd->dentry->d_mounted--;
}

static void attach_mnt(struct vfsmount *mnt, struct nameidata *nd)
{
	mnt->mnt_parent = mntget(nd->mnt);
	mnt->mnt_mountpoint = dget(nd->dentry);
	list_add(&mnt->mnt_hash, mount_hashtable+hash(nd->mnt, nd->dentry));
	list_add_tail(&mnt->mnt_child, &nd->mnt->mnt_mounts);
	nd->dentry->d_mounted++;
}

static struct vfsmount *next_mnt(struct vfsmount *p, struct vfsmount *root)
{
	struct list_head *next = p->mnt_mounts.next;
	if (next == &p->mnt_mounts) {
		while (1) {
			if (p == root)
				return NULL;
			next = p->mnt_child.next;
			if (next != &p->mnt_parent->mnt_mounts)
				break;
			p = p->mnt_parent;
		}
	}
	return list_entry(next, struct vfsmount, mnt_child);
}

static struct vfsmount *
clone_mnt(struct vfsmount *old, struct dentry *root)
{
	struct super_block *sb = old->mnt_sb;
	struct vfsmount *mnt = alloc_vfsmnt(old->mnt_devname);

	if (mnt) {
		mnt->mnt_flags = old->mnt_flags;
		atomic_inc(&sb->s_active);
		mnt->mnt_sb = sb;
		mnt->mnt_root = dget(root);
		mnt->mnt_mountpoint = mnt->mnt_root;
		mnt->mnt_parent = mnt;
		mnt->mnt_namespace = old->mnt_namespace;

		/* stick the duplicate mount on the same expiry list
		 * as the original if that was on one */
		spin_lock(&vfsmount_lock);
		if (!list_empty(&old->mnt_fslink))
			list_add(&mnt->mnt_fslink, &old->mnt_fslink);
		spin_unlock(&vfsmount_lock);
	}
	return mnt;
}

void __mntput(struct vfsmount *mnt)
{
	struct super_block *sb = mnt->mnt_sb;
	dput(mnt->mnt_root);
	free_vfsmnt(mnt);
	deactivate_super(sb);
}

EXPORT_SYMBOL(__mntput);


void umount_tree(struct vfsmount *mnt)
{
	struct vfsmount *p;
	LIST_HEAD(kill);

	for (p = mnt; p; p = next_mnt(p, mnt)) {
		list_del(&p->mnt_list);
		list_add(&p->mnt_list, &kill);
	}

	while (!list_empty(&kill)) {
		mnt = list_entry(kill.next, struct vfsmount, mnt_list);
		list_del_init(&mnt->mnt_list);
		list_del_init(&mnt->mnt_fslink);
		if (mnt->mnt_parent == mnt) {
			spin_unlock(&vfsmount_lock);
		} else {
			struct nameidata old_nd;
			detach_mnt(mnt, &old_nd);
			spin_unlock(&vfsmount_lock);
			path_release(&old_nd);
		}
		mntput(mnt);
		spin_lock(&vfsmount_lock);
	}
}

static int do_umount(struct vfsmount *mnt, int flags)
{
	struct super_block * sb = mnt->mnt_sb;
	int retval;

	retval = security_sb_umount(mnt, flags);
	if (retval)
		return retval;

	if (flags & MNT_EXPIRE) {
		if (mnt == current->fs->rootmnt ||
		    flags & (MNT_FORCE | MNT_DETACH))
			return -EINVAL;

		if (atomic_read(&mnt->mnt_count) != 2)
			return -EBUSY;

		if (!xchg(&mnt->mnt_expiry_mark, 1))
			return -EAGAIN;
	}

	lock_kernel();
	if( (flags&MNT_FORCE) && sb->s_op->umount_begin)
		sb->s_op->umount_begin(sb);
	unlock_kernel();

	if (mnt == current->fs->rootmnt && !(flags & MNT_DETACH)) {
		down_write(&sb->s_umount);
		if (!(sb->s_flags & MS_RDONLY)) {
			lock_kernel();
			DQUOT_OFF(sb);
			retval = do_remount_sb(sb, MS_RDONLY, NULL, 0);
			unlock_kernel();
		}
		up_write(&sb->s_umount);
		return retval;
	}

	down_write(&current->namespace->sem);
	spin_lock(&vfsmount_lock);

	if (atomic_read(&sb->s_active) == 1) {
		/* last instance - try to be smart */
		spin_unlock(&vfsmount_lock);
		lock_kernel();
		DQUOT_OFF(sb);
		acct_auto_close(sb);
		unlock_kernel();
		security_sb_umount_close(mnt);
		spin_lock(&vfsmount_lock);
	}
	retval = -EBUSY;
	if (atomic_read(&mnt->mnt_count) == 2 || flags & MNT_DETACH) {
		if (!list_empty(&mnt->mnt_list))
			umount_tree(mnt);
		retval = 0;
	}
	spin_unlock(&vfsmount_lock);
	if (retval)
		security_sb_umount_busy(mnt);
	up_write(&current->namespace->sem);
	return retval;
}

asmlinkage long sys_umount(char __user * name, int flags)
{
	struct nameidata nd;
	int retval;

	retval = __user_walk(name, LOOKUP_FOLLOW, &nd);
	if (retval)
		goto out;
	retval = -EINVAL;
	if (nd.dentry != nd.mnt->mnt_root)
		goto dput_and_out;
	if (!check_mnt(nd.mnt))
		goto dput_and_out;

	retval = -EPERM;
	if (!capable(CAP_SYS_ADMIN))
		goto dput_and_out;

	retval = do_umount(nd.mnt, flags);
dput_and_out:
	path_release_on_umount(&nd);
out:
	return retval;
}

#ifdef __ARCH_WANT_SYS_OLDUMOUNT

asmlinkage long sys_oldumount(char __user * name)
{
	return sys_umount(name,0);
}

#endif

static int mount_is_safe(struct nameidata *nd)
{
	if (capable(CAP_SYS_ADMIN))
		return 0;
	return -EPERM;
}

static int
lives_below_in_same_fs(struct dentry *d, struct dentry *dentry)
{
	while (1) {
		if (d == dentry)
			return 1;
		if (d == NULL || d == d->d_parent)
			return 0;
		d = d->d_parent;
	}
}

static struct vfsmount *copy_tree(struct vfsmount *mnt, struct dentry *dentry)
{
	struct vfsmount *res, *p, *q, *r, *s;
	struct list_head *h;
	struct nameidata nd;

	res = q = clone_mnt(mnt, dentry);
	if (!q)
		goto Enomem;
	q->mnt_mountpoint = mnt->mnt_mountpoint;

	p = mnt;
	for (h = mnt->mnt_mounts.next; h != &mnt->mnt_mounts; h = h->next) {
		r = list_entry(h, struct vfsmount, mnt_child);
		if (!lives_below_in_same_fs(r->mnt_mountpoint, dentry))
			continue;

		for (s = r; s; s = next_mnt(s, r)) {
			while (p != s->mnt_parent) {
				p = p->mnt_parent;
				q = q->mnt_parent;
			}
			p = s;
			nd.mnt = q;
			nd.dentry = p->mnt_mountpoint;
			q = clone_mnt(p, p->mnt_root);
			if (!q)
				goto Enomem;
			spin_lock(&vfsmount_lock);
			list_add_tail(&q->mnt_list, &res->mnt_list);
			attach_mnt(q, &nd);
			spin_unlock(&vfsmount_lock);
		}
	}
	return res;
 Enomem:
	if (res) {
		spin_lock(&vfsmount_lock);
		umount_tree(res);
		spin_unlock(&vfsmount_lock);
	}
	return NULL;
}

static int graft_tree(struct vfsmount *mnt, struct nameidata *nd)
{
	int err;
	if (mnt->mnt_sb->s_flags & MS_NOUSER)
		return -EINVAL;

	if (S_ISDIR(nd->dentry->d_inode->i_mode) !=
	      S_ISDIR(mnt->mnt_root->d_inode->i_mode))
		return -ENOTDIR;

	err = -ENOENT;
	down(&nd->dentry->d_inode->i_sem);
	if (IS_DEADDIR(nd->dentry->d_inode))
		goto out_unlock;

	err = security_sb_check_sb(mnt, nd);
	if (err)
		goto out_unlock;

	err = -ENOENT;
	spin_lock(&vfsmount_lock);
	if (IS_ROOT(nd->dentry) || !d_unhashed(nd->dentry)) {
		struct list_head head;

		attach_mnt(mnt, nd);
		list_add_tail(&head, &mnt->mnt_list);
		list_splice(&head, current->namespace->list.prev);
		mntget(mnt);
		err = 0;
	}
	spin_unlock(&vfsmount_lock);
out_unlock:
	up(&nd->dentry->d_inode->i_sem);
	if (!err)
		security_sb_post_addmount(mnt, nd);
	return err;
}

static int do_loopback(struct nameidata *nd, char *old_name, int recurse)
{
	struct nameidata old_nd;
	struct vfsmount *mnt = NULL;
	int err = mount_is_safe(nd);
	if (err)
		return err;
	if (!old_name || !*old_name)
		return -EINVAL;
	err = path_lookup(old_name, LOOKUP_FOLLOW, &old_nd);
	if (err)
		return err;

	down_write(&current->namespace->sem);
	err = -EINVAL;
	if (check_mnt(nd->mnt) && (!recurse || check_mnt(old_nd.mnt))) {
		err = -ENOMEM;
		if (recurse)
			mnt = copy_tree(old_nd.mnt, old_nd.dentry);
		else
			mnt = clone_mnt(old_nd.mnt, old_nd.dentry);
	}

	if (mnt) {
		/* stop bind mounts from expiring */
		spin_lock(&vfsmount_lock);
		list_del_init(&mnt->mnt_fslink);
		spin_unlock(&vfsmount_lock);

		err = graft_tree(mnt, nd);
		if (err) {
			spin_lock(&vfsmount_lock);
			umount_tree(mnt);
			spin_unlock(&vfsmount_lock);
		} else
			mntput(mnt);
	}

	up_write(&current->namespace->sem);
	path_release(&old_nd);
	return err;
}

static int do_remount(struct nameidata *nd, int flags, int mnt_flags,
		      void *data)
{
	int err;
	struct super_block * sb = nd->mnt->mnt_sb;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!check_mnt(nd->mnt))
		return -EINVAL;

	if (nd->dentry != nd->mnt->mnt_root)
		return -EINVAL;

	down_write(&sb->s_umount);
	err = do_remount_sb(sb, flags, data, 0);
	if (!err)
		nd->mnt->mnt_flags=mnt_flags;
	up_write(&sb->s_umount);
	if (!err)
		security_sb_post_remount(nd->mnt, flags, data);
	return err;
}

static int do_move_mount(struct nameidata *nd, char *old_name)
{
	struct nameidata old_nd, parent_nd;
	struct vfsmount *p;
	int err = 0;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!old_name || !*old_name)
		return -EINVAL;
	err = path_lookup(old_name, LOOKUP_FOLLOW, &old_nd);
	if (err)
		return err;

	down_write(&current->namespace->sem);
	while(d_mountpoint(nd->dentry) && follow_down(&nd->mnt, &nd->dentry))
		;
	err = -EINVAL;
	if (!check_mnt(nd->mnt) || !check_mnt(old_nd.mnt))
		goto out;

	err = -ENOENT;
	down(&nd->dentry->d_inode->i_sem);
	if (IS_DEADDIR(nd->dentry->d_inode))
		goto out1;

	spin_lock(&vfsmount_lock);
	if (!IS_ROOT(nd->dentry) && d_unhashed(nd->dentry))
		goto out2;

	err = -EINVAL;
	if (old_nd.dentry != old_nd.mnt->mnt_root)
		goto out2;

	if (old_nd.mnt == old_nd.mnt->mnt_parent)
		goto out2;

	if (S_ISDIR(nd->dentry->d_inode->i_mode) !=
	      S_ISDIR(old_nd.dentry->d_inode->i_mode))
		goto out2;

	err = -ELOOP;
	for (p = nd->mnt; p->mnt_parent!=p; p = p->mnt_parent)
		if (p == old_nd.mnt)
			goto out2;
	err = 0;

	detach_mnt(old_nd.mnt, &parent_nd);
	attach_mnt(old_nd.mnt, nd);

	/* if the mount is moved, it should no longer be expire
	 * automatically */
	list_del_init(&old_nd.mnt->mnt_fslink);
out2:
	spin_unlock(&vfsmount_lock);
out1:
	up(&nd->dentry->d_inode->i_sem);
out:
	up_write(&current->namespace->sem);
	if (!err)
		path_release(&parent_nd);
	path_release(&old_nd);
	return err;
}

static int do_new_mount(struct nameidata *nd, char *type, int flags,
			int mnt_flags, char *name, void *data)
{
	struct vfsmount *mnt;

	if (!type || !memchr(type, 0, PAGE_SIZE))
		return -EINVAL;

	/* we need capabilities... */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	mnt = do_kern_mount(type, flags, name, data);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	return do_add_mount(mnt, nd, mnt_flags, NULL);
}

int do_add_mount(struct vfsmount *newmnt, struct nameidata *nd,
		 int mnt_flags, struct list_head *fslist)
{
	int err;

	down_write(&current->namespace->sem);
	/* Something was mounted here while we slept */
	while(d_mountpoint(nd->dentry) && follow_down(&nd->mnt, &nd->dentry))
		;
	err = -EINVAL;
	if (!check_mnt(nd->mnt))
		goto unlock;

	/* Refuse the same filesystem on the same mount point */
	err = -EBUSY;
	if (nd->mnt->mnt_sb == newmnt->mnt_sb &&
	    nd->mnt->mnt_root == nd->dentry)
		goto unlock;

	err = -EINVAL;
	if (S_ISLNK(newmnt->mnt_root->d_inode->i_mode))
		goto unlock;

	newmnt->mnt_flags = mnt_flags;
	err = graft_tree(newmnt, nd);

	if (err == 0 && fslist) {
		/* add to the specified expiration list */
		spin_lock(&vfsmount_lock);
		list_add_tail(&newmnt->mnt_fslink, fslist);
		spin_unlock(&vfsmount_lock);
	}

unlock:
	up_write(&current->namespace->sem);
	mntput(newmnt);
	return err;
}

EXPORT_SYMBOL_GPL(do_add_mount);

static long
exact_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	char *t = to;
	const char __user *f = from;
	char c;

	if (!access_ok(VERIFY_READ, from, n))
		return n;

	while (n) {
		if (__get_user(c, f)) {
			memset(t, 0, n);
			break;
		}
		*t++ = c;
		f++;
		n--;
	}
	return n;
}

int copy_mount_options(const void __user *data, unsigned long *where)
{
	int i;
	unsigned long page;
	unsigned long size;
	
	*where = 0;
	if (!data)
		return 0;

	if (!(page = __get_free_page(GFP_KERNEL)))
		return -ENOMEM;

	/* We only care that *some* data at the address the user
	 * gave us is valid.  Just in case, we'll zero
	 * the remainder of the page.
	 */
	/* copy_from_user cannot cross TASK_SIZE ! */
	size = TASK_SIZE - (unsigned long)data;
	if (size > PAGE_SIZE)
		size = PAGE_SIZE;

	i = size - exact_copy_from_user((void *)page, data, size);
	if (!i) {
		free_page(page); 
		return -EFAULT;
	}
	if (i != PAGE_SIZE)
		memset((char *)page + i, 0, PAGE_SIZE - i);
	*where = page;
	return 0;
}

long do_mount(char * dev_name, char * dir_name, char *type_page,
		  unsigned long flags, void *data_page)
{
	struct nameidata nd;
	int retval = 0;
	int mnt_flags = 0;

	/* Discard magic */
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;

	/* Basic sanity checks */

	if (!dir_name || !*dir_name || !memchr(dir_name, 0, PAGE_SIZE))
		return -EINVAL;
	if (dev_name && !memchr(dev_name, 0, PAGE_SIZE))
		return -EINVAL;

	if (data_page)
		((char *)data_page)[PAGE_SIZE - 1] = 0;

	/* Separate the per-mountpoint flags */
	if (flags & MS_NOSUID)
		mnt_flags |= MNT_NOSUID;
	if (flags & MS_NODEV)
		mnt_flags |= MNT_NODEV;
	if (flags & MS_NOEXEC)
		mnt_flags |= MNT_NOEXEC;
	flags &= ~(MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_ACTIVE);

	/* ... and get the mountpoint */
	retval = path_lookup(dir_name, LOOKUP_FOLLOW, &nd);
	if (retval)
		return retval;

	retval = security_sb_mount(dev_name, &nd, type_page, flags, data_page);
	if (retval)
		goto dput_out;

	if (flags & MS_REMOUNT)
		retval = do_remount(&nd, flags & ~MS_REMOUNT, mnt_flags,
				    data_page);
	else if (flags & MS_BIND)
		retval = do_loopback(&nd, dev_name, flags & MS_REC);
	else if (flags & MS_MOVE)
		retval = do_move_mount(&nd, dev_name);
	else
		retval = do_new_mount(&nd, type_page, flags, mnt_flags,
				      dev_name, data_page);
dput_out:
	path_release(&nd);
	return retval;
}

int copy_namespace(int flags, struct task_struct *tsk)
{
	struct namespace *namespace = tsk->namespace;
	struct namespace *new_ns;
	struct vfsmount *rootmnt = NULL, *pwdmnt = NULL, *altrootmnt = NULL;
	struct fs_struct *fs = tsk->fs;
	struct vfsmount *p, *q;

	if (!namespace)
		return 0;
	get_namespace(namespace);

	if (!(flags & CLONE_NEWNS))
		return 0;

	panic("in copy_namespace function");
	return 0;
}

asmlinkage long sys_mount(char __user * dev_name, char __user * dir_name,
			  char __user * type, unsigned long flags,
			  void __user * data)
{
	int retval;
	unsigned long data_page;
	unsigned long type_page;
	unsigned long dev_page;
	char *dir_page;

	retval = copy_mount_options (type, &type_page);
	if (retval < 0)
		return retval;

	dir_page = getname(dir_name);
	retval = PTR_ERR(dir_page);
	if (IS_ERR(dir_page))
		goto out1;

	retval = copy_mount_options (dev_name, &dev_page);
	if (retval < 0)
		goto out2;

	retval = copy_mount_options (data, &data_page);
	if (retval < 0)
		goto out3;

	lock_kernel();
	retval = do_mount((char*)dev_page, dir_page, (char*)type_page,
			  flags, (void*)data_page);
	unlock_kernel();
	free_page(data_page);

out3:
	free_page(dev_page);
out2:
	putname(dir_page);
out1:
	free_page(type_page);
	return retval;
}

void set_fs_root(struct fs_struct *fs, struct vfsmount *mnt,
		 struct dentry *dentry)
{
	struct dentry *old_root;
	struct vfsmount *old_rootmnt;
	write_lock(&fs->lock);
	old_root = fs->root;
	old_rootmnt = fs->rootmnt;
	fs->rootmnt = mntget(mnt);
	fs->root = dget(dentry);
	write_unlock(&fs->lock);
	if (old_root) {
		dput(old_root);
		mntput(old_rootmnt);
	}
}

void set_fs_pwd(struct fs_struct *fs, struct vfsmount *mnt,
		struct dentry *dentry)
{
	struct dentry *old_pwd;
	struct vfsmount *old_pwdmnt;

	write_lock(&fs->lock);
	old_pwd = fs->pwd;
	old_pwdmnt = fs->pwdmnt;
	fs->pwdmnt = mntget(mnt);
	fs->pwd = dget(dentry);
	write_unlock(&fs->lock);

	if (old_pwd) {
		dput(old_pwd);
		mntput(old_pwdmnt);
	}
}

static void __init init_mount_tree(void)
{
	struct vfsmount *mnt;
	struct namespace *namespace;
	struct task_struct *g, *p;

	mnt = do_kern_mount("rootfs", 0, "rootfs", NULL);
	if (IS_ERR(mnt))
		panic("Can't create rootfs");
	namespace = kmalloc(sizeof(*namespace), GFP_KERNEL);
	if (!namespace)
		panic("Can't allocate initial namespace");
	atomic_set(&namespace->count, 1);
	INIT_LIST_HEAD(&namespace->list);
	init_rwsem(&namespace->sem);
	list_add(&mnt->mnt_list, &namespace->list);
	namespace->root = mnt;
	mnt->mnt_namespace = namespace;

	init_task.namespace = namespace;
	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
		get_namespace(namespace);
		p->namespace = namespace;
	} while_each_thread(g, p);
	read_unlock(&tasklist_lock);

	set_fs_pwd(current->fs, namespace->root, namespace->root->mnt_root);
	set_fs_root(current->fs, namespace->root, namespace->root->mnt_root);
}

void __init mnt_init(unsigned long mempages)
{
    struct list_head *d;
	unsigned long order;
	unsigned int nr_hash;
	int i;

	mnt_cache = kmem_cache_create("mnt_cache", sizeof(struct vfsmount),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);

	order = 0; 
	mount_hashtable = (struct list_head *)
		__get_free_pages(GFP_ATOMIC, order);
    
    if (!mount_hashtable)
		panic("Failed to allocate mount hash table\n");
    
    /*
	 * Find the power-of-two list-heads that can fit into the allocation..
	 * We don't guarantee that "sizeof(struct list_head)" is necessarily
	 * a power-of-two.
	 */
	nr_hash = (1UL << order) * PAGE_SIZE / sizeof(struct list_head);
	hash_bits = 0;
	do {
		hash_bits++;
	} while ((nr_hash >> hash_bits) != 0);
	hash_bits--;

    /*
	 * Re-calculate the actual number of entries and the mask
	 * from the number of bits we can fit.
	 */
	nr_hash = 1UL << hash_bits;
	hash_mask = nr_hash-1;

    printk("Mount-cache hash table entries: %d (order: %ld, %ld bytes)\n",
			nr_hash, order, (PAGE_SIZE << order));

	/* And initialize the newly allocated array */
	d = mount_hashtable;
	i = nr_hash;
	do {
		INIT_LIST_HEAD(d);
		d++;
		i--;
	} while (i);
    sysfs_init();
	init_rootfs();
	init_mount_tree();
}

void __put_namespace(struct namespace *namespace)
{
	struct vfsmount *mnt;

	down_write(&namespace->sem);
	spin_lock(&vfsmount_lock);

	list_for_each_entry(mnt, &namespace->list, mnt_list) {
		mnt->mnt_namespace = NULL;
	}
	
	umount_tree(namespace->root);
	spin_unlock(&vfsmount_lock);
	up_write(&namespace->sem);
	kfree(namespace);
}