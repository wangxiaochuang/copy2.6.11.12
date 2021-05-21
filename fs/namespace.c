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