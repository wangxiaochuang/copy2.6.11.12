#include <linux/config.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/dcache.h>
#include <linux/init.h>
#include <linux/quotaops.h>
#include <linux/slab.h>
#include <linux/writeback.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/wait.h>
#include <linux/hash.h>
#include <linux/swap.h>
#include <linux/security.h>
#include <linux/pagemap.h>
#include <linux/cdev.h>
#include <linux/bootmem.h>

int inode_has_buffers(struct inode *);
void invalidate_inode_buffers(struct inode *);

/*
 * Inode lookup is no longer as critical as it used to be:
 * most of the lookups are going to be through the dcache.
 */
#define I_HASHBITS	i_hash_shift
#define I_HASHMASK	i_hash_mask

static unsigned int i_hash_mask;
static unsigned int i_hash_shift;

/*
 * Each inode can be on two separate lists. One is
 * the hash list of the inode, used for lookups. The
 * other linked list is the "type" list:
 *  "in_use" - valid inode, i_count > 0, i_nlink > 0
 *  "dirty"  - as "in_use" but also dirty
 *  "unused" - valid inode, i_count = 0
 *
 * A "dirty" list is maintained for each super block,
 * allowing for low-overhead inode sync() operations.
 */

LIST_HEAD(inode_in_use);
LIST_HEAD(inode_unused);
static struct hlist_head *inode_hashtable;

DEFINE_SPINLOCK(inode_lock);

DECLARE_MUTEX(iprune_sem);

/*
 * Statistics gathering..
 */
struct inodes_stat_t inodes_stat;

static kmem_cache_t * inode_cachep;

static struct inode *alloc_inode(struct super_block *sb)
{
	static struct address_space_operations empty_aops;
	static struct inode_operations empty_iops;
	static struct file_operations empty_fops;
	struct inode *inode;

	if (sb->s_op->alloc_inode)
		inode = sb->s_op->alloc_inode(sb);
	else
		inode = (struct inode *) kmem_cache_alloc(inode_cachep, SLAB_KERNEL);

	if (inode) {
		struct address_space * const mapping = &inode->i_data;

		inode->i_sb = sb;
		inode->i_blkbits = sb->s_blocksize_bits;
		inode->i_flags = 0;
		atomic_set(&inode->i_count, 1);
		inode->i_sock = 0;
		inode->i_op = &empty_iops;
		inode->i_fop = &empty_fops;
		inode->i_nlink = 1;
		atomic_set(&inode->i_writecount, 0);
		inode->i_size = 0;
		inode->i_blocks = 0;
		inode->i_bytes = 0;
		inode->i_generation = 0;
#ifdef CONFIG_QUOTA
		memset(&inode->i_dquot, 0, sizeof(inode->i_dquot));
#endif
		inode->i_pipe = NULL;
		inode->i_bdev = NULL;
		inode->i_cdev = NULL;
		inode->i_rdev = 0;
		inode->i_security = NULL;
		inode->dirtied_when = 0;
		if (security_inode_alloc(inode)) {
			if (inode->i_sb->s_op->destroy_inode)
				inode->i_sb->s_op->destroy_inode(inode);
			else
				kmem_cache_free(inode_cachep, (inode));
			return NULL;
		}

		mapping->a_ops = &empty_aops;
 		mapping->host = inode;
		mapping->flags = 0;
		mapping_set_gfp_mask(mapping, GFP_HIGHUSER);
		mapping->assoc_mapping = NULL;
		mapping->backing_dev_info = &default_backing_dev_info;

		/*
		 * If the block_device provides a backing_dev_info for client
		 * inodes then use that.  Otherwise the inode share the bdev's
		 * backing_dev_info.
		 */
		if (sb->s_bdev) {
			struct backing_dev_info *bdi;

			bdi = sb->s_bdev->bd_inode_backing_dev_info;
			if (!bdi)
				bdi = sb->s_bdev->bd_inode->i_mapping->backing_dev_info;
			mapping->backing_dev_info = bdi;
		}
		memset(&inode->u, 0, sizeof(inode->u));
		inode->i_mapping = mapping;
	}
	return inode;
}

void destroy_inode(struct inode *inode) 
{
	if (inode_has_buffers(inode))
		BUG();
	security_inode_free(inode);
	if (inode->i_sb->s_op->destroy_inode)
		inode->i_sb->s_op->destroy_inode(inode);
	else
		kmem_cache_free(inode_cachep, (inode));
}

void inode_init_once(struct inode *inode)
{
	memset(inode, 0, sizeof(*inode));
	INIT_HLIST_NODE(&inode->i_hash);
	INIT_LIST_HEAD(&inode->i_dentry);
	INIT_LIST_HEAD(&inode->i_devices);
	sema_init(&inode->i_sem, 1);
	init_rwsem(&inode->i_alloc_sem);
	INIT_RADIX_TREE(&inode->i_data.page_tree, GFP_ATOMIC);
	spin_lock_init(&inode->i_data.tree_lock);
	spin_lock_init(&inode->i_data.i_mmap_lock);
	INIT_LIST_HEAD(&inode->i_data.private_list);
	spin_lock_init(&inode->i_data.private_lock);
	INIT_RAW_PRIO_TREE_ROOT(&inode->i_data.i_mmap);
	INIT_LIST_HEAD(&inode->i_data.i_mmap_nonlinear);
	spin_lock_init(&inode->i_lock);
	i_size_ordered_init(inode);
}

EXPORT_SYMBOL(inode_init_once);

static void init_once(void * foo, kmem_cache_t * cachep, unsigned long flags)
{
	struct inode * inode = (struct inode *) foo;

	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
	    SLAB_CTOR_CONSTRUCTOR)
		inode_init_once(inode);
}

/*
 * inode_lock must be held
 */
void __iget(struct inode * inode)
{
	if (atomic_read(&inode->i_count)) {
		atomic_inc(&inode->i_count);
		return;
	}
	atomic_inc(&inode->i_count);
	if (!(inode->i_state & (I_DIRTY|I_LOCK)))
		list_move(&inode->i_list, &inode_in_use);
	inodes_stat.nr_unused--;
}

void clear_inode(struct inode *inode)
{
	might_sleep();
	invalidate_inode_buffers(inode);

	if (inode->i_data.nrpages)
		BUG();
	if (!(inode->i_state & I_FREEING))
		BUG();
	if (inode->i_state & I_CLEAR)
		BUG();
	wait_on_inode(inode);
	DQUOT_DROP(inode);
	if (inode->i_sb && inode->i_sb->s_op->clear_inode)
		inode->i_sb->s_op->clear_inode(inode);
	if (inode->i_bdev)
		bd_forget(inode);
	if (inode->i_cdev)
		cd_forget(inode);
	inode->i_state = I_CLEAR;
}

static void dispose_list(struct list_head *head)
{
	int nr_disposed = 0;

	while (!list_empty(head)) {
		struct inode *inode;

		inode = list_entry(head->next, struct inode, i_list);
		list_del(&inode->i_list);

		if (inode->i_data.nrpages)
			truncate_inode_pages(&inode->i_data, 0);
		clear_inode(inode);
		destroy_inode(inode);
		nr_disposed++;
	}
	spin_lock(&inode_lock);
	inodes_stat.nr_inodes -= nr_disposed;
	spin_unlock(&inode_lock);
}

/*
 * Invalidate all inodes for a device.
 */
static int invalidate_list(struct list_head *head, struct list_head *dispose)
{
	struct list_head *next;
	int busy = 0, count = 0;

	next = head->next;
	for (;;) {
		struct list_head * tmp = next;
		struct inode * inode;

		/*
		 * We can reschedule here without worrying about the list's
		 * consistency because the per-sb list of inodes must not
		 * change during umount anymore, and because iprune_sem keeps
		 * shrink_icache_memory() away.
		 */
		cond_resched_lock(&inode_lock);

		next = next->next;
		if (tmp == head)
			break;
		inode = list_entry(tmp, struct inode, i_sb_list);
		invalidate_inode_buffers(inode);
		if (!atomic_read(&inode->i_count)) {
			hlist_del_init(&inode->i_hash);
			list_del(&inode->i_sb_list);
			list_move(&inode->i_list, dispose);
			inode->i_state |= I_FREEING;
			count++;
			continue;
		}
		busy = 1;
	}
	/* only unused inodes may be cached with i_count zero */
	inodes_stat.nr_unused -= count;
	return busy;
}

int invalidate_inodes(struct super_block * sb)
{
	int busy;
	LIST_HEAD(throw_away);

	down(&iprune_sem);
	spin_lock(&inode_lock);
	busy = invalidate_list(&sb->s_inodes, &throw_away);
	spin_unlock(&inode_lock);

	dispose_list(&throw_away);
	up(&iprune_sem);

	return busy;
}

static void prune_icache(int nr_to_scan)
{
	panic("in prune_icache function");
}

static int shrink_icache_memory(int nr, unsigned int gfp_mask)
{
	if (nr) {
		if (!(gfp_mask & __GFP_FS))
			return -1;
		prune_icache(nr);
	}
	return (inodes_stat.nr_unused / 100) * sysctl_vfs_cache_pressure;
}

static void __wait_on_freeing_inode(struct inode *inode);
/*
 * Called with the inode lock held.
 * NOTE: we are not increasing the inode-refcount, you must call __iget()
 * by hand after calling find_inode now! This simplifies iunique and won't
 * add any additional branch in the common code.
 */
static struct inode * find_inode(struct super_block * sb, struct hlist_head *head, int (*test)(struct inode *, void *), void *data)
{
	struct hlist_node *node;
	struct inode * inode = NULL;

repeat:
	hlist_for_each (node, head) { 
		inode = hlist_entry(node, struct inode, i_hash);
		if (inode->i_sb != sb)
			continue;
		if (!test(inode, data))
			continue;
		if (inode->i_state & (I_FREEING|I_CLEAR)) {
			__wait_on_freeing_inode(inode);
			goto repeat;
		}
		break;
	}
	return node ? inode : NULL;
}

/*
 * find_inode_fast is the fast path version of find_inode, see the comment at
 * iget_locked for details.
 */
static struct inode * find_inode_fast(struct super_block * sb, struct hlist_head *head, unsigned long ino)
{
	struct hlist_node *node;
	struct inode * inode = NULL;

repeat:
	hlist_for_each (node, head) {
		inode = hlist_entry(node, struct inode, i_hash);
		if (inode->i_ino != ino)
			continue;
		if (inode->i_sb != sb)
			continue;
		if (inode->i_state & (I_FREEING|I_CLEAR)) {
			__wait_on_freeing_inode(inode);
			goto repeat;
		}
		break;
	}
	return node ? inode : NULL;
}

struct inode *new_inode(struct super_block *sb)
{
	static unsigned long last_ino;
	struct inode * inode;

	spin_lock_prefetch(&inode_lock);
	
	inode = alloc_inode(sb);
	if (inode) {
		spin_lock(&inode_lock);
		inodes_stat.nr_inodes++;
		list_add(&inode->i_list, &inode_in_use);
		list_add(&inode->i_sb_list, &sb->s_inodes);
		inode->i_ino = ++last_ino;
		inode->i_state = 0;
		spin_unlock(&inode_lock);
	}
	return inode;
}

void unlock_new_inode(struct inode *inode)
{
	inode->i_state &= ~(I_LOCK|I_NEW);
	wake_up_inode(inode);
}

EXPORT_SYMBOL(unlock_new_inode);

static struct inode * get_new_inode(struct super_block *sb, struct hlist_head *head, int (*test)(struct inode *, void *), int (*set)(struct inode *, void *), void *data)
{
	struct inode * inode;

	inode = alloc_inode(sb);
	if (inode) {
		struct inode * old;

		spin_lock(&inode_lock);
		/* We released the lock, so.. */
		old = find_inode(sb, head, test, data);
		if (!old) {
			if (set(inode, data))
				goto set_failed;

			inodes_stat.nr_inodes++;
			list_add(&inode->i_list, &inode_in_use);
			list_add(&inode->i_sb_list, &sb->s_inodes);
			hlist_add_head(&inode->i_hash, head);
			inode->i_state = I_LOCK|I_NEW;
			spin_unlock(&inode_lock);

			/* Return the locked inode with I_NEW set, the
			 * caller is responsible for filling in the contents
			 */
			return inode;
		}

		/*
		 * Uhhuh, somebody else created the same inode under
		 * us. Use the old inode instead of the one we just
		 * allocated.
		 */
		__iget(old);
		spin_unlock(&inode_lock);
		destroy_inode(inode);
		inode = old;
		wait_on_inode(inode);
	}
	return inode;

set_failed:
	spin_unlock(&inode_lock);
	destroy_inode(inode);
	return NULL;
}

static struct inode * get_new_inode_fast(struct super_block *sb, struct hlist_head *head, unsigned long ino)
{
	struct inode * inode;

	inode = alloc_inode(sb);
	if (inode) {
		struct inode * old;

		spin_lock(&inode_lock);
		/* We released the lock, so.. */
		old = find_inode_fast(sb, head, ino);
		if (!old) {
			inode->i_ino = ino;
			inodes_stat.nr_inodes++;
			list_add(&inode->i_list, &inode_in_use);
			list_add(&inode->i_sb_list, &sb->s_inodes);
			hlist_add_head(&inode->i_hash, head);
			inode->i_state = I_LOCK|I_NEW;
			spin_unlock(&inode_lock);

			/* Return the locked inode with I_NEW set, the
			 * caller is responsible for filling in the contents
			 */
			return inode;
		}

		/*
		 * Uhhuh, somebody else created the same inode under
		 * us. Use the old inode instead of the one we just
		 * allocated.
		 */
		__iget(old);
		spin_unlock(&inode_lock);
		destroy_inode(inode);
		inode = old;
		wait_on_inode(inode);
	}
	return inode;
}

static inline unsigned long hash(struct super_block *sb, unsigned long hashval)
{
	unsigned long tmp;

	tmp = (hashval * (unsigned long)sb) ^ (GOLDEN_RATIO_PRIME + hashval) /
			L1_CACHE_BYTES;
	tmp = tmp ^ ((tmp ^ GOLDEN_RATIO_PRIME) >> I_HASHBITS);
	return tmp & I_HASHMASK;
}

struct inode *igrab(struct inode *inode)
{
	spin_lock(&inode_lock);
	if (!(inode->i_state & I_FREEING))
		__iget(inode);
	else
		/*
		 * Handle the case where s_op->clear_inode is not been
		 * called yet, and somebody is calling igrab
		 * while the inode is getting freed.
		 */
		inode = NULL;
	spin_unlock(&inode_lock);
	return inode;
}

EXPORT_SYMBOL(igrab);

static inline struct inode *ifind(struct super_block *sb,
		struct hlist_head *head, int (*test)(struct inode *, void *),
		void *data)
{
	struct inode *inode;

	spin_lock(&inode_lock);
	inode = find_inode(sb, head, test, data);
	if (inode) {
		__iget(inode);
		spin_unlock(&inode_lock);
		wait_on_inode(inode);
		return inode;
	}
	spin_unlock(&inode_lock);
	return NULL;
}

static inline struct inode *ifind_fast(struct super_block *sb,
		struct hlist_head *head, unsigned long ino)
{
	struct inode *inode;

	spin_lock(&inode_lock);
	inode = find_inode_fast(sb, head, ino);
	if (inode) {
		__iget(inode);
		spin_unlock(&inode_lock);
		wait_on_inode(inode);
		return inode;
	}
	spin_unlock(&inode_lock);
	return NULL;
}

struct inode *ilookup5(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data)
{
	struct hlist_head *head = inode_hashtable + hash(sb, hashval);

	return ifind(sb, head, test, data);
}

EXPORT_SYMBOL(ilookup5);

struct inode *ilookup(struct super_block *sb, unsigned long ino)
{
	struct hlist_head *head = inode_hashtable + hash(sb, ino);

	return ifind_fast(sb, head, ino);
}

EXPORT_SYMBOL(ilookup);

struct inode *iget5_locked(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *),
		int (*set)(struct inode *, void *), void *data)
{
	struct hlist_head *head = inode_hashtable + hash(sb, hashval);
	struct inode *inode;

	inode = ifind(sb, head, test, data);
	if (inode)
		return inode;
	/*
	 * get_new_inode() will do the right thing, re-trying the search
	 * in case it had to block at any point.
	 */
	return get_new_inode(sb, head, test, set, data);
}

EXPORT_SYMBOL(iget5_locked);

struct inode *iget_locked(struct super_block *sb, unsigned long ino)
{
	struct hlist_head *head = inode_hashtable + hash(sb, ino);
	struct inode *inode;

	inode = ifind_fast(sb, head, ino);
	if (inode)
		return inode;
	/*
	 * get_new_inode_fast() will do the right thing, re-trying the search
	 * in case it had to block at any point.
	 */
	return get_new_inode_fast(sb, head, ino);
}

EXPORT_SYMBOL(iget_locked);

void generic_delete_inode(struct inode *inode)
{
	struct super_operations *op = inode->i_sb->s_op;

	list_del_init(&inode->i_list);
	list_del_init(&inode->i_sb_list);
	inode->i_state |= I_FREEING;
	inodes_stat.nr_inodes--;
	spin_unlock(&inode_lock);

	if (inode->i_data.nrpages)
		truncate_inode_pages(&inode->i_data, 0);

	security_inode_delete(inode);

	if (op->delete_inode) {
		void (*delete)(struct inode *) = op->delete_inode;
		if (!is_bad_inode(inode))
			DQUOT_INIT(inode);
		delete(inode);
	} else
		clear_inode(inode);
	spin_lock(&inode_lock);
	hlist_del_init(&inode->i_hash);
	spin_unlock(&inode_lock);
	wake_up_inode(inode);
	if (inode->i_state != I_CLEAR)
		BUG();
	destroy_inode(inode);
}

EXPORT_SYMBOL(generic_delete_inode);

static void generic_forget_inode(struct inode *inode)
{
	panic("in generic_forget_inode function");
}

static void generic_drop_inode(struct inode *inode)
{
	if (!inode->i_nlink)
		generic_delete_inode(inode);
	else
		generic_forget_inode(inode);
}

static inline void iput_final(struct inode *inode)
{
	struct super_operations *op = inode->i_sb->s_op;
	void (*drop)(struct inode *) = generic_drop_inode;

	if (op && op->drop_inode)
		drop = op->drop_inode;
	drop(inode);
}

void iput(struct inode *inode)
{
	if (inode) {
		struct super_operations *op = inode->i_sb->s_op;

		if (inode->i_state == I_CLEAR)
			BUG();

		if (op && op->put_inode)
			op->put_inode(inode);

		if (atomic_dec_and_lock(&inode->i_count, &inode_lock))
			iput_final(inode);
	}
}

EXPORT_SYMBOL(iput);

int inode_wait(void *word)
{
	schedule();
	return 0;
}

static void __wait_on_freeing_inode(struct inode *inode)
{
	wait_queue_head_t *wq;
	DEFINE_WAIT_BIT(wait, &inode->i_state, __I_LOCK);

	/*
	 * I_FREEING and I_CLEAR are cleared in process context under
	 * inode_lock, so we have to give the tasks who would clear them
	 * a chance to run and acquire inode_lock.
	 */
	if (!(inode->i_state & I_LOCK)) {
		spin_unlock(&inode_lock);
		yield();
		spin_lock(&inode_lock);
		return;
	}
	wq = bit_waitqueue(&inode->i_state, __I_LOCK);
	prepare_to_wait(wq, &wait.wait, TASK_UNINTERRUPTIBLE);
	spin_unlock(&inode_lock);
	schedule();
	finish_wait(wq, &wait.wait);
	spin_lock(&inode_lock);
}

void wake_up_inode(struct inode *inode)
{
	/*
	 * Prevent speculative execution through spin_unlock(&inode_lock);
	 */
	smp_mb();
	wake_up_bit(&inode->i_state, __I_LOCK);
}

static __initdata unsigned long ihash_entries;

/*
 * Initialize the waitqueues and inode hash table.
 */
void __init inode_init_early(void) {
    int loop;

	/* If hashes are distributed across NUMA nodes, defer
	 * hash allocation until vmalloc space is available.
	 */
	if (hashdist)
		return;

	inode_hashtable =
		alloc_large_system_hash("Inode-cache",
					sizeof(struct hlist_head),
					ihash_entries,
					14,
					HASH_EARLY,
					&i_hash_shift,
					&i_hash_mask,
					0);

	for (loop = 0; loop < (1 << i_hash_shift); loop++)
		INIT_HLIST_HEAD(&inode_hashtable[loop]);
}

void __init inode_init(unsigned long mempages)
{
	int loop;

	/* inode slab cache */
	inode_cachep = kmem_cache_create("inode_cache", sizeof(struct inode),
				0, SLAB_PANIC, init_once, NULL);
	set_shrinker(DEFAULT_SEEKS, shrink_icache_memory);

	/* Hash may have been set up in inode_init_early */
	if (!hashdist)
		return;

	inode_hashtable =
		alloc_large_system_hash("Inode-cache",
					sizeof(struct hlist_head),
					ihash_entries,
					14,
					0,
					&i_hash_shift,
					&i_hash_mask,
					0);

	for (loop = 0; loop < (1 << i_hash_shift); loop++)
		INIT_HLIST_HEAD(&inode_hashtable[loop]);
}

void init_special_inode(struct inode *inode, umode_t mode, dev_t rdev)
{
	inode->i_mode = mode;
	if (S_ISCHR(mode)) {
		inode->i_fop = &def_chr_fops;
		inode->i_rdev = rdev;
	} else if (S_ISBLK(mode)) {
		inode->i_fop = &def_blk_fops;
		inode->i_rdev = rdev;
	} else if (S_ISFIFO(mode))
		inode->i_fop = &def_fifo_fops;
	else if (S_ISSOCK(mode))
		inode->i_fop = &bad_sock_fops;
	else
		printk(KERN_DEBUG "init_special_inode: bogus i_mode (%o)\n",
		       mode);
}
EXPORT_SYMBOL(init_special_inode);