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

static void prune_icache(int nr_to_scan)
{
	panic("in prune_icache");
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