#include <linux/config.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <linux/security.h>
#include <linux/seqlock.h>
#include <linux/swap.h>
#include <linux/bootmem.h>

int sysctl_vfs_cache_pressure = 100;

static kmem_cache_t *dentry_cache;

static unsigned int d_hash_mask;
static unsigned int d_hash_shift;
static struct hlist_head *dentry_hashtable;

/* Statistics gathering. */
struct dentry_stat_t dentry_stat = {
	.age_limit = 45,
};

static void prune_dcache(int count)
{
}

static int shrink_dcache_memory(int nr, unsigned int gfp_mask)
{
	if (nr) {
		if (!(gfp_mask & __GFP_FS))
			return -1;
		prune_dcache(nr);
	}
	return (dentry_stat.nr_unused / 100) * sysctl_vfs_cache_pressure;
}

static __initdata unsigned long dhash_entries;

static void __init dcache_init_early(void) {
    int loop;

    if (hashdist)
        return;
    
    dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct hlist_head),
					dhash_entries,
					13,
					HASH_EARLY,
					&d_hash_shift,
					&d_hash_mask,
					0);
    for (loop = 0; loop < (1 << d_hash_shift); loop++)
        INIT_HLIST_HEAD(&dentry_hashtable[loop]);
}

static void __init dcache_init(unsigned long mempages)
{
	int loop;

	dentry_cache = kmem_cache_create("dentry_cache",
					 sizeof(struct dentry),
					 0,
					 SLAB_RECLAIM_ACCOUNT|SLAB_PANIC,
					 NULL, NULL);

	set_shrinker(DEFAULT_SEEKS, shrink_dcache_memory);

	if (!hashdist)
		return;

	dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct hlist_head),
					dhash_entries,
					13,
					0,
					&d_hash_shift,
					&d_hash_mask,
					0);

	for (loop = 0; loop < (1 << d_hash_shift); loop++)
		INIT_HLIST_HEAD(&dentry_hashtable[loop]);
}

/* SLAB cache for __getname() consumers */
kmem_cache_t *names_cachep;

/* SLAB cache for file structures */
kmem_cache_t *filp_cachep;

void __init vfs_caches_init_early(void)
{
	dcache_init_early();
	inode_init_early();
}

void __init vfs_caches_init(unsigned long mempages)
{
	unsigned long reserve;

	/* Base hash sizes on available memory, with a reserve equal to
           150% of current kernel size */

	reserve = min((mempages - nr_free_pages()) * 3/2, mempages - 1);
	mempages -= reserve;

	names_cachep = kmem_cache_create("names_cache", PATH_MAX, 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);

	filp_cachep = kmem_cache_create("filp", sizeof(struct file), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, filp_ctor, filp_dtor);

	dcache_init(mempages);
	inode_init(mempages);
	files_init(mempages);
	mnt_init(mempages);
	bdev_cache_init();
	chrdev_init();
}