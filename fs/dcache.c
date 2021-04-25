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

static unsigned int d_hash_mask;
static unsigned int d_hash_shift;
static struct hlist_head *dentry_hashtable;

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

void __init vfs_caches_init_early(void)
{
	dcache_init_early();
	inode_init_early();
}