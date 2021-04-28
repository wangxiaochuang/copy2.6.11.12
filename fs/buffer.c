#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/blkdev.h>
#include <linux/file.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/hash.h>
#include <linux/suspend.h>
#include <linux/buffer_head.h>
#include <linux/bio.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/bitops.h>

/*
 * Buffer-head allocation
 */
static kmem_cache_t *bh_cachep;

/*
 * Once the number of bh's in the machine exceeds this level, we start
 * stripping them in writeback.
 */
static int max_buffer_heads;

void free_buffer_head(struct buffer_head *bh)
{
}

static void
init_buffer_head(void *data, kmem_cache_t *cachep, unsigned long flags)
{
    if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
			    SLAB_CTOR_CONSTRUCTOR) {
		struct buffer_head * bh = (struct buffer_head *)data;

		memset(bh, 0, sizeof(*bh));
		INIT_LIST_HEAD(&bh->b_assoc_buffers);
	}
}

void __init buffer_init(void)
{
	int nrpages;

	bh_cachep = kmem_cache_create("buffer_head",
			sizeof(struct buffer_head), 0,
			SLAB_PANIC, init_buffer_head, NULL);
    
    nrpages = (nr_free_buffer_pages() * 10) / 100;
    max_buffer_heads = nrpages * (PAGE_SIZE / sizeof(struct buffer_head));
    hotcpu_notifier(buffer_cpu_notify, 0);
}