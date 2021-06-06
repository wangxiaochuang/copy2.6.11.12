#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>	/* for try_to_release_page(),
					buffer_heads_over_limit */
#include <linux/mm_inline.h>
#include <linux/pagevec.h>
#include <linux/backing-dev.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/rwsem.h>

#include <asm/tlbflush.h>
#include <asm/div64.h>

#include <linux/swapops.h>

struct scan_control {
	/* Ask refill_inactive_zone, or shrink_cache to scan this many pages */
	unsigned long nr_to_scan;

	/* Incremented by the number of inactive pages that were scanned */
	unsigned long nr_scanned;

	/* Incremented by the number of pages reclaimed */
	unsigned long nr_reclaimed;

	unsigned long nr_mapped;	/* From page_state */

	/* How many pages shrink_cache() should reclaim */
	int nr_to_reclaim;

	/* Ask shrink_caches, or shrink_zone to scan at this priority */
	unsigned int priority;

	/* This context's GFP mask */
	unsigned int gfp_mask;

	int may_writepage;
};

/*
 * The list of shrinker callbacks used by to apply pressure to
 * ageable caches.
 */
struct shrinker {
	shrinker_t		shrinker;
	struct list_head	list;
	int			seeks;	/* seeks to recreate an obj */
	long			nr;	/* objs pending delete */
};

static LIST_HEAD(shrinker_list);
static DECLARE_RWSEM(shrinker_rwsem);

/*
 * Add a shrinker callback to be called from the vm
 */
struct shrinker *set_shrinker(int seeks, shrinker_t theshrinker)
{
	struct shrinker *shrinker;

	shrinker = kmalloc(sizeof(*shrinker), GFP_KERNEL);
	if (shrinker) {
	        shrinker->shrinker = theshrinker;
	        shrinker->seeks = seeks;
	        shrinker->nr = 0;
	        down_write(&shrinker_rwsem);
	        list_add(&shrinker->list, &shrinker_list);
	        up_write(&shrinker_rwsem);
	}
	return shrinker;
}

int try_to_free_pages(struct zone **zones,
		unsigned int gfp_mask, unsigned int order)
{
	panic("in try_to_free_pages");
    return 0;
}

void wakeup_kswapd(struct zone *zone, int order)
{
	pg_data_t *pgdat;

    if (zone->present_pages == 0)
        return;
    
    pgdat = zone->zone_pgdat;
    if (zone_watermark_ok(zone, order, zone->pages_low, 0, 0, 0))
        return;
    if (pgdat->kswapd_max_order < order)
        pgdat->kswapd_max_order = order;
    if (!waitqueue_active(&zone->zone_pgdat->kswapd_wait))
        return;
    wake_up_interruptible(&zone->zone_pgdat->kswapd_wait);
}