#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/init.h>
#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/mpage.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/smp.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>

#define MAX_WRITEBACK_PAGES	1024

/*
 * After a CPU has dirtied this many pages, balance_dirty_pages_ratelimited
 * will look to see if it needs to force writeback or throttling.
 */
static long ratelimit_pages = 32;

static long total_pages;

/*
 * Start background writeback (via pdflush) at this percentage
 */
int dirty_background_ratio = 10;

/*
 * The generator of dirty data starts writeback at this percentage
 */
int vm_dirty_ratio = 40;

/*
 * The interval between `kupdate'-style writebacks, in centiseconds
 * (hundredths of a second)
 */
int dirty_writeback_centisecs = 5 * 100;

/*
 * Flag that makes the machine dump writes/reads and block dirtyings.
 */
int block_dump;

int laptop_mode;

EXPORT_SYMBOL(laptop_mode);

static void background_writeout(unsigned long _min_pages);

struct writeback_state
{
	unsigned long nr_dirty;
	unsigned long nr_unstable;
	unsigned long nr_mapped;
	unsigned long nr_writeback;
};

static void get_writeback_state(struct writeback_state *wbs)
{
	wbs->nr_dirty = read_page_state(nr_dirty);
	wbs->nr_unstable = read_page_state(nr_unstable);
	wbs->nr_mapped = read_page_state(nr_mapped);
	wbs->nr_writeback = read_page_state(nr_writeback);
}

static void
get_dirty_limits(struct writeback_state *wbs, long *pbackground, long *pdirty,
		struct address_space *mapping)
{
	int background_ratio;		/* Percentages */
	int dirty_ratio;
	int unmapped_ratio;
	long background;
	long dirty;
	unsigned long available_memory = total_pages;
	struct task_struct *tsk;

	get_writeback_state(wbs);

#ifdef CONFIG_HIGHMEM
	/*
	 * If this mapping can only allocate from low memory,
	 * we exclude high memory from our count.
	 */
	if (mapping && !(mapping_gfp_mask(mapping) & __GFP_HIGHMEM))
		available_memory -= totalhigh_pages;
#endif


	unmapped_ratio = 100 - (wbs->nr_mapped * 100) / total_pages;

	dirty_ratio = vm_dirty_ratio;
	if (dirty_ratio > unmapped_ratio / 2)
		dirty_ratio = unmapped_ratio / 2;

	if (dirty_ratio < 5)
		dirty_ratio = 5;

	background_ratio = dirty_background_ratio;
	if (background_ratio >= dirty_ratio)
		background_ratio = dirty_ratio / 2;

	background = (background_ratio * available_memory) / 100;
	dirty = (dirty_ratio * available_memory) / 100;
	tsk = current;
	if (tsk->flags & PF_LESS_THROTTLE || rt_task(tsk)) {
		background += background / 4;
		dirty += dirty / 4;
	}
	*pbackground = background;
	*pdirty = dirty;
}

void balance_dirty_pages_ratelimited(struct address_space *mapping)
{
	panic("in balance_dirty_pages_ratelimited");
}

static void background_writeout(unsigned long _min_pages)
{
	long min_pages = _min_pages;
	struct writeback_control wbc = {
		.bdi		= NULL,
		.sync_mode	= WB_SYNC_NONE,
		.older_than_this = NULL,
		.nr_to_write	= 0,
		.nonblocking	= 1,
	};

	for ( ; ; ) {
		struct writeback_state wbs;
		long background_thresh;
		long dirty_thresh;

		get_dirty_limits(&wbs, &background_thresh, &dirty_thresh, NULL);
		if (wbs.nr_dirty + wbs.nr_unstable < background_thresh
				&& min_pages <= 0)
			break;
		wbc.encountered_congestion = 0;
		wbc.nr_to_write = MAX_WRITEBACK_PAGES;
		wbc.pages_skipped = 0;
		writeback_inodes(&wbc);
		min_pages -= MAX_WRITEBACK_PAGES - wbc.nr_to_write;
		if (wbc.nr_to_write > 0 || wbc.pages_skipped > 0) {
			/* Wrote less than expected */
			blk_congestion_wait(WRITE, HZ/10);
			if (!wbc.encountered_congestion)
				break;
		}
	}
}

int wakeup_bdflush(long nr_pages)
{
	if (nr_pages == 0) {
		struct writeback_state wbs;

		get_writeback_state(&wbs);
		nr_pages = wbs.nr_dirty + wbs.nr_unstable;
	}
	return pdflush_operation(background_writeout, nr_pages);
}

static void wb_timer_fn(unsigned long unused);
static void laptop_timer_fn(unsigned long unused);

static struct timer_list wb_timer =
			TIMER_INITIALIZER(wb_timer_fn, 0, 0);
static struct timer_list laptop_mode_wb_timer =
			TIMER_INITIALIZER(laptop_timer_fn, 0, 0);

static void wb_kupdate(unsigned long arg)
{
	panic("in wb_kupdate function");
}

static void wb_timer_fn(unsigned long unused)
{
	if (pdflush_operation(wb_kupdate, 0) < 0)
		mod_timer(&wb_timer, jiffies + HZ); /* delay 1 second */
}

static void laptop_flush(unsigned long unused)
{
	sys_sync();
}

static void laptop_timer_fn(unsigned long unused)
{
	pdflush_operation(laptop_flush, 0);
}

void laptop_io_completion(void)
{
	mod_timer(&laptop_mode_wb_timer, jiffies + laptop_mode * HZ);
}

void laptop_sync_completion(void)
{
	del_timer(&laptop_mode_wb_timer);
}

static void set_ratelimit(void)
{
	ratelimit_pages = total_pages / (num_online_cpus() * 32);
	if (ratelimit_pages < 16)
		ratelimit_pages = 16;
	if (ratelimit_pages * PAGE_CACHE_SIZE > 4096 * 1024)
		ratelimit_pages = (4096 * 1024) / PAGE_CACHE_SIZE;
}

static int
ratelimit_handler(struct notifier_block *self, unsigned long u, void *v)
{
	set_ratelimit();
	return 0;
}

static struct notifier_block ratelimit_nb = {
	.notifier_call	= ratelimit_handler,
	.next		= NULL,
};

void __init page_writeback_init(void)
{
	long buffer_pages = nr_free_buffer_pages();
	long correction;

	total_pages = nr_free_pagecache_pages();

	correction = (100 * 4 * buffer_pages) / total_pages;

	if (correction < 100) {
		dirty_background_ratio *= correction;
		dirty_background_ratio /= 100;
		vm_dirty_ratio *= correction;
		vm_dirty_ratio /= 100;

		if (dirty_background_ratio <= 0)
			dirty_background_ratio = 1;
		if (vm_dirty_ratio <= 0)
			vm_dirty_ratio = 1;
	}
	mod_timer(&wb_timer, jiffies + (dirty_writeback_centisecs * HZ) / 100);
	set_ratelimit();
	register_cpu_notifier(&ratelimit_nb);
}

int do_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	if (wbc->nr_to_write <= 0)
		return 0;
	if (mapping->a_ops->writepages)
		return mapping->a_ops->writepages(mapping, wbc);
	return generic_writepages(mapping, wbc);
}

int __set_page_dirty_nobuffers(struct page *page)
{
	int ret = 0;

	if (!TestSetPageDirty(page)) {
		struct address_space *mapping = page_mapping(page);
		struct address_space *mapping2;

		if (mapping) {
			spin_lock_irq(&mapping->tree_lock);
			mapping2 = page_mapping(page);
			if (mapping2) { /* Race with truncate? */
				BUG_ON(mapping2 != mapping);
				if (!mapping->backing_dev_info->memory_backed)
					inc_page_state(nr_dirty);
				radix_tree_tag_set(&mapping->page_tree,
					page_index(page), PAGECACHE_TAG_DIRTY);
			}
			spin_unlock_irq(&mapping->tree_lock);
			if (mapping->host) {
				/* !PageAnon && !swapper_space */
				__mark_inode_dirty(mapping->host,
							I_DIRTY_PAGES);
			}
		}
	}
	return ret;
}

EXPORT_SYMBOL(__set_page_dirty_nobuffers);

int redirty_page_for_writepage(struct writeback_control *wbc, struct page *page)
{
	wbc->pages_skipped++;
	return __set_page_dirty_nobuffers(page);
}
EXPORT_SYMBOL(redirty_page_for_writepage);

int fastcall set_page_dirty(struct page *page)
{
	struct address_space *mapping = page_mapping(page);

	if (likely(mapping)) {
		int (*spd)(struct page *) = mapping->a_ops->set_page_dirty;
		if (spd)
			return (*spd)(page);
		return __set_page_dirty_buffers(page);
	}
	if (!PageDirty(page))
		SetPageDirty(page);
	return 0;
}
EXPORT_SYMBOL(set_page_dirty);

int set_page_dirty_lock(struct page *page)
{
	int ret;

	lock_page(page);
	ret = set_page_dirty(page);
	unlock_page(page);
	return ret;
}
EXPORT_SYMBOL(set_page_dirty_lock);

int test_clear_page_dirty(struct page *page)
{
	struct address_space *mapping = page_mapping(page);
	unsigned long flags;

	if (mapping) {
		spin_lock_irqsave(&mapping->tree_lock, flags);
		if (TestClearPageDirty(page)) {
			radix_tree_tag_clear(&mapping->page_tree,
						page_index(page),
						PAGECACHE_TAG_DIRTY);
			spin_unlock_irqrestore(&mapping->tree_lock, flags);
			if (!mapping->backing_dev_info->memory_backed)
				dec_page_state(nr_dirty);
			return 1;
		}
		spin_unlock_irqrestore(&mapping->tree_lock, flags);
		return 0;
	}
	return TestClearPageDirty(page);
}
EXPORT_SYMBOL(test_clear_page_dirty);

int clear_page_dirty_for_io(struct page *page)
{
	struct address_space *mapping = page_mapping(page);

	if (mapping) {
		if (TestClearPageDirty(page)) {
			if (!mapping->backing_dev_info->memory_backed)
				dec_page_state(nr_dirty);
			return 1;
		}
		return 0;
	}
	return TestClearPageDirty(page);
}
EXPORT_SYMBOL(clear_page_dirty_for_io);

int mapping_tagged(struct address_space *mapping, int tag)
{
	panic("in mapping_tagged function");
	return 0;
}

EXPORT_SYMBOL(mapping_tagged);
