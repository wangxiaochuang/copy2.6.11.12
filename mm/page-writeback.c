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



int pdflush_operation(void (*fn)(unsigned long), unsigned long arg0)
{
	panic("in pdflush_operation function");
	return 0;
}

static void wb_timer_fn(unsigned long unused);

static struct timer_list wb_timer =
			TIMER_INITIALIZER(wb_timer_fn, 0, 0);

static void wb_kupdate(unsigned long arg)
{
	panic("in wb_kupdate function");
}

static void wb_timer_fn(unsigned long unused)
{
	if (pdflush_operation(wb_kupdate, 0) < 0)
		mod_timer(&wb_timer, jiffies + HZ); /* delay 1 second */
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
	panic("in __set_page_dirty_nobuffers function");
	return 0;
}

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
