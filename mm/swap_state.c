#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/backing-dev.h>

#include <asm/pgtable.h>

static struct address_space_operations swap_aops = {
	.writepage	= swap_writepage,
	.sync_page	= block_sync_page,
	.set_page_dirty	= __set_page_dirty_nobuffers,
};

static struct backing_dev_info swap_backing_dev_info = {
	.memory_backed	= 1,	/* Does not contribute to dirty memory */
	.unplug_io_fn	= swap_unplug_io_fn,
};

struct address_space swapper_space = {
	.page_tree	= RADIX_TREE_INIT(GFP_ATOMIC|__GFP_NOWARN),
	.tree_lock	= SPIN_LOCK_UNLOCKED,
	.a_ops		= &swap_aops,
	.i_mmap_nonlinear = LIST_HEAD_INIT(swapper_space.i_mmap_nonlinear),
	.backing_dev_info = &swap_backing_dev_info,
};
EXPORT_SYMBOL(swapper_space);

#define INC_CACHE_INFO(x)	do { swap_cache_info.x++; } while (0)

static struct {
	unsigned long add_total;
	unsigned long del_total;
	unsigned long find_success;
	unsigned long find_total;
	unsigned long noent_race;
	unsigned long exist_race;
} swap_cache_info;

void show_swap_cache_info(void)
{
	printk("Swap cache: add %lu, delete %lu, find %lu/%lu, race %lu+%lu\n",
		swap_cache_info.add_total, swap_cache_info.del_total,
		swap_cache_info.find_success, swap_cache_info.find_total,
		swap_cache_info.noent_race, swap_cache_info.exist_race);
	printk("Free swap  = %lukB\n", nr_swap_pages << (PAGE_SHIFT - 10));
	printk("Total swap = %lukB\n", total_swap_pages << (PAGE_SHIFT - 10));
}

static int __add_to_swap_cache(struct page *page,
		swp_entry_t entry, int gfp_mask)
{
	panic("in __add_to_swap_cache");
	return 0;
}

static int add_to_swap_cache(struct page *page, swp_entry_t entry)
{
	panic("in add_to_swap_cache");
	return 0;
}

void __delete_from_swap_cache(struct page *page)
{
	panic("in __delete_from_swap_cache");
}

int add_to_swap(struct page * page)
{
	panic("in add_to_swap");
	return 0;
}

void delete_from_swap_cache(struct page *page)
{
	panic("in delete_from_swap_cache");
}

int move_to_swap_cache(struct page *page, swp_entry_t entry)
{
	panic("in move_to_swap_cache");
	return 0;
}

int move_from_swap_cache(struct page *page, unsigned long index,
		struct address_space *mapping)
{
	panic("in move_from_swap_cache");
	return 0;
}

static inline void free_swap_cache(struct page *page)
{
	panic("in free_swap_cache");
}

void free_page_and_swap_cache(struct page *page)
{
	free_swap_cache(page);
	page_cache_release(page);
}

void free_pages_and_swap_cache(struct page **pages, int nr)
{
	panic("in free_pages_and_swap_cache");
}

struct page * lookup_swap_cache(swp_entry_t entry)
{
	panic("in lookup_swap_cache");
	return NULL;
}

struct page *read_swap_cache_async(swp_entry_t entry,
			struct vm_area_struct *vma, unsigned long addr)
{
	panic("in read_swap_cache_async");
	return NULL;
}