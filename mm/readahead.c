#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>

void default_unplug_io_fn(struct backing_dev_info *bdi, struct page *page)
{
}
EXPORT_SYMBOL(default_unplug_io_fn);

struct backing_dev_info default_backing_dev_info = {
	.ra_pages	= (VM_MAX_READAHEAD * 1024) / PAGE_CACHE_SIZE,
	.state		= 0,
	.unplug_io_fn	= default_unplug_io_fn,
};
EXPORT_SYMBOL_GPL(default_backing_dev_info);

void
file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping)
{
	ra->ra_pages = mapping->backing_dev_info->ra_pages;
	ra->prev_page = -1;
}

/*
 * Return max readahead size for this inode in number-of-pages.
 */
static inline unsigned long get_max_readahead(struct file_ra_state *ra)
{
	return ra->ra_pages;
}

static inline unsigned long get_min_readahead(struct file_ra_state *ra)
{
	return (VM_MIN_READAHEAD * 1024) / PAGE_CACHE_SIZE;
}

static inline void ra_off(struct file_ra_state *ra)
{
	ra->start = 0;
	ra->flags = 0;
	ra->size = -1;
	ra->ahead_start = 0;
	ra->ahead_size = 0;
	return;
}

static unsigned long get_init_ra_size(unsigned long size, unsigned long max)
{
	panic("in get_init_ra_size");
	return 0;
}

static unsigned long get_next_ra_size(unsigned long cur, unsigned long max,
				unsigned long min, unsigned long * flags)
{
	unsigned long newsize;

	if (*flags & RA_FLAG_MISS) {
		newsize = max((cur - 2), min);
		*flags &= ~RA_FLAG_MISS;
	} else if (cur < max / 16) {
		newsize = 4 * cur;
	} else {
		newsize = 2 * cur;
	}
	return min(newsize, max);
}

#define list_to_page(head) (list_entry((head)->prev, struct page, lru))

int read_cache_pages(struct address_space *mapping, struct list_head *pages,
			int (*filler)(void *, struct page *), void *data)
{
	panic("in read_cache_pages");
	return 0;
}

EXPORT_SYMBOL(read_cache_pages);

static int read_pages(struct address_space *mapping, struct file *filp,
		struct list_head *pages, unsigned nr_pages)
{
	panic("in read_pages");
	return 0;
}

static int
__do_page_cache_readahead(struct address_space *mapping, struct file *filp,
			unsigned long offset, unsigned long nr_to_read)
{
	panic("in __do_page_cache_readahead");
	return 0;
}

int force_page_cache_readahead(struct address_space *mapping, struct file *filp,
		unsigned long offset, unsigned long nr_to_read)
{
	panic("in force_page_cache_readahead");
	return 0;
}

int check_ra_success(struct file_ra_state *ra, unsigned long nr_to_read,
				 unsigned long actual)
{
	panic("in check_ra_success");
	return 0;
}

int do_page_cache_readahead(struct address_space *mapping, struct file *filp,
			unsigned long offset, unsigned long nr_to_read)
{
	panic("in do_page_cache_readahead");
	return 0;
}

static int
blockable_page_cache_readahead(struct address_space *mapping, struct file *filp,
			unsigned long offset, unsigned long nr_to_read,
			struct file_ra_state *ra, int block)
{
	panic("in blockable_page_cache_readahead");
	return 0;
}

unsigned long
page_cache_readahead(struct address_space *mapping, struct file_ra_state *ra,
		     struct file *filp, unsigned long offset,
		     unsigned long req_size)
{
	panic("in page_cache_readahead");
	return 0;
}

void handle_ra_miss(struct address_space *mapping,
		struct file_ra_state *ra, pgoff_t offset)
{
	ra->flags |= RA_FLAG_MISS;
	ra->flags &= ~RA_FLAG_INCACHE;
}

unsigned long max_sane_readahead(unsigned long nr)
{
	panic("in max_sane_readahead");
	return 0;
}