#include <linux/config.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/shm.h>
#include <linux/blkdev.h>
#include <linux/writeback.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rmap.h>
#include <linux/security.h>
#include <linux/acct.h>
#include <linux/backing-dev.h>
#include <linux/syscalls.h>

#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/swapops.h>

DEFINE_SPINLOCK(swaplock);
unsigned int nr_swapfiles;
long total_swap_pages;

EXPORT_SYMBOL(total_swap_pages);

static const char Bad_file[] = "Bad swap file entry ";
static const char Unused_file[] = "Unused swap file entry ";
static const char Bad_offset[] = "Bad swap offset entry ";
static const char Unused_offset[] = "Unused swap offset entry ";

struct swap_list_t swap_list = {-1, -1};

struct swap_info_struct swap_info[MAX_SWAPFILES];

void swap_unplug_io_fn(struct backing_dev_info *unused_bdi, struct page *page)
{
    panic("in swap_unplug_io_fn function");
}

static struct swap_info_struct * swap_info_get(swp_entry_t entry)
{
	struct swap_info_struct * p;
	unsigned long offset, type;

	if (!entry.val)
		goto out;
	type = swp_type(entry);
	if (type >= nr_swapfiles)
		goto bad_nofile;
	p = & swap_info[type];
	if (!(p->flags & SWP_USED))
		goto bad_device;
	offset = swp_offset(entry);
	if (offset >= p->max)
		goto bad_offset;
	if (!p->swap_map[offset])
		goto bad_free;
	swap_list_lock();
	if (p->prio > swap_info[swap_list.next].prio)
		swap_list.next = type;
	swap_device_lock(p);
	return p;

bad_free:
	printk(KERN_ERR "swap_free: %s%08lx\n", Unused_offset, entry.val);
	goto out;
bad_offset:
	printk(KERN_ERR "swap_free: %s%08lx\n", Bad_offset, entry.val);
	goto out;
bad_device:
	printk(KERN_ERR "swap_free: %s%08lx\n", Unused_file, entry.val);
	goto out;
bad_nofile:
	printk(KERN_ERR "swap_free: %s%08lx\n", Bad_file, entry.val);
out:
	return NULL;
}

static void swap_info_put(struct swap_info_struct * p)
{
	swap_device_unlock(p);
	swap_list_unlock();
}

void swap_free(swp_entry_t entry)
{
}

/*
 * Check if we're the only user of a swap page,
 * when the page is locked.
 */
static int exclusive_swap_page(struct page *page)
{
	int retval = 0;
	struct swap_info_struct * p;
	swp_entry_t entry;

	entry.val = page->private;
	p = swap_info_get(entry);
	if (p) {
		/* Is the only swap cache user the cache itself? */
		if (p->swap_map[swp_offset(entry)] == 1) {
			/* Recheck the page count with the swapcache lock held.. */
			spin_lock_irq(&swapper_space.tree_lock);
			if (page_count(page) == 2)
				retval = 1;
			spin_unlock_irq(&swapper_space.tree_lock);
		}
		swap_info_put(p);
	}
	return retval;
}

int can_share_swap_page(struct page *page)
{
    int retval = 0;

	if (!PageLocked(page))
		BUG();
    
    switch (page_count(page)) {
    case 3:
        if (!PagePrivate(page))
        break;
        /* Fallthrough */
    case 2:
		if (!PageSwapCache(page))
			break;
		retval = exclusive_swap_page(page);
		break;
	case 1:
		if (PageReserved(page))
			break;
		retval = 1;
    }
    return retval;
}