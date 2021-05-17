#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/buffer_head.h>

void truncate_inode_pages(struct address_space *mapping, loff_t lstart)
{
    const pgoff_t start = (lstart + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;
	const unsigned partial = lstart & (PAGE_CACHE_SIZE - 1);
	struct pagevec pvec;
	pgoff_t next;
	int i;

	if (mapping->nrpages == 0)
		return;

    panic("in truncate_inode_pages function");
}