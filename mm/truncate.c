#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/buffer_head.h>

static int
invalidate_complete_page(struct address_space *mapping, struct page *page)
{
	if (page->mapping != mapping)
		return 0;

	if (PagePrivate(page) && !try_to_release_page(page, 0))
		return 0;

	spin_lock_irq(&mapping->tree_lock);
	if (PageDirty(page)) {
		spin_unlock_irq(&mapping->tree_lock);
		return 0;
	}

	BUG_ON(PagePrivate(page));
	__remove_from_page_cache(page);
	spin_unlock_irq(&mapping->tree_lock);
	ClearPageUptodate(page);
	page_cache_release(page);	/* pagecache ref */
	return 1;
}

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

unsigned long invalidate_mapping_pages(struct address_space *mapping,
				pgoff_t start, pgoff_t end)
{
	struct pagevec pvec;
	pgoff_t next = start;
	unsigned long ret = 0;
	int i;

	pagevec_init(&pvec, 0);
	while (next <= end &&
			pagevec_lookup(&pvec, mapping, next, PAGEVEC_SIZE)) {
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			if (TestSetPageLocked(page)) {
				next++;
				continue;
			}
			if (page->index > next)
				next = page->index;
			next++;
			if (PageDirty(page) || PageWriteback(page))
				goto unlock;
			if (page_mapped(page))
				goto unlock;
			ret += invalidate_complete_page(mapping, page);
unlock:
			unlock_page(page);
			if (next > end)
				break;
		}
		pagevec_release(&pvec);
		cond_resched();
	}
	return ret;
}

unsigned long invalidate_inode_pages(struct address_space *mapping)
{
	return invalidate_mapping_pages(mapping, 0, ~0UL);
}

EXPORT_SYMBOL(invalidate_inode_pages);


int invalidate_inode_pages2(struct address_space *mapping)
{
	struct pagevec pvec;
	pgoff_t next = 0;
	int i;
	int ret = 0;
	int did_full_unmap = 0;

	pagevec_init(&pvec, 0);
	while (!ret && pagevec_lookup(&pvec, mapping, next, PAGEVEC_SIZE)) {
		for (i = 0; !ret && i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];
			int was_dirty;

			lock_page(page);
			if (page->mapping != mapping) {	/* truncate race? */
				unlock_page(page);
				continue;
			}
			wait_on_page_writeback(page);
			next = page->index + 1;
			while (page_mapped(page)) {
				if (!did_full_unmap) {
					/*
					 * Zap the rest of the file in one hit.
					 * FIXME: invalidate_inode_pages2()
					 * should take start/end offsets.
					 */
					unmap_mapping_range(mapping,
						page->index << PAGE_CACHE_SHIFT,
					  	-1, 0);
					did_full_unmap = 1;
				} else {
					/*
					 * Just zap this page
					 */
					unmap_mapping_range(mapping,
					  page->index << PAGE_CACHE_SHIFT,
					  (page->index << PAGE_CACHE_SHIFT)+1,
					  0);
				}
			}
			was_dirty = test_clear_page_dirty(page);
			if (!invalidate_complete_page(mapping, page)) {
				if (was_dirty)
					set_page_dirty(page);
				ret = -EIO;
			}
			unlock_page(page);
		}
		pagevec_release(&pvec);
		cond_resched();
	}
	return ret;
}
EXPORT_SYMBOL_GPL(invalidate_inode_pages2);
