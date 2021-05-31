#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/acct.h>
#include <linux/rmap.h>
#include <linux/rcupdate.h>

#include <asm/tlbflush.h>

kmem_cache_t *anon_vma_cachep;

static inline void validate_anon_vma(struct vm_area_struct *find_vma)
{
#ifdef RMAP_DEBUG
#error "RMAP_DEBUG"
#endif
}

/* This must be called under the mmap_sem. */
int anon_vma_prepare(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	might_sleep();
	if (unlikely(!anon_vma)) {
		struct mm_struct *mm = vma->vm_mm;
		struct anon_vma *allocated, *locked;

		anon_vma = find_mergeable_anon_vma(vma);
		if (anon_vma) {
			allocated = NULL;
			locked = anon_vma;
			spin_lock(&locked->lock);
		} else {
			anon_vma = anon_vma_alloc();
			if (unlikely(!anon_vma))
				return -ENOMEM;
			allocated = anon_vma;
			locked = NULL;
		}

		/* page_table_lock to protect against threads */
		spin_lock(&mm->page_table_lock);
		if (likely(!vma->anon_vma)) {
			vma->anon_vma = anon_vma;
			list_add(&vma->anon_vma_node, &anon_vma->head);
			allocated = NULL;
		}
		spin_unlock(&mm->page_table_lock);

		if (locked)
			spin_unlock(&locked->lock);
		if (unlikely(allocated))
			anon_vma_free(allocated);
	}
	return 0;
}


void __anon_vma_merge(struct vm_area_struct *vma, struct vm_area_struct *next)
{
	BUG_ON(vma->anon_vma != next->anon_vma);
	list_del(&next->anon_vma_node);
}

void __anon_vma_link(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	if (anon_vma) {
		list_add(&vma->anon_vma_node, &anon_vma->head);
		validate_anon_vma(vma);
	}
}

void anon_vma_link(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	if (anon_vma) {
		spin_lock(&anon_vma->lock);
		list_add(&vma->anon_vma_node, &anon_vma->head);
		validate_anon_vma(vma);
		spin_unlock(&anon_vma->lock);
	}
}

void anon_vma_unlink(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	int empty;

	if (!anon_vma)
		return;

	spin_lock(&anon_vma->lock);
	validate_anon_vma(vma);
	list_del(&vma->anon_vma_node);

	/* We must garbage collect the anon_vma if it's empty */
	empty = list_empty(&anon_vma->head);
	spin_unlock(&anon_vma->lock);

	if (empty)
		anon_vma_free(anon_vma);
}

static void anon_vma_ctor(void *data, kmem_cache_t *cachep, unsigned long flags)
{
	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
						SLAB_CTOR_CONSTRUCTOR) {
		struct anon_vma *anon_vma = data;

		spin_lock_init(&anon_vma->lock);
		INIT_LIST_HEAD(&anon_vma->head);
	}
}

void __init anon_vma_init(void)
{
	anon_vma_cachep = kmem_cache_create("anon_vma", sizeof(struct anon_vma),
			0, SLAB_DESTROY_BY_RCU|SLAB_PANIC, anon_vma_ctor, NULL);
}

void page_add_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	pgoff_t index;

	BUG_ON(PageReserved(page));
	BUG_ON(!anon_vma);

	vma->vm_mm->anon_rss++;

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	index = (address - vma->vm_start) >> PAGE_SHIFT;
	index += vma->vm_pgoff;
	index >>= PAGE_CACHE_SHIFT - PAGE_SHIFT;

	if (atomic_inc_and_test(&page->_mapcount)) {
		page->index = index;
		page->mapping = (struct address_space *) anon_vma;
		inc_page_state(nr_mapped);
	}
	/* else checking page index and mapping is racy */
}

void page_add_file_rmap(struct page *page)
{
	BUG_ON(PageAnon(page));
	if (!pfn_valid(page_to_pfn(page)) || PageReserved(page))
		return;

	if (atomic_inc_and_test(&page->_mapcount))
		inc_page_state(nr_mapped);
}

void page_remove_rmap(struct page *page)
{
	BUG_ON(PageReserved(page));

	if (atomic_add_negative(-1, &page->_mapcount)) {
		BUG_ON(page_mapcount(page) < 0);
		if (page_test_and_clear_dirty(page))
			set_page_dirty(page);
		dec_page_state(nr_mapped);
	}
}