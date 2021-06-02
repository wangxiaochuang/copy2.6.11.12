#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm_inline.h>
#include <linux/buffer_head.h>	/* for try_to_release_page() */
#include <linux/module.h>
#include <linux/percpu_counter.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/init.h>

#ifdef CONFIG_HUGETLB_PAGE
void put_page(struct page *page)
{
	if (unlikely(PageCompound(page))) {
		page = (struct page *)page->private;
		if (put_page_testzero(page)) {
			void (*dtor)(struct page *page);

			dtor = (void (*)(struct page *))page[1].mapping;
			(*dtor)(page);
		}
		return;
	}
	if (!PageReserved(page) && put_page_testzero(page))
		__page_cache_release(page);
}
EXPORT_SYMBOL(put_page);
#endif

void fastcall activate_page(struct page *page)
{
	struct zone *zone = page_zone(page);

	spin_lock_irq(&zone->lru_lock);
	if (PageLRU(page) && !PageActive(page)) {
		del_page_from_inactive_list(zone, page);
		SetPageActive(page);
		add_page_to_active_list(zone, page);
		inc_page_state(pgactivate);
	}
	spin_unlock_irq(&zone->lru_lock);
}

/*
 * Mark a page as having seen activity.
 *
 * inactive,unreferenced	->	inactive,referenced
 * inactive,referenced		->	active,unreferenced
 * active,unreferenced		->	active,referenced
 */
void fastcall mark_page_accessed(struct page *page)
{
	if (!PageActive(page) && PageReferenced(page) && PageLRU(page)) {
		activate_page(page);
		ClearPageReferenced(page);
	} else if (!PageReferenced(page)) {
		SetPageReferenced(page);
	}
}

EXPORT_SYMBOL(mark_page_accessed);

/**
 * lru_cache_add: add a page to the page lists
 * @page: the page to add
 */
static DEFINE_PER_CPU(struct pagevec, lru_add_pvecs) = { 0, };
static DEFINE_PER_CPU(struct pagevec, lru_add_active_pvecs) = { 0, };

void fastcall lru_cache_add(struct page *page)
{
	struct pagevec *pvec = &get_cpu_var(lru_add_pvecs);

	page_cache_get(page);
	if (!pagevec_add(pvec, page))
		__pagevec_lru_add(pvec);
	put_cpu_var(lru_add_pvecs);
}

void fastcall lru_cache_add_active(struct page *page)
{
	struct pagevec *pvec = &get_cpu_var(lru_add_active_pvecs);

	page_cache_get(page);
	if (!pagevec_add(pvec, page))
		__pagevec_lru_add_active(pvec);
	put_cpu_var(lru_add_active_pvecs);
}

void lru_add_drain(void)
{
	struct pagevec *pvec = &get_cpu_var(lru_add_pvecs);

	if (pagevec_count(pvec))
		__pagevec_lru_add(pvec);
	pvec = &__get_cpu_var(lru_add_active_pvecs);
	if (pagevec_count(pvec))
		__pagevec_lru_add_active(pvec);
	put_cpu_var(lru_add_pvecs);
}

void fastcall __page_cache_release(struct page *page)
{
	unsigned long flags;
	struct zone *zone = page_zone(page);

	spin_lock_irqsave(&zone->lru_lock, flags);
	if (TestClearPageLRU(page))
		del_page_from_lru(zone, page);
	if (page_count(page) != 0)
		page = NULL;
	spin_unlock_irqrestore(&zone->lru_lock, flags);
	if (page)
		free_hot_page(page);
}

EXPORT_SYMBOL(__page_cache_release);

void release_pages(struct page **pages, int nr, int cold)
{
	int i;
	struct pagevec pages_to_free;
	struct zone *zone = NULL;

	pagevec_init(&pages_to_free, cold);
	for (i = 0; i < nr; i++) {
		struct page *page = pages[i];
		struct zone *pagezone;

		if (PageReserved(page) || !put_page_testzero(page))
			continue;

		pagezone = page_zone(page);
		if (pagezone != zone) {
			if (zone)
				spin_unlock_irq(&zone->lru_lock);
			zone = pagezone;
			spin_lock_irq(&zone->lru_lock);
		}
		if (TestClearPageLRU(page))
			del_page_from_lru(zone, page);
		if (page_count(page) == 0) {
			if (!pagevec_add(&pages_to_free, page)) {
				spin_unlock_irq(&zone->lru_lock);
				__pagevec_free(&pages_to_free);
				pagevec_reinit(&pages_to_free);
				zone = NULL;	/* No lock is held */
			}
		}
	}
	if (zone)
		spin_unlock_irq(&zone->lru_lock);

	pagevec_free(&pages_to_free);
}

void __pagevec_release(struct pagevec *pvec)
{
	lru_add_drain();
	release_pages(pvec->pages, pagevec_count(pvec), pvec->cold);
	pagevec_reinit(pvec);
}

void __pagevec_lru_add(struct pagevec *pvec)
{
	int i;
	struct zone *zone = NULL;

	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];
		struct zone *pagezone = page_zone(page);

		if (pagezone != zone) {
			if (zone)
				spin_unlock_irq(&zone->lru_lock);
			zone = pagezone;
			spin_lock_irq(&zone->lru_lock);
		}
		if (TestSetPageLRU(page))
			BUG();
		add_page_to_inactive_list(zone, page);
	}
	if (zone)
		spin_unlock_irq(&zone->lru_lock);
	release_pages(pvec->pages, pvec->nr, pvec->cold);
	pagevec_reinit(pvec);
}

EXPORT_SYMBOL(__pagevec_lru_add);

void __pagevec_lru_add_active(struct pagevec *pvec)
{
	int i;
	struct zone *zone = NULL;

	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];
		struct zone *pagezone = page_zone(page);

		if (pagezone != zone) {
			if (zone)
				spin_unlock_irq(&zone->lru_lock);
			zone = pagezone;
			spin_lock_irq(&zone->lru_lock);
		}
		if (TestSetPageLRU(page))
			BUG();
		if (TestSetPageActive(page))
			BUG();
		add_page_to_active_list(zone, page);
	}
	if (zone)
		spin_unlock_irq(&zone->lru_lock);
	release_pages(pvec->pages, pvec->nr, pvec->cold);
	pagevec_reinit(pvec);
}

unsigned pagevec_lookup_tag(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t *index, int tag, unsigned nr_pages)
{
	pvec->nr = find_get_pages_tag(mapping, index, tag,
					nr_pages, pvec->pages);
	return pagevec_count(pvec);
}

#ifdef CONFIG_SMP

#define ACCT_THRESHOLD	max(16, NR_CPUS * 2)

static DEFINE_PER_CPU(long, committed_space) = 0;

void vm_acct_memory(long pages)
{
	long *local;

	preempt_disable();
	local = &__get_cpu_var(committed_space);
	*local += pages;
	if (*local > ACCT_THRESHOLD || *local < -ACCT_THRESHOLD) {
		atomic_add(*local, &vm_committed_space);
		*local = 0;
	}
	preempt_enable();
}
EXPORT_SYMBOL(vm_acct_memory);

#endif /* CONFIG_SMP */