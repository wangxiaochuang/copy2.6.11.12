#include <linux/mm.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/pagemap.h>
#include <linux/mempool.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/highmem.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_HIGHMEM
pte_t * pkmap_page_table;
#else /* CONFIG_HIGHMEM */
#endif

// #if defined(CONFIG_HIGHMEM) && !defined(WANT_PAGE_VIRTUAL)
// #ifndef HASHED_PAGE_VIRTUAL
// #define HASHED_PAGE_VIRTUAL 
// #endif
#if defined(HASHED_PAGE_VIRTUAL)
#define PA_HASH_ORDER	7

struct page_address_map {
    struct page *page;
    void *virtual;
    struct list_head list;
};

static struct page_address_map page_address_maps[LAST_PKMAP];

static struct list_head page_address_pool;	/* freelist */
static spinlock_t pool_lock;			/* protects page_address_pool */

static struct page_address_slot {
    struct list_head lh;
    spinlock_t lock;
} ____cacheline_aligned_in_smp page_address_htable[1<<PA_HASH_ORDER];

static struct page_address_slot *page_slot(struct page *page)
{
	return &page_address_htable[hash_ptr(page, PA_HASH_ORDER)];
}

void *page_address(struct page *page)
{
	unsigned long flags;
	void *ret;
	struct page_address_slot *pas;

    if (!PageHighMem(page))
        return lowmem_page_address(page);

    pas = page_slot(page);
    ret = NULL;
    spin_lock_irqsave(&pas->lock, flags);
    if (!list_empty(&pas->lh)) {
        struct page_address_map *pam;

        list_for_each_entry(pam, &pas->lh, list) {
            ret = pam->virtual;
            goto done;
        }
    }
done:
	spin_unlock_irqrestore(&pas->lock, flags);
	return ret;
}

EXPORT_SYMBOL(page_address);

void __init page_address_init(void) {
    int i;
    INIT_LIST_HEAD(&page_address_pool);
    for (i = 0; i < ARRAY_SIZE(page_address_maps); i++)
        list_add(&page_address_maps[i].list, &page_address_pool);
    
    for (i = 0; i < ARRAY_SIZE(page_address_htable); i++) {
        INIT_LIST_HEAD(&page_address_htable[i].lh);
        spin_lock_init(&page_address_htable[i].lock);
    }
    spin_lock_init(&pool_lock);
}
#endif /* defined(CONFIG_HIGHMEM) && !defined(WANT_PAGE_VIRTUAL) */