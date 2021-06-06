#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mempool.h>
#include <linux/blkdev.h>
#include <linux/writeback.h>

static void add_element(mempool_t *pool, void *element)
{
	BUG_ON(pool->curr_nr >= pool->min_nr);
	pool->elements[pool->curr_nr++] = element;
}

static void *remove_element(mempool_t *pool)
{
	BUG_ON(pool->curr_nr <= 0);
	return pool->elements[--pool->curr_nr];
}

static void free_pool(mempool_t *pool)
{
	while (pool->curr_nr) {
		void *element = remove_element(pool);
		pool->free(element, pool->pool_data);
	}
	kfree(pool->elements);
	kfree(pool);
}

mempool_t * mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
				mempool_free_t *free_fn, void *pool_data)
{
    mempool_t *pool;

	pool = kmalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return NULL;
	memset(pool, 0, sizeof(*pool));
    pool->elements = kmalloc(min_nr * sizeof(void *), GFP_KERNEL);
	if (!pool->elements) {
		kfree(pool);
		return NULL;
	}
    spin_lock_init(&pool->lock);
	pool->min_nr = min_nr;
	pool->pool_data = pool_data;
	init_waitqueue_head(&pool->wait);
	pool->alloc = alloc_fn;
	pool->free = free_fn;

    /*
	 * First pre-allocate the guaranteed number of buffers.
	 */
	while (pool->curr_nr < pool->min_nr) {
		void *element;

		element = pool->alloc(GFP_KERNEL, pool->pool_data);
		if (unlikely(!element)) {
			free_pool(pool);
			return NULL;
		}
		add_element(pool, element);
	}
	return pool;
}

EXPORT_SYMBOL(mempool_create);

int mempool_resize(mempool_t *pool, int new_min_nr, int gfp_mask)
{
    panic("in mempool_resize");
    return 0;
}

EXPORT_SYMBOL(mempool_resize);

void mempool_destroy(mempool_t *pool)
{
	if (pool->curr_nr != pool->min_nr)
		BUG();		/* There were outstanding elements */
	free_pool(pool);
}
EXPORT_SYMBOL(mempool_destroy);

void * mempool_alloc(mempool_t *pool, int gfp_mask)
{
    void *element;
	unsigned long flags;
	DEFINE_WAIT(wait);
	int gfp_nowait = gfp_mask & ~(__GFP_WAIT | __GFP_IO);

	might_sleep_if(gfp_mask & __GFP_WAIT);
repeat_alloc:
	element = pool->alloc(gfp_nowait|__GFP_NOWARN, pool->pool_data);
	if (likely(element != NULL))
		return element;

	/*
	 * If the pool is less than 50% full and we can perform effective
	 * page reclaim then try harder to allocate an element.
	 */
	mb();
	if ((gfp_mask & __GFP_FS) && (gfp_mask != gfp_nowait) &&
				(pool->curr_nr <= pool->min_nr/2)) {
		element = pool->alloc(gfp_mask, pool->pool_data);
		if (likely(element != NULL))
			return element;
	}

	/*
	 * Kick the VM at this point.
	 */
	wakeup_bdflush(0);

	spin_lock_irqsave(&pool->lock, flags);
	if (likely(pool->curr_nr)) {
		element = remove_element(pool);
		spin_unlock_irqrestore(&pool->lock, flags);
		return element;
	}
	spin_unlock_irqrestore(&pool->lock, flags);

	/* We must not sleep in the GFP_ATOMIC case */
	if (!(gfp_mask & __GFP_WAIT))
		return NULL;

	prepare_to_wait(&pool->wait, &wait, TASK_UNINTERRUPTIBLE);
	mb();
	if (!pool->curr_nr)
		io_schedule();
	finish_wait(&pool->wait, &wait);

	goto repeat_alloc;
}

EXPORT_SYMBOL(mempool_alloc);

void mempool_free(void *element, mempool_t *pool)
{
	unsigned long flags;

	mb();
	if (pool->curr_nr < pool->min_nr) {
		spin_lock_irqsave(&pool->lock, flags);
		if (pool->curr_nr < pool->min_nr) {
			add_element(pool, element);
			spin_unlock_irqrestore(&pool->lock, flags);
			wake_up(&pool->wait);
			return;
		}
		spin_unlock_irqrestore(&pool->lock, flags);
	}
	pool->free(element, pool->pool_data);
}
EXPORT_SYMBOL(mempool_free);

void *mempool_alloc_slab(int gfp_mask, void *pool_data)
{
	kmem_cache_t *mem = (kmem_cache_t *) pool_data;
	return kmem_cache_alloc(mem, gfp_mask);
}
EXPORT_SYMBOL(mempool_alloc_slab);

void mempool_free_slab(void *element, void *pool_data)
{
	kmem_cache_t *mem = (kmem_cache_t *) pool_data;
	kmem_cache_free(mem, element);
}
EXPORT_SYMBOL(mempool_free_slab);