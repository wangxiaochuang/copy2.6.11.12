#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>

#define BIO_POOL_SIZE 256

static mempool_t *bio_pool;
static kmem_cache_t *bio_slab;

#define BIOVEC_NR_POOLS 6

/*
 * a small number of entries is fine, not going to be performance critical.
 * basically we just need to survive
 */
#define BIO_SPLIT_ENTRIES 8	
mempool_t *bio_split_pool;

struct biovec_pool {
	int nr_vecs;
	char *name; 
	kmem_cache_t *slab;
	mempool_t *pool;
};

/*
 * if you change this list, also change bvec_alloc or things will
 * break badly! cannot be bigger than what you can fit into an
 * unsigned short
 */

#define BV(x) { .nr_vecs = x, .name = "biovec-"__stringify(x) }
static struct biovec_pool bvec_array[BIOVEC_NR_POOLS] = {
	BV(1), BV(4), BV(16), BV(64), BV(128), BV(BIO_MAX_PAGES),
};
#undef BV

static inline struct bio_vec *bvec_alloc(int gfp_mask, int nr, unsigned long *idx)
{
	struct biovec_pool *bp;
	struct bio_vec *bvl;

	/*
	 * see comment near bvec_array define!
	 */
	switch (nr) {
		case   1        : *idx = 0; break;
		case   2 ...   4: *idx = 1; break;
		case   5 ...  16: *idx = 2; break;
		case  17 ...  64: *idx = 3; break;
		case  65 ... 128: *idx = 4; break;
		case 129 ... BIO_MAX_PAGES: *idx = 5; break;
		default:
			return NULL;
	}
	/*
	 * idx now points to the pool we want to allocate from
	 */
	bp = bvec_array + *idx;

	bvl = mempool_alloc(bp->pool, gfp_mask);
	if (bvl)
		memset(bvl, 0, bp->nr_vecs * sizeof(struct bio_vec));
	return bvl;
}

static void bio_destructor(struct bio *bio)
{
	const int pool_idx = BIO_POOL_IDX(bio);
	struct biovec_pool *bp = bvec_array + pool_idx;

	BIO_BUG_ON(pool_idx >= BIOVEC_NR_POOLS);

	mempool_free(bio->bi_io_vec, bp->pool);
	mempool_free(bio, bio_pool);
}

inline void bio_init(struct bio *bio)
{
	bio->bi_next = NULL;
	bio->bi_flags = 1 << BIO_UPTODATE;
	bio->bi_rw = 0;
	bio->bi_vcnt = 0;
	bio->bi_idx = 0;
	bio->bi_phys_segments = 0;
	bio->bi_hw_segments = 0;
	bio->bi_hw_front_size = 0;
	bio->bi_hw_back_size = 0;
	bio->bi_size = 0;
	bio->bi_max_vecs = 0;
	bio->bi_end_io = NULL;
	atomic_set(&bio->bi_cnt, 1);
	bio->bi_private = NULL;
}

struct bio *bio_alloc(int gfp_mask, int nr_iovecs)
{
    struct bio *bio = mempool_alloc(bio_pool, gfp_mask);

	if (likely(bio)) {
		struct bio_vec *bvl = NULL;

		bio_init(bio);
		if (likely(nr_iovecs)) {
			unsigned long idx;

			bvl = bvec_alloc(gfp_mask, nr_iovecs, &idx);
			if (unlikely(!bvl)) {
				mempool_free(bio, bio_pool);
				bio = NULL;
				goto out;
			}
			bio->bi_flags |= idx << BIO_POOL_OFFSET;
			bio->bi_max_vecs = bvec_array[idx].nr_vecs;
		}
		bio->bi_io_vec = bvl;
		bio->bi_destructor = bio_destructor;
	}
out:
	return bio;
}

void bio_put(struct bio *bio)
{
	BIO_BUG_ON(!atomic_read(&bio->bi_cnt));

	/*
	 * last put frees it
	 */
	if (atomic_dec_and_test(&bio->bi_cnt)) {
		bio->bi_next = NULL;
		bio->bi_destructor(bio);
	}
}

inline int bio_phys_segments(request_queue_t *q, struct bio *bio)
{
	if (unlikely(!bio_flagged(bio, BIO_SEG_VALID)))
		blk_recount_segments(q, bio);

	return bio->bi_phys_segments;
}

inline int bio_hw_segments(request_queue_t *q, struct bio *bio)
{
	if (unlikely(!bio_flagged(bio, BIO_SEG_VALID)))
		blk_recount_segments(q, bio);

	return bio->bi_hw_segments;
}






void bio_endio(struct bio *bio, unsigned int bytes_done, int error)
{
	if (error)
		clear_bit(BIO_UPTODATE, &bio->bi_flags);

	if (unlikely(bytes_done > bio->bi_size)) {
		printk("%s: want %u bytes done, only %u left\n", __FUNCTION__,
						bytes_done, bio->bi_size);
		bytes_done = bio->bi_size;
	}

	bio->bi_size -= bytes_done;
	bio->bi_sector += (bytes_done >> 9);

	if (bio->bi_end_io)
		bio->bi_end_io(bio, bytes_done, error);
}


static void *bio_pair_alloc(int gfp_flags, void *data)
{
	return kmalloc(sizeof(struct bio_pair), gfp_flags);
}

static void bio_pair_free(void *bp, void *data)
{
	kfree(bp);
}

static void __init biovec_init_pools(void)
{
	int i, size, megabytes, pool_entries = BIO_POOL_SIZE;
	int scale = BIOVEC_NR_POOLS;

	megabytes = nr_free_pages() >> (20 - PAGE_SHIFT);

	/*
	 * find out where to start scaling
	 */
	if (megabytes <= 16)
		scale = 0;
	else if (megabytes <= 32)
		scale = 1;
	else if (megabytes <= 64)
		scale = 2;
	else if (megabytes <= 96)
		scale = 3;
	else if (megabytes <= 128)
		scale = 4;

	/*
	 * scale number of entries
	 */
	pool_entries = megabytes * 2;
	if (pool_entries > 256)
		pool_entries = 256;

	for (i = 0; i < BIOVEC_NR_POOLS; i++) {
		struct biovec_pool *bp = bvec_array + i;

		size = bp->nr_vecs * sizeof(struct bio_vec);

		bp->slab = kmem_cache_create(bp->name, size, 0,
				SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);

		if (i >= scale)
			pool_entries >>= 1;

		bp->pool = mempool_create(pool_entries, mempool_alloc_slab,
					mempool_free_slab, bp->slab);
		if (!bp->pool)
			panic("biovec: can't init mempool\n");
	}
}

static int __init init_bio(void)
{
	bio_slab = kmem_cache_create("bio", sizeof(struct bio), 0,
				SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
	bio_pool = mempool_create(BIO_POOL_SIZE, mempool_alloc_slab,
				mempool_free_slab, bio_slab);
	if (!bio_pool)
		panic("bio: can't create mempool\n");

	biovec_init_pools();

	bio_split_pool = mempool_create(BIO_SPLIT_ENTRIES,
				bio_pair_alloc, bio_pair_free, NULL);
	if (!bio_split_pool)
		panic("bio: can't create split pool\n");

	return 0;
}

subsys_initcall(init_bio);