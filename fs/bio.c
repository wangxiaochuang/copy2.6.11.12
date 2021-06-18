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

inline void __bio_clone(struct bio *bio, struct bio *bio_src)
{
	request_queue_t *q = bdev_get_queue(bio_src->bi_bdev);

	memcpy(bio->bi_io_vec, bio_src->bi_io_vec, bio_src->bi_max_vecs * sizeof(struct bio_vec));

	bio->bi_sector = bio_src->bi_sector;
	bio->bi_bdev = bio_src->bi_bdev;
	bio->bi_flags |= 1 << BIO_CLONED;
	bio->bi_rw = bio_src->bi_rw;

	/*
	 * notes -- maybe just leave bi_idx alone. assume identical mapping
	 * for the clone
	 */
	bio->bi_vcnt = bio_src->bi_vcnt;
	bio->bi_size = bio_src->bi_size;
	bio_phys_segments(q, bio);
	bio_hw_segments(q, bio);
}

struct bio *bio_clone(struct bio *bio, int gfp_mask)
{
	struct bio *b = bio_alloc(gfp_mask, bio->bi_max_vecs);

	if (b)
		__bio_clone(b, bio);

	return b;
}

int bio_get_nr_vecs(struct block_device *bdev)
{
	request_queue_t *q = bdev_get_queue(bdev);
	int nr_pages;

	nr_pages = ((q->max_sectors << 9) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (nr_pages > q->max_phys_segments)
		nr_pages = q->max_phys_segments;
	if (nr_pages > q->max_hw_segments)
		nr_pages = q->max_hw_segments;

	return nr_pages;
}

static int __bio_add_page(request_queue_t *q, struct bio *bio, struct page
			  *page, unsigned int len, unsigned int offset)
{
	int retried_segments = 0;
	struct bio_vec *bvec;

	/*
	 * cloned bio must not modify vec list
	 */
	if (unlikely(bio_flagged(bio, BIO_CLONED)))
		return 0;

	if (bio->bi_vcnt >= bio->bi_max_vecs)
		return 0;

	if (((bio->bi_size + len) >> 9) > q->max_sectors)
		return 0;

	/*
	 * we might lose a segment or two here, but rather that than
	 * make this too complex.
	 */

	while (bio->bi_phys_segments >= q->max_phys_segments
	       || bio->bi_hw_segments >= q->max_hw_segments
	       || BIOVEC_VIRT_OVERSIZE(bio->bi_size)) {

		if (retried_segments)
			return 0;

		retried_segments = 1;
		blk_recount_segments(q, bio);
	}

	/*
	 * setup the new entry, we might clear it again later if we
	 * cannot add the page
	 */
	bvec = &bio->bi_io_vec[bio->bi_vcnt];
	bvec->bv_page = page;
	bvec->bv_len = len;
	bvec->bv_offset = offset;

	/*
	 * if queue has other restrictions (eg varying max sector size
	 * depending on offset), it can specify a merge_bvec_fn in the
	 * queue to get further control
	 */
	if (q->merge_bvec_fn) {
		/*
		 * merge_bvec_fn() returns number of bytes it can accept
		 * at this offset
		 */
		if (q->merge_bvec_fn(q, bio, bvec) < len) {
			bvec->bv_page = NULL;
			bvec->bv_len = 0;
			bvec->bv_offset = 0;
			return 0;
		}
	}

	/* If we may be able to merge these biovecs, force a recount */
	if (bio->bi_vcnt && (BIOVEC_PHYS_MERGEABLE(bvec-1, bvec) ||
	    BIOVEC_VIRT_MERGEABLE(bvec-1, bvec)))
		bio->bi_flags &= ~(1 << BIO_SEG_VALID);

	bio->bi_vcnt++;
	bio->bi_phys_segments++;
	bio->bi_hw_segments++;
	bio->bi_size += len;
	return len;
}

/**
 *	bio_add_page	-	attempt to add page to bio
 *	@bio: destination bio
 *	@page: page to add
 *	@len: vec entry length
 *	@offset: vec entry offset
 *
 *	Attempt to add a page to the bio_vec maplist. This can fail for a
 *	number of reasons, such as the bio being full or target block
 *	device limitations. The target block device must allow bio's
 *      smaller than PAGE_SIZE, so it is always possible to add a single
 *      page to an empty bio.
 */
int bio_add_page(struct bio *bio, struct page *page, unsigned int len,
		 unsigned int offset)
{
	return __bio_add_page(bdev_get_queue(bio->bi_bdev), bio, page,
			      len, offset);
}

struct bio_map_data {
	struct bio_vec *iovecs;
	void __user *userptr;
};

static void bio_set_map_data(struct bio_map_data *bmd, struct bio *bio)
{
	memcpy(bmd->iovecs, bio->bi_io_vec, sizeof(struct bio_vec) * bio->bi_vcnt);
	bio->bi_private = bmd;
}

static void bio_free_map_data(struct bio_map_data *bmd)
{
	kfree(bmd->iovecs);
	kfree(bmd);
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