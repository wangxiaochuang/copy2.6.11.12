#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/bootmem.h>	/* for max_pfn/max_low_pfn */
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/writeback.h>

/*
 * for max sense size
 */
#include <scsi/scsi_cmnd.h>

static void blk_unplug_work(void *data);
static void blk_unplug_timeout(unsigned long data);

/*
 * For the allocated request tables
 */
static kmem_cache_t *request_cachep;

/*
 * For queue allocation
 */
static kmem_cache_t *requestq_cachep;

/*
 * For io context allocations
 */
static kmem_cache_t *iocontext_cachep;

static wait_queue_head_t congestion_wqh[2] = {
		__WAIT_QUEUE_HEAD_INITIALIZER(congestion_wqh[0]),
		__WAIT_QUEUE_HEAD_INITIALIZER(congestion_wqh[1])
	};

/*
 * Controlling structure to kblockd
 */
static struct workqueue_struct *kblockd_workqueue; 

unsigned long blk_max_low_pfn, blk_max_pfn;

EXPORT_SYMBOL(blk_max_low_pfn);
EXPORT_SYMBOL(blk_max_pfn);

/* Amount of time in which a process may batch requests */
#define BLK_BATCH_TIME	(HZ/50UL)

/* Number of requests a "batching" process may submit */
#define BLK_BATCH_REQ	32

static inline int queue_congestion_on_threshold(struct request_queue *q)
{
	return q->nr_congestion_on;
}

static inline int queue_congestion_off_threshold(struct request_queue *q)
{
	return q->nr_congestion_off;
}

static void blk_queue_congestion_threshold(struct request_queue *q)
{
	int nr;

	nr = q->nr_requests - (q->nr_requests / 8) + 1;
	if (nr > q->nr_requests)
		nr = q->nr_requests;
	q->nr_congestion_on = nr;

	nr = q->nr_requests - (q->nr_requests / 8) - (q->nr_requests / 16) - 1;
	if (nr < 1)
		nr = 1;
	q->nr_congestion_off = nr;
}

static void clear_queue_congested(request_queue_t *q, int rw)
{
	enum bdi_state bit;
	wait_queue_head_t *wqh = &congestion_wqh[rw];

	bit = (rw == WRITE) ? BDI_write_congested : BDI_read_congested;
	clear_bit(bit, &q->backing_dev_info.state);
	smp_mb__after_clear_bit();
	if (waitqueue_active(wqh))
		wake_up(wqh);
}

static void set_queue_congested(request_queue_t *q, int rw)
{
	enum bdi_state bit;

	bit = (rw == WRITE) ? BDI_write_congested : BDI_read_congested;
	set_bit(bit, &q->backing_dev_info.state);
}

struct backing_dev_info *blk_get_backing_dev_info(struct block_device *bdev)
{
	struct backing_dev_info *ret = NULL;
	request_queue_t *q = bdev_get_queue(bdev);

	if (q)
		ret = &q->backing_dev_info;
	return ret;
}

EXPORT_SYMBOL(blk_get_backing_dev_info);

void blk_queue_activity_fn(request_queue_t *q, activity_fn *fn, void *data)
{
	q->activity_fn = fn;
	q->activity_data = data;
}

EXPORT_SYMBOL(blk_queue_activity_fn);

void blk_queue_prep_rq(request_queue_t *q, prep_rq_fn *pfn)
{
	panic("in blk_queue_prep_rq");
}

EXPORT_SYMBOL(blk_queue_prep_rq);

void blk_queue_merge_bvec(request_queue_t *q, merge_bvec_fn *mbfn)
{
	panic("in blk_queue_merge_bvec");
}

EXPORT_SYMBOL(blk_queue_merge_bvec);

void blk_queue_make_request(request_queue_t * q, make_request_fn * mfn)
{
	/*
	 * set defaults
	 */
	q->nr_requests = BLKDEV_MAX_RQ;
	q->max_phys_segments = MAX_PHYS_SEGMENTS;
	q->max_hw_segments = MAX_HW_SEGMENTS;
	q->make_request_fn = mfn;
	q->backing_dev_info.ra_pages = (VM_MAX_READAHEAD * 1024) / PAGE_CACHE_SIZE;
	q->backing_dev_info.state = 0;
	q->backing_dev_info.memory_backed = 0;
	blk_queue_max_sectors(q, MAX_SECTORS);
	blk_queue_hardsect_size(q, 512);
	blk_queue_dma_alignment(q, 511);
	blk_queue_congestion_threshold(q);
	q->nr_batching = BLK_BATCH_REQ;

	q->unplug_thresh = 4;		/* hmm */
	q->unplug_delay = (3 * HZ) / 1000;	/* 3 milliseconds */
	if (q->unplug_delay == 0)
		q->unplug_delay = 1;

	INIT_WORK(&q->unplug_work, blk_unplug_work, q);

	q->unplug_timer.function = blk_unplug_timeout; // ###### import
	q->unplug_timer.data = (unsigned long)q;

	/*
	 * by default assume old behaviour and bounce for any highmem page
	 */
	blk_queue_bounce_limit(q, BLK_BOUNCE_HIGH);

	blk_queue_activity_fn(q, NULL, NULL);

	INIT_LIST_HEAD(&q->drain_list);
}

EXPORT_SYMBOL(blk_queue_make_request);

void blk_queue_ordered(request_queue_t *q, int flag)
{
	panic("in blk_queue_ordered");
}

EXPORT_SYMBOL(blk_queue_ordered);

void blk_queue_issue_flush_fn(request_queue_t *q, issue_flush_fn *iff)
{
	panic("in blk_queue_issue_flush_fn");
}

EXPORT_SYMBOL(blk_queue_issue_flush_fn);

void blk_queue_bounce_limit(request_queue_t *q, u64 dma_addr)
{
	unsigned long bounce_pfn = dma_addr >> PAGE_SHIFT;

	/*
	 * set appropriate bounce gfp mask -- unfortunately we don't have a
	 * full 4GB zone, so we have to resort to low memory for any bounces.
	 * ISA has its own < 16MB zone.
	 */
	if (bounce_pfn < blk_max_low_pfn) {
		BUG_ON(dma_addr < BLK_BOUNCE_ISA);
		init_emergency_isa_pool();
		q->bounce_gfp = GFP_NOIO | GFP_DMA;
	} else
		q->bounce_gfp = GFP_NOIO;

	q->bounce_pfn = bounce_pfn;
}

EXPORT_SYMBOL(blk_queue_bounce_limit);

void blk_queue_max_sectors(request_queue_t *q, unsigned short max_sectors)
{
	if ((max_sectors << 9) < PAGE_CACHE_SIZE) {
		max_sectors = 1 << (PAGE_CACHE_SHIFT - 9);
		printk("%s: set to minimum %d\n", __FUNCTION__, max_sectors);
	}

	q->max_sectors = q->max_hw_sectors = max_sectors;
}

EXPORT_SYMBOL(blk_queue_max_sectors);

void blk_queue_max_phys_segments(request_queue_t *q, unsigned short max_segments)
{
	if (!max_segments) {
		max_segments = 1;
		printk("%s: set to minimum %d\n", __FUNCTION__, max_segments);
	}

	q->max_phys_segments = max_segments;
}

EXPORT_SYMBOL(blk_queue_max_phys_segments);

void blk_queue_max_hw_segments(request_queue_t *q, unsigned short max_segments)
{
	if (!max_segments) {
		max_segments = 1;
		printk("%s: set to minimum %d\n", __FUNCTION__, max_segments);
	}

	q->max_hw_segments = max_segments;
}

EXPORT_SYMBOL(blk_queue_max_hw_segments);

void blk_queue_max_segment_size(request_queue_t *q, unsigned int max_size)
{
	if (max_size < PAGE_CACHE_SIZE) {
		max_size = PAGE_CACHE_SIZE;
		printk("%s: set to minimum %d\n", __FUNCTION__, max_size);
	}

	q->max_segment_size = max_size;
}

EXPORT_SYMBOL(blk_queue_max_segment_size);

void blk_queue_hardsect_size(request_queue_t *q, unsigned short size)
{
	q->hardsect_size = size;
}

EXPORT_SYMBOL(blk_queue_hardsect_size);

#define min_not_zero(l, r) (l == 0) ? r : ((r == 0) ? l : min(l, r))

void blk_queue_stack_limits(request_queue_t *t, request_queue_t *b)
{
	panic("in blk_queue_stack_limits");
}

EXPORT_SYMBOL(blk_queue_stack_limits);

void blk_queue_segment_boundary(request_queue_t *q, unsigned long mask)
{
	if (mask < PAGE_CACHE_SIZE - 1) {
		mask = PAGE_CACHE_SIZE - 1;
		printk("%s: set to minimum %lx\n", __FUNCTION__, mask);
	}

	q->seg_boundary_mask = mask;
}

EXPORT_SYMBOL(blk_queue_segment_boundary);

void blk_queue_dma_alignment(request_queue_t *q, int mask)
{
	q->dma_alignment = mask;
}

EXPORT_SYMBOL(blk_queue_dma_alignment);

struct request *blk_queue_find_tag(request_queue_t *q, int tag)
{
	struct blk_queue_tag *bqt = q->queue_tags;

	if (unlikely(bqt == NULL || tag >= bqt->real_max_depth))
		return NULL;

	return bqt->tag_index[tag];
}

EXPORT_SYMBOL(blk_queue_find_tag);

static void __blk_queue_free_tags(request_queue_t *q)
{
	struct blk_queue_tag *bqt = q->queue_tags;

	if (!bqt)
		return;

	if (atomic_dec_and_test(&bqt->refcnt)) {
		BUG_ON(bqt->busy);
		BUG_ON(!list_empty(&bqt->busy_list));

		kfree(bqt->tag_index);
		bqt->tag_index = NULL;

		kfree(bqt->tag_map);
		bqt->tag_map = NULL;

		kfree(bqt);
	}

	q->queue_tags = NULL;
	q->queue_flags &= ~(1 << QUEUE_FLAG_QUEUED);
}

void blk_queue_free_tags(request_queue_t *q)
{
	clear_bit(QUEUE_FLAG_QUEUED, &q->queue_flags);
}

EXPORT_SYMBOL(blk_queue_free_tags);

static int
init_tag_map(request_queue_t *q, struct blk_queue_tag *tags, int depth)
{
	int bits, i;
	struct request **tag_index;
	unsigned long *tag_map;

	if (depth > q->nr_requests * 2) {
		depth = q->nr_requests * 2;
		printk(KERN_ERR "%s: adjusted depth to %d\n",
				__FUNCTION__, depth);
	}

	tag_index = kmalloc(depth * sizeof(struct request *), GFP_ATOMIC);
	if (!tag_index)
		goto fail;

	bits = (depth / BLK_TAGS_PER_LONG) + 1;
	tag_map = kmalloc(bits * sizeof(unsigned long), GFP_ATOMIC);
	if (!tag_map)
		goto fail;

	memset(tag_index, 0, depth * sizeof(struct request *));
	memset(tag_map, 0, bits * sizeof(unsigned long));
	tags->max_depth = depth;
	tags->real_max_depth = bits * BITS_PER_LONG;
	tags->tag_index = tag_index;
	tags->tag_map = tag_map;

	/*
	 * set the upper bits if the depth isn't a multiple of the word size
	 */
	for (i = depth; i < bits * BLK_TAGS_PER_LONG; i++)
		__set_bit(i, tag_map);

	return 0;
fail:
	kfree(tag_index);
	return -ENOMEM;
}

int blk_queue_init_tags(request_queue_t *q, int depth,
			struct blk_queue_tag *tags)
{
	int rc;

	BUG_ON(tags && q->queue_tags && tags != q->queue_tags);

	if (!tags && !q->queue_tags) {
		tags = kmalloc(sizeof(struct blk_queue_tag), GFP_ATOMIC);
		if (!tags)
			goto fail;

		if (init_tag_map(q, tags, depth))
			goto fail;

		INIT_LIST_HEAD(&tags->busy_list);
		tags->busy = 0;
		atomic_set(&tags->refcnt, 1);
	} else if (q->queue_tags) {
		if ((rc = blk_queue_resize_tags(q, depth)))
			return rc;
		set_bit(QUEUE_FLAG_QUEUED, &q->queue_flags);
		return 0;
	} else
		atomic_inc(&tags->refcnt);

	/*
	 * assign it, all done
	 */
	q->queue_tags = tags;
	q->queue_flags |= (1 << QUEUE_FLAG_QUEUED);
	return 0;
fail:
	kfree(tags);
	return -ENOMEM;
}

EXPORT_SYMBOL(blk_queue_init_tags);

int blk_queue_resize_tags(request_queue_t *q, int new_depth)
{
	struct blk_queue_tag *bqt = q->queue_tags;
	struct request **tag_index;
	unsigned long *tag_map;
	int bits, max_depth;

	if (!bqt)
		return -ENXIO;

	/*
	 * don't bother sizing down
	 */
	if (new_depth <= bqt->real_max_depth) {
		bqt->max_depth = new_depth;
		return 0;
	}

	/*
	 * save the old state info, so we can copy it back
	 */
	tag_index = bqt->tag_index;
	tag_map = bqt->tag_map;
	max_depth = bqt->real_max_depth;

	if (init_tag_map(q, bqt, new_depth))
		return -ENOMEM;

	memcpy(bqt->tag_index, tag_index, max_depth * sizeof(struct request *));
	bits = max_depth / BLK_TAGS_PER_LONG;
	memcpy(bqt->tag_map, tag_map, bits * sizeof(unsigned long));

	kfree(tag_index);
	kfree(tag_map);
	return 0;
}

EXPORT_SYMBOL(blk_queue_resize_tags);

void blk_queue_end_tag(request_queue_t *q, struct request *rq)
{
	struct blk_queue_tag *bqt = q->queue_tags;
	int tag = rq->tag;

	BUG_ON(tag == -1);

	if (unlikely(tag >= bqt->real_max_depth))
		return;

	if (unlikely(!__test_and_clear_bit(tag, bqt->tag_map))) {
		printk("attempt to clear non-busy tag (%d)\n", tag);
		return;
	}

	list_del_init(&rq->queuelist);
	rq->flags &= ~REQ_QUEUED;
	rq->tag = -1;

	if (unlikely(bqt->tag_index[tag] == NULL))
		printk("tag %d is missing\n", tag);

	bqt->tag_index[tag] = NULL;
	bqt->busy--;
}

EXPORT_SYMBOL(blk_queue_end_tag);

int blk_queue_start_tag(request_queue_t *q, struct request *rq)
{
	panic("in blk_queue_start_tag");
	return 0;
}

EXPORT_SYMBOL(blk_queue_start_tag);

void blk_queue_invalidate_tags(request_queue_t *q)
{
	panic("in blk_queue_invalidate_tags");
}

EXPORT_SYMBOL(blk_queue_invalidate_tags);

void blk_dump_rq_flags(struct request *rq, char *msg)
{
	panic("in blk_dump_rq_flags");
}

EXPORT_SYMBOL(blk_dump_rq_flags);

void blk_recount_segments(request_queue_t *q, struct bio *bio)
{
	struct bio_vec *bv, *bvprv = NULL;
	int i, nr_phys_segs, nr_hw_segs, seg_size, hw_seg_size, cluster;
	int high, highprv = 1;

	if (unlikely(!bio->bi_io_vec))
		return;

	cluster = q->queue_flags & (1 << QUEUE_FLAG_CLUSTER);
	hw_seg_size = seg_size = nr_phys_segs = nr_hw_segs = 0;
	bio_for_each_segment(bv, bio, i) {
		/*
		 * the trick here is making sure that a high page is never
		 * considered part of another segment, since that might
		 * change with the bounce page.
		 */
		high = page_to_pfn(bv->bv_page) >= q->bounce_pfn;
		if (high || highprv)
			goto new_hw_segment;
		if (cluster) {
			if (seg_size + bv->bv_len > q->max_segment_size)
				goto new_segment;
			if (!BIOVEC_PHYS_MERGEABLE(bvprv, bv))
				goto new_segment;
			if (!BIOVEC_SEG_BOUNDARY(q, bvprv, bv))
				goto new_segment;
			if (BIOVEC_VIRT_OVERSIZE(hw_seg_size + bv->bv_len))
				goto new_hw_segment;

			seg_size += bv->bv_len;
			hw_seg_size += bv->bv_len;
			bvprv = bv;
			continue;
		}
new_segment:
		if (BIOVEC_VIRT_MERGEABLE(bvprv, bv) &&
		    !BIOVEC_VIRT_OVERSIZE(hw_seg_size + bv->bv_len)) {
			hw_seg_size += bv->bv_len;
		} else {
new_hw_segment:
			if (hw_seg_size > bio->bi_hw_front_size)
				bio->bi_hw_front_size = hw_seg_size;
			hw_seg_size = BIOVEC_VIRT_START_SIZE(bv) + bv->bv_len;
			nr_hw_segs++;
		}

		nr_phys_segs++;
		bvprv = bv;
		seg_size = bv->bv_len;
		highprv = high;
	}
	if (hw_seg_size > bio->bi_hw_back_size)
		bio->bi_hw_back_size = hw_seg_size;
	if (nr_hw_segs == 1 && hw_seg_size > bio->bi_hw_front_size)
		bio->bi_hw_front_size = hw_seg_size;
	bio->bi_phys_segments = nr_phys_segs;
	bio->bi_hw_segments = nr_hw_segs;
	bio->bi_flags |= (1 << BIO_SEG_VALID);
}

int blk_phys_contig_segment(request_queue_t *q, struct bio *bio,
				   struct bio *nxt)
{
	if (!(q->queue_flags & (1 << QUEUE_FLAG_CLUSTER)))
		return 0;

	if (!BIOVEC_PHYS_MERGEABLE(__BVEC_END(bio), __BVEC_START(nxt)))
		return 0;
	if (bio->bi_size + nxt->bi_size > q->max_segment_size)
		return 0;

	/*
	 * bio and nxt are contigous in memory, check if the queue allows
	 * these two to be merged into one
	 */
	if (BIO_SEG_BOUNDARY(q, bio, nxt))
		return 1;

	return 0;
}

EXPORT_SYMBOL(blk_phys_contig_segment);

int blk_hw_contig_segment(request_queue_t *q, struct bio *bio,
				 struct bio *nxt)
{
	if (unlikely(!bio_flagged(bio, BIO_SEG_VALID)))
		blk_recount_segments(q, bio);
	if (unlikely(!bio_flagged(nxt, BIO_SEG_VALID)))
		blk_recount_segments(q, nxt);
	if (!BIOVEC_VIRT_MERGEABLE(__BVEC_END(bio), __BVEC_START(nxt)) ||
	    BIOVEC_VIRT_OVERSIZE(bio->bi_hw_front_size + bio->bi_hw_back_size))
		return 0;
	if (bio->bi_size + nxt->bi_size > q->max_segment_size)
		return 0;

	return 1;
}

EXPORT_SYMBOL(blk_hw_contig_segment);

int blk_rq_map_sg(request_queue_t *q, struct request *rq, struct scatterlist *sg)
{
	panic("in blk_rq_map_sg");
	return 0;
}

EXPORT_SYMBOL(blk_rq_map_sg);

static inline int ll_new_mergeable(request_queue_t *q,
				   struct request *req,
				   struct bio *bio)
{
	int nr_phys_segs = bio_phys_segments(q, bio);

	if (req->nr_phys_segments + nr_phys_segs > q->max_phys_segments) {
		req->flags |= REQ_NOMERGE;
		if (req == q->last_merge)
			q->last_merge = NULL;
		return 0;
	}

	/*
	 * A hw segment is just getting larger, bump just the phys
	 * counter.
	 */
	req->nr_phys_segments += nr_phys_segs;
	return 1;
}

static inline int ll_new_hw_segment(request_queue_t *q,
				    struct request *req,
				    struct bio *bio)
{
	int nr_hw_segs = bio_hw_segments(q, bio);
	int nr_phys_segs = bio_phys_segments(q, bio);

	if (req->nr_hw_segments + nr_hw_segs > q->max_hw_segments
	    || req->nr_phys_segments + nr_phys_segs > q->max_phys_segments) {
		req->flags |= REQ_NOMERGE;
		if (req == q->last_merge)
			q->last_merge = NULL;
		return 0;
	}

	/*
	 * This will form the start of a new hw segment.  Bump both
	 * counters.
	 */
	req->nr_hw_segments += nr_hw_segs;
	req->nr_phys_segments += nr_phys_segs;
	return 1;
}

static int ll_back_merge_fn(request_queue_t *q, struct request *req, 
			    struct bio *bio)
{
	int len;

	if (req->nr_sectors + bio_sectors(bio) > q->max_sectors) {
		req->flags |= REQ_NOMERGE;
		if (req == q->last_merge)
			q->last_merge = NULL;
		return 0;
	}
	if (unlikely(!bio_flagged(req->biotail, BIO_SEG_VALID)))
		blk_recount_segments(q, req->biotail);
	if (unlikely(!bio_flagged(bio, BIO_SEG_VALID)))
		blk_recount_segments(q, bio);
	len = req->biotail->bi_hw_back_size + bio->bi_hw_front_size;
	if (BIOVEC_VIRT_MERGEABLE(__BVEC_END(req->biotail), __BVEC_START(bio)) &&
	    !BIOVEC_VIRT_OVERSIZE(len)) {
		int mergeable =  ll_new_mergeable(q, req, bio);

		if (mergeable) {
			if (req->nr_hw_segments == 1)
				req->bio->bi_hw_front_size = len;
			if (bio->bi_hw_segments == 1)
				bio->bi_hw_back_size = len;
		}
		return mergeable;
	}

	return ll_new_hw_segment(q, req, bio);
}

static int ll_front_merge_fn(request_queue_t *q, struct request *req, 
			     struct bio *bio)
{
	panic("in ll_front_merge_fn");
	return 0;
}

static int ll_merge_requests_fn(request_queue_t *q, struct request *req,
				struct request *next)
{
	panic("in ll_merge_requests_fn");
	return 0;
}

void blk_plug_device(request_queue_t *q)
{
	WARN_ON(!irqs_disabled());

	/*
	 * don't plug a stopped queue, it must be paired with blk_start_queue()
	 * which will restart the queueing
	 */
	if (test_bit(QUEUE_FLAG_STOPPED, &q->queue_flags))
		return;

	if (!test_and_set_bit(QUEUE_FLAG_PLUGGED, &q->queue_flags))
		mod_timer(&q->unplug_timer, jiffies + q->unplug_delay);
}

EXPORT_SYMBOL(blk_plug_device);

int blk_remove_plug(request_queue_t *q)
{
	WARN_ON(!irqs_disabled());

	if (!test_and_clear_bit(QUEUE_FLAG_PLUGGED, &q->queue_flags))
		return 0;

	del_timer(&q->unplug_timer);
	return 1;
}

EXPORT_SYMBOL(blk_remove_plug);

void __generic_unplug_device(request_queue_t *q)
{
	if (test_bit(QUEUE_FLAG_STOPPED, &q->queue_flags))
		return;

	if (!blk_remove_plug(q))
		return;

	/*
	 * was plugged, fire request_fn if queue has stuff to do
	 */
	if (elv_next_request(q))
		q->request_fn(q);
}

EXPORT_SYMBOL(__generic_unplug_device);

void generic_unplug_device(request_queue_t *q)
{
	spin_lock_irq(q->queue_lock);
	__generic_unplug_device(q);
	spin_unlock_irq(q->queue_lock);
}
EXPORT_SYMBOL(generic_unplug_device);

static void blk_backing_dev_unplug(struct backing_dev_info *bdi,
				   struct page *page)
{
	request_queue_t *q = bdi->unplug_io_data;

	if (q->unplug_fn)
		q->unplug_fn(q);
}

static void blk_unplug_work(void *data)
{
	request_queue_t *q = data;

	q->unplug_fn(q);
}

static void blk_unplug_timeout(unsigned long data)
{
	request_queue_t *q = (request_queue_t *)data;

	kblockd_schedule_work(&q->unplug_work);
}

void blk_start_queue(request_queue_t *q)
{
	panic("in blk_start_queue");
}

EXPORT_SYMBOL(blk_start_queue);

void blk_stop_queue(request_queue_t *q)
{
	panic("in blk_stop_queue");
}
EXPORT_SYMBOL(blk_stop_queue);

void blk_sync_queue(struct request_queue *q)
{
	del_timer_sync(&q->unplug_timer);
	kblockd_flush();
}
EXPORT_SYMBOL(blk_sync_queue);

void blk_run_queue(struct request_queue *q)
{
	panic("in blk_run_queue");
}
EXPORT_SYMBOL(blk_run_queue);

void blk_cleanup_queue(request_queue_t * q)
{
	struct request_list *rl = &q->rq;

	if (!atomic_dec_and_test(&q->refcnt))
		return;

	if (q->elevator)
		elevator_exit(q->elevator);

	blk_sync_queue(q);

	if (rl->rq_pool)
		mempool_destroy(rl->rq_pool);

	if (q->queue_tags)
		__blk_queue_free_tags(q);

	kmem_cache_free(requestq_cachep, q);
}

EXPORT_SYMBOL(blk_cleanup_queue);

static int blk_init_free_list(request_queue_t *q)
{
	struct request_list *rl = &q->rq;
	rl->count[READ] = rl->count[WRITE] = 0;
	rl->starved[READ] = rl->starved[WRITE] = 0;
	init_waitqueue_head(&rl->wait[READ]);
	init_waitqueue_head(&rl->wait[WRITE]);
	init_waitqueue_head(&rl->drain);

	rl->rq_pool = mempool_create(BLKDEV_MIN_RQ, mempool_alloc_slab, mempool_free_slab, request_cachep);

	if (!rl->rq_pool)
		return -ENOMEM;

	return 0;
}

static int __make_request(request_queue_t *, struct bio *);

request_queue_t *blk_alloc_queue(int gfp_mask)
{
	request_queue_t *q = kmem_cache_alloc(requestq_cachep, gfp_mask);

	if (!q)
		return NULL;

	memset(q, 0, sizeof(*q));
	init_timer(&q->unplug_timer);
	atomic_set(&q->refcnt, 1);

	q->backing_dev_info.unplug_io_fn = blk_backing_dev_unplug;
	q->backing_dev_info.unplug_io_data = q;

	return q;
}

EXPORT_SYMBOL(blk_alloc_queue);


request_queue_t *blk_init_queue(request_fn_proc *rfn, spinlock_t *lock)
{
	request_queue_t *q = blk_alloc_queue(GFP_KERNEL);

	if (!q)
		return NULL;

	if (blk_init_free_list(q))
		goto out_init;

	q->request_fn		= rfn;
	q->back_merge_fn       	= ll_back_merge_fn;
	q->front_merge_fn      	= ll_front_merge_fn;
	q->merge_requests_fn	= ll_merge_requests_fn;
	q->prep_rq_fn		= NULL;
	/* import */ q->unplug_fn		= generic_unplug_device;
	q->queue_flags		= (1 << QUEUE_FLAG_CLUSTER);
	q->queue_lock		= lock;

	blk_queue_segment_boundary(q, 0xffffffff);

	blk_queue_make_request(q, __make_request);
	blk_queue_max_segment_size(q, MAX_SEGMENT_SIZE);

	blk_queue_max_hw_segments(q, MAX_HW_SEGMENTS);
	blk_queue_max_phys_segments(q, MAX_PHYS_SEGMENTS);

	/*
	 * all done
	 */
	if (!elevator_init(q, NULL)) {
		blk_queue_congestion_threshold(q);
		return q;
	}

	blk_cleanup_queue(q);
out_init:
	kmem_cache_free(requestq_cachep, q);
	return NULL;
}

EXPORT_SYMBOL(blk_init_queue);

int blk_get_queue(request_queue_t *q)
{
	if (!test_bit(QUEUE_FLAG_DEAD, &q->queue_flags)) {
		atomic_inc(&q->refcnt);
		return 0;
	}

	return 1;
}

EXPORT_SYMBOL(blk_get_queue);

static inline void blk_free_request(request_queue_t *q, struct request *rq)
{
	elv_put_request(q, rq);
	mempool_free(rq, q->rq.rq_pool);
}

static inline struct request *blk_alloc_request(request_queue_t *q, int rw,
						int gfp_mask)
{
	struct request *rq = mempool_alloc(q->rq.rq_pool, gfp_mask);

	if (!rq)
		return NULL;

	/*
	 * first three bits are identical in rq->flags and bio->bi_rw,
	 * see bio.h and blkdev.h
	 */
	rq->flags = rw;

	if (!elv_set_request(q, rq, gfp_mask))
		return rq;

	mempool_free(rq, q->rq.rq_pool);
	return NULL;
}


static inline int ioc_batching(request_queue_t *q, struct io_context *ioc)
{
	if (!ioc)
		return 0;

	/*
	 * Make sure the process is able to allocate at least 1 request
	 * even if the batch times out, otherwise we could theoretically
	 * lose wakeups.
	 */
	return ioc->nr_batch_requests == q->nr_batching ||
		(ioc->nr_batch_requests > 0
		&& time_before(jiffies, ioc->last_waited + BLK_BATCH_TIME));
}

void ioc_set_batching(request_queue_t *q, struct io_context *ioc)
{
	if (!ioc || ioc_batching(q, ioc))
		return;

	ioc->nr_batch_requests = q->nr_batching;
	ioc->last_waited = jiffies;
}

static void __freed_request(request_queue_t *q, int rw)
{
	struct request_list *rl = &q->rq;

	if (rl->count[rw] < queue_congestion_off_threshold(q))
		clear_queue_congested(q, rw);

	if (rl->count[rw] + 1 <= q->nr_requests) {
		smp_mb();
		if (waitqueue_active(&rl->wait[rw]))
			wake_up(&rl->wait[rw]);

		blk_clear_queue_full(q, rw);
	}
}

static void freed_request(request_queue_t *q, int rw)
{
	struct request_list *rl = &q->rq;

	rl->count[rw]--;

	__freed_request(q, rw);

	if (unlikely(rl->starved[rw ^ 1]))
		__freed_request(q, rw ^ 1);

	if (!rl->count[READ] && !rl->count[WRITE]) {
		smp_mb();
		if (unlikely(waitqueue_active(&rl->drain)))
			wake_up(&rl->drain);
	}
}


#define blkdev_free_rq(list) list_entry((list)->next, struct request, queuelist)

static struct request *get_request(request_queue_t *q, int rw, int gfp_mask)
{
	struct request *rq = NULL;
	struct request_list *rl = &q->rq;
	struct io_context *ioc = get_io_context(gfp_mask);

	if (unlikely(test_bit(QUEUE_FLAG_DRAIN, &q->queue_flags)))
		goto out;

	spin_lock_irq(q->queue_lock);
	if (rl->count[rw]+1 >= q->nr_requests) {
		/*
		 * The queue will fill after this allocation, so set it as
		 * full, and mark this process as "batching". This process
		 * will be allowed to complete a batch of requests, others
		 * will be blocked.
		 */
		if (!blk_queue_full(q, rw)) {
			ioc_set_batching(q, ioc);
			blk_set_queue_full(q, rw);
		}
	}

	switch (elv_may_queue(q, rw)) {
		case ELV_MQUEUE_NO:
			goto rq_starved;
		case ELV_MQUEUE_MAY:
			break;
		case ELV_MQUEUE_MUST:
			goto get_rq;
	}

	if (blk_queue_full(q, rw) && !ioc_batching(q, ioc)) {
		/*
		 * The queue is full and the allocating process is not a
		 * "batcher", and not exempted by the IO scheduler
		 */
		spin_unlock_irq(q->queue_lock);
		goto out;
	}

get_rq:
	rl->count[rw]++;
	rl->starved[rw] = 0;
	if (rl->count[rw] >= queue_congestion_on_threshold(q))
		set_queue_congested(q, rw);
	spin_unlock_irq(q->queue_lock);

	rq = blk_alloc_request(q, rw, gfp_mask);
	if (!rq) {
		/*
		 * Allocation failed presumably due to memory. Undo anything
		 * we might have messed up.
		 *
		 * Allocating task should really be put onto the front of the
		 * wait queue, but this is pretty rare.
		 */
		spin_lock_irq(q->queue_lock);
		freed_request(q, rw);

		/*
		 * in the very unlikely event that allocation failed and no
		 * requests for this direction was pending, mark us starved
		 * so that freeing of a request in the other direction will
		 * notice us. another possible fix would be to split the
		 * rq mempool into READ and WRITE
		 */
rq_starved:
		if (unlikely(rl->count[rw] == 0))
			rl->starved[rw] = 1;

		spin_unlock_irq(q->queue_lock);
		goto out;
	}

	if (ioc_batching(q, ioc))
		ioc->nr_batch_requests--;
	
	INIT_LIST_HEAD(&rq->queuelist);

	rq->errors = 0;
	rq->rq_status = RQ_ACTIVE;
	rq->bio = rq->biotail = NULL;
	rq->buffer = NULL;
	rq->ref_count = 1;
	rq->q = q;
	rq->rl = rl;
	rq->waiting = NULL;
	rq->special = NULL;
	rq->data_len = 0;
	rq->data = NULL;
	rq->sense = NULL;

out:
	put_io_context(ioc);
	return rq;
}

static struct request *get_request_wait(request_queue_t *q, int rw)
{
	panic("in get_request_wait");
	return NULL;
}

struct request *blk_get_request(request_queue_t *q, int rw, int gfp_mask)
{
	panic("in blk_get_request");
	return NULL;
}

EXPORT_SYMBOL(blk_get_request);

void blk_requeue_request(request_queue_t *q, struct request *rq)
{
	panic("in blk_requeue_request");
}

EXPORT_SYMBOL(blk_requeue_request);

void blk_insert_request(request_queue_t *q, struct request *rq,
			int at_head, void *data, int reinsert)
{
	panic("in blk_insert_request");
}

EXPORT_SYMBOL(blk_insert_request);

struct request *blk_rq_map_user(request_queue_t *q, int rw, void __user *ubuf,
				unsigned int len)
{
	panic("in blk_rq_map_user");
	return NULL;
}

EXPORT_SYMBOL(blk_rq_map_user);

int blk_rq_unmap_user(struct request *rq, struct bio *bio, unsigned int ulen)
{
	panic("in blk_rq_unmap_user");
	return 0;
}

int blk_execute_rq(request_queue_t *q, struct gendisk *bd_disk,
		   struct request *rq)
{
	panic("in blk_execute_rq");
	return 0;
}

void drive_stat_acct(struct request *rq, int nr_sectors, int new_io)
{
	int rw = rq_data_dir(rq);

	if (!blk_fs_request(rq) || !rq->rq_disk)
		return;

	if (rw == READ) {
		__disk_stat_add(rq->rq_disk, read_sectors, nr_sectors);
		if (!new_io)
			__disk_stat_inc(rq->rq_disk, read_merges);
	} else if (rw == WRITE) {
		__disk_stat_add(rq->rq_disk, write_sectors, nr_sectors);
		if (!new_io)
			__disk_stat_inc(rq->rq_disk, write_merges);
	}
	if (new_io) {
		disk_round_stats(rq->rq_disk);
		rq->rq_disk->in_flight++;
	}
}

static inline void add_request(request_queue_t * q, struct request * req)
{
	drive_stat_acct(req, req->nr_sectors, 1);

	if (q->activity_fn)
		q->activity_fn(q->activity_data, rq_data_dir(req));

	/*
	 * elevator indicated where it wants this request to be
	 * inserted at elevator_merge time
	 */
	__elv_add_request(q, req, ELEVATOR_INSERT_SORT, 0);
}

void disk_round_stats(struct gendisk *disk)
{
	unsigned long now = jiffies;

	__disk_stat_add(disk, time_in_queue,
			disk->in_flight * (now - disk->stamp));
	disk->stamp = now;

	if (disk->in_flight)
		__disk_stat_add(disk, io_ticks, (now - disk->stamp_idle));
	disk->stamp_idle = now;
}

void __blk_put_request(request_queue_t *q, struct request *req)
{
	struct request_list *rl = req->rl;

	if (unlikely(!q))
		return;
	if (unlikely(--req->ref_count))
		return;

	req->rq_status = RQ_INACTIVE;
	req->q = NULL;
	req->rl = NULL;

	/*
	 * Request may not have originated from ll_rw_blk. if not,
	 * it didn't come out of our reserved rq pools
	 */
	if (rl) {
		int rw = rq_data_dir(req);

		elv_completed_request(q, req);

		BUG_ON(!list_empty(&req->queuelist));

		blk_free_request(q, req);
		freed_request(q, rw);
	}
}

void blk_put_request(struct request *req)
{
	/*
	 * if req->rl isn't set, this request didnt originate from the
	 * block layer, so it's safe to just disregard it
	 */
	if (req->rl) {
		unsigned long flags;
		request_queue_t *q = req->q;

		spin_lock_irqsave(q->queue_lock, flags);
		__blk_put_request(q, req);
		spin_unlock_irqrestore(q->queue_lock, flags);
	}
}

EXPORT_SYMBOL(blk_put_request);

long blk_congestion_wait(int rw, long timeout)
{
	long ret;
	DEFINE_WAIT(wait);
	wait_queue_head_t *wqh = &congestion_wqh[rw];

	prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);
	ret = io_schedule_timeout(timeout);
	finish_wait(wqh, &wait);
	return ret;
}

static int attempt_merge(request_queue_t *q, struct request *req,
			  struct request *next)
{
	if (!rq_mergeable(req) || !rq_mergeable(next))
		return 0;

	/*
	 * not contigious
	 */
	if (req->sector + req->nr_sectors != next->sector)
		return 0;

	if (rq_data_dir(req) != rq_data_dir(next)
	    || req->rq_disk != next->rq_disk
	    || next->waiting || next->special)
		return 0;

	/*
	 * If we are allowed to merge, then append bio list
	 * from next to rq and release next. merge_requests_fn
	 * will have updated segment counts, update sector
	 * counts here.
	 */
	if (!q->merge_requests_fn(q, req, next))
		return 0;

	/*
	 * At this point we have either done a back merge
	 * or front merge. We need the smaller start_time of
	 * the merged requests to be the current request
	 * for accounting purposes.
	 */
	if (time_after(req->start_time, next->start_time))
		req->start_time = next->start_time;

	req->biotail->bi_next = next->bio;
	req->biotail = next->biotail;

	req->nr_sectors = req->hard_nr_sectors += next->hard_nr_sectors;

	elv_merge_requests(q, req, next);

	if (req->rq_disk) {
		disk_round_stats(req->rq_disk);
		req->rq_disk->in_flight--;
	}

	__blk_put_request(q, next);
	return 1;
}

static inline int attempt_back_merge(request_queue_t *q, struct request *rq)
{
	struct request *next = elv_latter_request(q, rq);

	if (next)
		return attempt_merge(q, rq, next);

	return 0;
}

static inline int attempt_front_merge(request_queue_t *q, struct request *rq)
{
	panic("in attempt_front_merge");
	return 0;
}

void blk_attempt_remerge(request_queue_t *q, struct request *rq)
{
	panic("in blk_attempt_remerge");
}

EXPORT_SYMBOL(blk_attempt_remerge);

void __blk_attempt_remerge(request_queue_t *q, struct request *rq)
{
	panic("in __blk_attempt_remerge");
}

EXPORT_SYMBOL(__blk_attempt_remerge);

static int __make_request(request_queue_t *q, struct bio *bio)
{
	struct request *req, *freereq = NULL;
	int el_ret, rw, nr_sectors, cur_nr_sectors, barrier, err;
	sector_t sector;

	sector = bio->bi_sector;
	nr_sectors = bio_sectors(bio);
	cur_nr_sectors = bio_cur_sectors(bio);

	rw = bio_data_dir(bio);

	/*
	 * low level driver can indicate that it wants pages above a
	 * certain limit bounced to low memory (ie for highmem, or even
	 * ISA dma in theory)
	 */
	blk_queue_bounce(q, &bio);

	spin_lock_prefetch(q->queue_lock);

	barrier = bio_barrier(bio);
	if (barrier && !(q->queue_flags & (1 << QUEUE_FLAG_ORDERED))) {
		err = -EOPNOTSUPP;
		goto end_io;
	}

again:
	spin_lock_irq(q->queue_lock);

	if (elv_queue_empty(q)) {
		blk_plug_device(q);
		goto get_rq;
	}
	if (barrier)
		goto get_rq;

	el_ret = elv_merge(q, &req, bio);
	switch (el_ret) {
		case ELEVATOR_BACK_MERGE:
			BUG_ON(!rq_mergeable(req));

			if (!q->back_merge_fn(q, req, bio))
				break;

			req->biotail->bi_next = bio;
			req->biotail = bio;
			req->nr_sectors = req->hard_nr_sectors += nr_sectors;
			drive_stat_acct(req, nr_sectors, 0);
			if (!attempt_back_merge(q, req))
				elv_merged_request(q, req);
			goto out;

		case ELEVATOR_FRONT_MERGE:
			BUG_ON(!rq_mergeable(req));

			if (!q->front_merge_fn(q, req, bio))
				break;

			bio->bi_next = req->bio;
			req->bio = bio;

			/*
			 * may not be valid. if the low level driver said
			 * it didn't need a bounce buffer then it better
			 * not touch req->buffer either...
			 */
			req->buffer = bio_data(bio);
			req->current_nr_sectors = cur_nr_sectors;
			req->hard_cur_sectors = cur_nr_sectors;
			req->sector = req->hard_sector = sector;
			req->nr_sectors = req->hard_nr_sectors += nr_sectors;
			drive_stat_acct(req, nr_sectors, 0);
			if (!attempt_front_merge(q, req))
				elv_merged_request(q, req);
			goto out;

		/*
		 * elevator says don't/can't merge. get new request
		 */
		case ELEVATOR_NO_MERGE:
			break;

		default:
			printk("elevator returned crap (%d)\n", el_ret);
			BUG();
	}

	/*
	 * Grab a free request from the freelist - if that is empty, check
	 * if we are doing read ahead and abort instead of blocking for
	 * a free slot.
	 */
get_rq:
	if (freereq) {
		req = freereq;
		freereq = NULL;
	} else {
		spin_unlock_irq(q->queue_lock);
		if ((freereq = get_request(q, rw, GFP_ATOMIC)) == NULL) {
			/*
			 * READA bit set
			 */
			err = -EWOULDBLOCK;
			if (bio_rw_ahead(bio))
				goto end_io;
	
			freereq = get_request_wait(q, rw);
		}
		goto again;
	}

	req->flags |= REQ_CMD;

	/*
	 * inherit FAILFAST from bio (for read-ahead, and explicit FAILFAST)
	 */
	if (bio_rw_ahead(bio) || bio_failfast(bio))
		req->flags |= REQ_FAILFAST;

	/*
	 * REQ_BARRIER implies no merging, but lets make it explicit
	 */
	if (barrier)
		req->flags |= (REQ_HARDBARRIER | REQ_NOMERGE);

	req->errors = 0;
	req->hard_sector = req->sector = sector;
	req->hard_nr_sectors = req->nr_sectors = nr_sectors;
	req->current_nr_sectors = req->hard_cur_sectors = cur_nr_sectors;
	req->nr_phys_segments = bio_phys_segments(q, bio);
	req->nr_hw_segments = bio_hw_segments(q, bio);
	req->buffer = bio_data(bio);	/* see ->buffer comment above */
	req->waiting = NULL;
	req->bio = req->biotail = bio;
	req->rq_disk = bio->bi_bdev->bd_disk;
	req->start_time = jiffies;

	add_request(q, req);
out:
	if (freereq)
		__blk_put_request(q, freereq);
	if (bio_sync(bio))
		__generic_unplug_device(q);

	spin_unlock_irq(q->queue_lock);
	return 0;

end_io:
	bio_endio(bio, nr_sectors << 9, err);
	return 0;
}


static inline void blk_partition_remap(struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;

	if (bdev != bdev->bd_contains) {
		struct hd_struct *p = bdev->bd_part;

		switch (bio->bi_rw) {
		case READ:
			p->read_sectors += bio_sectors(bio);
			p->reads++;
			break;
		case WRITE:
			p->write_sectors += bio_sectors(bio);
			p->writes++;
			break;
		}
		bio->bi_sector += p->start_sect;
		bio->bi_bdev = bdev->bd_contains;
	}
}

void blk_finish_queue_drain(request_queue_t *q)
{
	panic("in blk_finish_queue_drain");
}

static int wait_drain(request_queue_t *q, struct request_list *rl, int dispatch)
{
	int wait = rl->count[READ] + rl->count[WRITE];

	if (dispatch)
		wait += !list_empty(&q->queue_head);

	return wait;
}

void blk_wait_queue_drained(request_queue_t *q, int wait_dispatch)
{
	panic("in blk_wait_queue_drained");
}

static inline void block_wait_queue_running(request_queue_t *q)
{
	DEFINE_WAIT(wait);

	while (test_bit(QUEUE_FLAG_DRAIN, &q->queue_flags)) {
		struct request_list *rl = &q->rq;

		prepare_to_wait_exclusive(&rl->drain, &wait,
				TASK_UNINTERRUPTIBLE);

		/*
		 * re-check the condition. avoids using prepare_to_wait()
		 * in the fast path (queue is running)
		 */
		if (test_bit(QUEUE_FLAG_DRAIN, &q->queue_flags))
			io_schedule();

		finish_wait(&rl->drain, &wait);
	}
}

static void handle_bad_sector(struct bio *bio)
{
	char b[BDEVNAME_SIZE];

	printk(KERN_INFO "attempt to access beyond end of device\n");
	printk(KERN_INFO "%s: rw=%ld, want=%Lu, limit=%Lu\n",
			bdevname(bio->bi_bdev, b),
			bio->bi_rw,
			(unsigned long long)bio->bi_sector + bio_sectors(bio),
			(long long)(bio->bi_bdev->bd_inode->i_size >> 9));

	set_bit(BIO_EOF, &bio->bi_flags);
}


void generic_make_request(struct bio *bio)
{
	request_queue_t *q;
	sector_t maxsector;
	int ret, nr_sectors = bio_sectors(bio);

	might_sleep();
	/* Test device or partition size, when known. */
	maxsector = bio->bi_bdev->bd_inode->i_size >> 9;
	if (maxsector) {
		sector_t sector = bio->bi_sector;

		if (maxsector < nr_sectors || maxsector - nr_sectors < sector) {
			handle_bad_sector(bio);
			goto end_io;
		}
	}

	do {
		char b[BDEVNAME_SIZE];

		q = bdev_get_queue(bio->bi_bdev);
		if (!q) {
			printk(KERN_ERR
			       "generic_make_request: Trying to access "
				"nonexistent block-device %s (%Lu)\n",
				bdevname(bio->bi_bdev, b),
				(long long) bio->bi_sector);
end_io:
			bio_endio(bio, bio->bi_size, -EIO);
			break;
		}

		if (unlikely(bio_sectors(bio) > q->max_hw_sectors)) {
			printk("bio too big device %s (%u > %u)\n", 
				bdevname(bio->bi_bdev, b),
				bio_sectors(bio),
				q->max_hw_sectors);
			goto end_io;
		}

		if (test_bit(QUEUE_FLAG_DEAD, &q->queue_flags))
			goto end_io;

		block_wait_queue_running(q);

		/*
		 * If this device has partitions, remap block n
		 * of partition p to block n+start(p) of the disk.
		 */
		blk_partition_remap(bio);

		ret = q->make_request_fn(q, bio);
	} while (ret);
}

EXPORT_SYMBOL(generic_make_request);

void submit_bio(int rw, struct bio *bio)
{
	int count = bio_sectors(bio);

	BIO_BUG_ON(!bio->bi_size);
	BIO_BUG_ON(!bio->bi_io_vec);
	bio->bi_rw = rw;
	if (rw & WRITE)
		mod_page_state(pgpgout, count);
	else
		mod_page_state(pgpgin, count);

	if (unlikely(block_dump)) {
		char b[BDEVNAME_SIZE];
		printk(KERN_DEBUG "%s(%d): %s block %Lu on %s\n",
			current->comm, current->pid,
			(rw & WRITE) ? "WRITE" : "READ",
			(unsigned long long)bio->bi_sector,
			bdevname(bio->bi_bdev,b));
	}

	generic_make_request(bio);
}

EXPORT_SYMBOL(submit_bio);

void blk_recalc_rq_segments(struct request *rq)
{
	struct bio *bio, *prevbio = NULL;
	int nr_phys_segs, nr_hw_segs;
	unsigned int phys_size, hw_size;
	request_queue_t *q = rq->q;

	if (!rq->bio)
		return;

	phys_size = hw_size = nr_phys_segs = nr_hw_segs = 0;
	rq_for_each_bio(bio, rq) {
		/* Force bio hw/phys segs to be recalculated. */
		bio->bi_flags &= ~(1 << BIO_SEG_VALID);

		nr_phys_segs += bio_phys_segments(q, bio);
		nr_hw_segs += bio_hw_segments(q, bio);
		if (prevbio) {
			int pseg = phys_size + prevbio->bi_size + bio->bi_size;
			int hseg = hw_size + prevbio->bi_size + bio->bi_size;

			if (blk_phys_contig_segment(q, prevbio, bio) &&
			    pseg <= q->max_segment_size) {
				nr_phys_segs--;
				phys_size += prevbio->bi_size + bio->bi_size;
			} else
				phys_size = 0;

			if (blk_hw_contig_segment(q, prevbio, bio) &&
			    hseg <= q->max_segment_size) {
				nr_hw_segs--;
				hw_size += prevbio->bi_size + bio->bi_size;
			} else
				hw_size = 0;
		}
		prevbio = bio;
	}

	rq->nr_phys_segments = nr_phys_segs;
	rq->nr_hw_segments = nr_hw_segs;
}

void blk_recalc_rq_sectors(struct request *rq, int nsect)
{
	if (blk_fs_request(rq)) {
		rq->hard_sector += nsect;
		rq->hard_nr_sectors -= nsect;

		/*
		 * Move the I/O submission pointers ahead if required.
		 */
		if ((rq->nr_sectors >= rq->hard_nr_sectors) &&
		    (rq->sector <= rq->hard_sector)) {
			rq->sector = rq->hard_sector;
			rq->nr_sectors = rq->hard_nr_sectors;
			rq->hard_cur_sectors = bio_cur_sectors(rq->bio);
			rq->current_nr_sectors = rq->hard_cur_sectors;
			rq->buffer = bio_data(rq->bio);
		}

		/*
		 * if total number of sectors is less than the first segment
		 * size, something has gone terribly wrong
		 */
		if (rq->nr_sectors < rq->current_nr_sectors) {
			printk("blk: request botched\n");
			rq->nr_sectors = rq->current_nr_sectors;
		}
	}
}

static int __end_that_request_first(struct request *req, int uptodate,
				    int nr_bytes)
{
	int total_bytes, bio_nbytes, error, next_idx = 0;
	struct bio *bio;

	/*
	 * extend uptodate bool to allow < 0 value to be direct io error
	 */
	error = 0;
	if (end_io_error(uptodate))
		error = !uptodate ? -EIO : uptodate;

	/*
	 * for a REQ_BLOCK_PC request, we want to carry any eventual
	 * sense key with us all the way through
	 */
	if (!blk_pc_request(req))
		req->errors = 0;

	if (!uptodate) {
		if (blk_fs_request(req) && !(req->flags & REQ_QUIET))
			printk("end_request: I/O error, dev %s, sector %llu\n",
				req->rq_disk ? req->rq_disk->disk_name : "?",
				(unsigned long long)req->sector);
	}

	total_bytes = bio_nbytes = 0;
	while ((bio = req->bio) != NULL) {
		int nbytes;

		if (nr_bytes >= bio->bi_size) {
			req->bio = bio->bi_next;
			nbytes = bio->bi_size;
			bio_endio(bio, nbytes, error);
			next_idx = 0;
			bio_nbytes = 0;
		} else {
			int idx = bio->bi_idx + next_idx;

			if (unlikely(bio->bi_idx >= bio->bi_vcnt)) {
				blk_dump_rq_flags(req, "__end_that");
				printk("%s: bio idx %d >= vcnt %d\n",
						__FUNCTION__,
						bio->bi_idx, bio->bi_vcnt);
				break;
			}

			nbytes = bio_iovec_idx(bio, idx)->bv_len;
			BIO_BUG_ON(nbytes > bio->bi_size);

			/*
			 * not a complete bvec done
			 */
			if (unlikely(nbytes > nr_bytes)) {
				bio_nbytes += nr_bytes;
				total_bytes += nr_bytes;
				break;
			}

			/*
			 * advance to the next vector
			 */
			next_idx++;
			bio_nbytes += nbytes;
		}

		total_bytes += nbytes;
		nr_bytes -= nbytes;

		if ((bio = req->bio)) {
			/*
			 * end more in this run, or just return 'not-done'
			 */
			if (unlikely(nr_bytes <= 0))
				break;
		}
	}

	/*
	 * completely done
	 */
	if (!req->bio)
		return 0;

	/*
	 * if the request wasn't completed, update state
	 */
	if (bio_nbytes) {
		bio_endio(bio, bio_nbytes, error);
		bio->bi_idx += next_idx;
		bio_iovec(bio)->bv_offset += nr_bytes;
		bio_iovec(bio)->bv_len -= nr_bytes;
	}

	blk_recalc_rq_sectors(req, total_bytes >> 9);
	blk_recalc_rq_segments(req);
	return 1;
}


int end_that_request_first(struct request *req, int uptodate, int nr_sectors)
{
	return __end_that_request_first(req, uptodate, nr_sectors << 9);
}

EXPORT_SYMBOL(end_that_request_first);

int end_that_request_chunk(struct request *req, int uptodate, int nr_bytes)
{
	return __end_that_request_first(req, uptodate, nr_bytes);
}

EXPORT_SYMBOL(end_that_request_chunk);

/*
 * queue lock must be held
 */
void end_that_request_last(struct request *req)
{
	struct gendisk *disk = req->rq_disk;
	struct completion *waiting = req->waiting;

	if (unlikely(laptop_mode) && blk_fs_request(req))
		laptop_io_completion();

	if (disk && blk_fs_request(req)) {
		unsigned long duration = jiffies - req->start_time;
		switch (rq_data_dir(req)) {
		    case WRITE:
			__disk_stat_inc(disk, writes);
			__disk_stat_add(disk, write_ticks, duration);
			break;
		    case READ:
			__disk_stat_inc(disk, reads);
			__disk_stat_add(disk, read_ticks, duration);
			break;
		}
		disk_round_stats(disk);
		disk->in_flight--;
	}
	__blk_put_request(req->q, req);
	/* Do this LAST! The structure may be freed immediately afterwards */
	if (waiting)
		complete(waiting);
}

EXPORT_SYMBOL(end_that_request_last);

void end_request(struct request *req, int uptodate)
{
	if (!end_that_request_first(req, uptodate, req->hard_cur_sectors)) {
		add_disk_randomness(req->rq_disk);
		blkdev_dequeue_request(req);
		end_that_request_last(req);
	}
}

EXPORT_SYMBOL(end_request);

void blk_rq_bio_prep(request_queue_t *q, struct request *rq, struct bio *bio)
{
	panic("in blk_rq_bio_prep");
}

EXPORT_SYMBOL(blk_rq_bio_prep);

int kblockd_schedule_work(struct work_struct *work)
{
	return queue_work(kblockd_workqueue, work);
}

EXPORT_SYMBOL(kblockd_schedule_work);

void kblockd_flush(void)
{
	flush_workqueue(kblockd_workqueue);
}
EXPORT_SYMBOL(kblockd_flush);

int __init blk_dev_init(void)
{
	kblockd_workqueue = create_workqueue("kblockd");
	if (!kblockd_workqueue)
		panic("Failed to create kblockd\n");

	request_cachep = kmem_cache_create("blkdev_requests",
			sizeof(struct request), 0, SLAB_PANIC, NULL, NULL);

	requestq_cachep = kmem_cache_create("blkdev_queue",
			sizeof(request_queue_t), 0, SLAB_PANIC, NULL, NULL);

	iocontext_cachep = kmem_cache_create("blkdev_ioc",
			sizeof(struct io_context), 0, SLAB_PANIC, NULL, NULL);

	blk_max_low_pfn = max_low_pfn;
	blk_max_pfn = max_pfn;

	return 0;
}

void put_io_context(struct io_context *ioc)
{
	if (ioc == NULL)
		return;

	BUG_ON(atomic_read(&ioc->refcount) == 0);

	if (atomic_dec_and_test(&ioc->refcount)) {
		if (ioc->aic && ioc->aic->dtor)
			ioc->aic->dtor(ioc->aic);
		if (ioc->cic && ioc->cic->dtor)
			ioc->cic->dtor(ioc->cic);

		kmem_cache_free(iocontext_cachep, ioc);
	}
}
EXPORT_SYMBOL(put_io_context);

/* Called by the exitting task */
void exit_io_context(void)
{
	unsigned long flags;
	struct io_context *ioc;

	local_irq_save(flags);
	ioc = current->io_context;
	current->io_context = NULL;
	local_irq_restore(flags);

	if (ioc->aic && ioc->aic->exit)
		ioc->aic->exit(ioc->aic);
	if (ioc->cic && ioc->cic->exit)
		ioc->cic->exit(ioc->cic);

	put_io_context(ioc);
}

struct io_context *get_io_context(int gfp_flags)
{
	struct task_struct *tsk = current;
	unsigned long flags;
	struct io_context *ret;

	local_irq_save(flags);
	ret = tsk->io_context;
	if (ret)
		goto out;

	local_irq_restore(flags);

	ret = kmem_cache_alloc(iocontext_cachep, gfp_flags);
	if (ret) {
		atomic_set(&ret->refcount, 1);
		ret->pid = tsk->pid;
		ret->last_waited = jiffies; /* doesn't matter... */
		ret->nr_batch_requests = 0; /* because this is 0 */
		ret->aic = NULL;
		ret->cic = NULL;
		spin_lock_init(&ret->lock);

		local_irq_save(flags);

		/*
		 * very unlikely, someone raced with us in setting up the task
		 * io context. free new context and just grab a reference.
		 */
		if (!tsk->io_context)
			tsk->io_context = ret;
		else {
			kmem_cache_free(iocontext_cachep, ret);
			ret = tsk->io_context;
		}

out:
		atomic_inc(&ret->refcount);
		local_irq_restore(flags);
	}

	return ret;
}
EXPORT_SYMBOL(get_io_context);

void copy_io_context(struct io_context **pdst, struct io_context **psrc)
{
	struct io_context *src = *psrc;
	struct io_context *dst = *pdst;

	if (src) {
		BUG_ON(atomic_read(&src->refcount) == 0);
		atomic_inc(&src->refcount);
		put_io_context(dst);
		*pdst = src;
	}
}
EXPORT_SYMBOL(copy_io_context);

void swap_io_context(struct io_context **ioc1, struct io_context **ioc2)
{
	struct io_context *temp;
	temp = *ioc1;
	*ioc1 = *ioc2;
	*ioc2 = temp;
}
EXPORT_SYMBOL(swap_io_context);




/*
 * sysfs parts below
 */
struct queue_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct request_queue *, char *);
	ssize_t (*store)(struct request_queue *, const char *, size_t);
};

static ssize_t
queue_var_show(unsigned int var, char *page)
{
	return sprintf(page, "%d\n", var);
}

static ssize_t
queue_var_store(unsigned long *var, const char *page, size_t count)
{
	char *p = (char *) page;

	*var = simple_strtoul(p, &p, 10);
	return count;
}

static ssize_t queue_requests_show(struct request_queue *q, char *page)
{
	return queue_var_show(q->nr_requests, (page));
}

static ssize_t
queue_requests_store(struct request_queue *q, const char *page, size_t count)
{
	struct request_list *rl = &q->rq;

	int ret = queue_var_store(&q->nr_requests, page, count);
	if (q->nr_requests < BLKDEV_MIN_RQ)
		q->nr_requests = BLKDEV_MIN_RQ;
	blk_queue_congestion_threshold(q);

	if (rl->count[READ] >= queue_congestion_on_threshold(q))
		set_queue_congested(q, READ);
	else if (rl->count[READ] < queue_congestion_off_threshold(q))
		clear_queue_congested(q, READ);

	if (rl->count[WRITE] >= queue_congestion_on_threshold(q))
		set_queue_congested(q, WRITE);
	else if (rl->count[WRITE] < queue_congestion_off_threshold(q))
		clear_queue_congested(q, WRITE);

	if (rl->count[READ] >= q->nr_requests) {
		blk_set_queue_full(q, READ);
	} else if (rl->count[READ]+1 <= q->nr_requests) {
		blk_clear_queue_full(q, READ);
		wake_up(&rl->wait[READ]);
	}

	if (rl->count[WRITE] >= q->nr_requests) {
		blk_set_queue_full(q, WRITE);
	} else if (rl->count[WRITE]+1 <= q->nr_requests) {
		blk_clear_queue_full(q, WRITE);
		wake_up(&rl->wait[WRITE]);
	}
	return ret;
}

static ssize_t queue_ra_show(struct request_queue *q, char *page)
{
	int ra_kb = q->backing_dev_info.ra_pages << (PAGE_CACHE_SHIFT - 10);

	return queue_var_show(ra_kb, (page));
}

static ssize_t
queue_ra_store(struct request_queue *q, const char *page, size_t count)
{
	unsigned long ra_kb;
	ssize_t ret = queue_var_store(&ra_kb, page, count);

	spin_lock_irq(q->queue_lock);
	if (ra_kb > (q->max_sectors >> 1))
		ra_kb = (q->max_sectors >> 1);

	q->backing_dev_info.ra_pages = ra_kb >> (PAGE_CACHE_SHIFT - 10);
	spin_unlock_irq(q->queue_lock);

	return ret;
}

static ssize_t queue_max_sectors_show(struct request_queue *q, char *page)
{
	int max_sectors_kb = q->max_sectors >> 1;

	return queue_var_show(max_sectors_kb, (page));
}

static ssize_t
queue_max_sectors_store(struct request_queue *q, const char *page, size_t count)
{
	unsigned long max_sectors_kb,
			max_hw_sectors_kb = q->max_hw_sectors >> 1,
			page_kb = 1 << (PAGE_CACHE_SHIFT - 10);
	ssize_t ret = queue_var_store(&max_sectors_kb, page, count);
	int ra_kb;

	if (max_sectors_kb > max_hw_sectors_kb || max_sectors_kb < page_kb)
		return -EINVAL;
	/*
	 * Take the queue lock to update the readahead and max_sectors
	 * values synchronously:
	 */
	spin_lock_irq(q->queue_lock);
	/*
	 * Trim readahead window as well, if necessary:
	 */
	ra_kb = q->backing_dev_info.ra_pages << (PAGE_CACHE_SHIFT - 10);
	if (ra_kb > max_sectors_kb)
		q->backing_dev_info.ra_pages =
				max_sectors_kb >> (PAGE_CACHE_SHIFT - 10);

	q->max_sectors = max_sectors_kb << 1;
	spin_unlock_irq(q->queue_lock);

	return ret;
}

static ssize_t queue_max_hw_sectors_show(struct request_queue *q, char *page)
{
	int max_hw_sectors_kb = q->max_hw_sectors >> 1;

	return queue_var_show(max_hw_sectors_kb, (page));
}

static struct queue_sysfs_entry queue_requests_entry = {
	.attr = {.name = "nr_requests", .mode = S_IRUGO | S_IWUSR },
	.show = queue_requests_show,
	.store = queue_requests_store,
};

static struct queue_sysfs_entry queue_ra_entry = {
	.attr = {.name = "read_ahead_kb", .mode = S_IRUGO | S_IWUSR },
	.show = queue_ra_show,
	.store = queue_ra_store,
};

static struct queue_sysfs_entry queue_max_sectors_entry = {
	.attr = {.name = "max_sectors_kb", .mode = S_IRUGO | S_IWUSR },
	.show = queue_max_sectors_show,
	.store = queue_max_sectors_store,
};

static struct queue_sysfs_entry queue_max_hw_sectors_entry = {
	.attr = {.name = "max_hw_sectors_kb", .mode = S_IRUGO },
	.show = queue_max_hw_sectors_show,
};

static struct queue_sysfs_entry queue_iosched_entry = {
	.attr = {.name = "scheduler", .mode = S_IRUGO | S_IWUSR },
	.show = elv_iosched_show,
	.store = elv_iosched_store,
};

static struct attribute *default_attrs[] = {
	&queue_requests_entry.attr,
	&queue_ra_entry.attr,
	&queue_max_hw_sectors_entry.attr,
	&queue_max_sectors_entry.attr,
	&queue_iosched_entry.attr,
	NULL,
};

#define to_queue(atr) container_of((atr), struct queue_sysfs_entry, attr)

static ssize_t
queue_attr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	struct queue_sysfs_entry *entry = to_queue(attr);
	struct request_queue *q;

	q = container_of(kobj, struct request_queue, kobj);
	if (!entry->show)
		return 0;

	return entry->show(q, page);
}

static ssize_t
queue_attr_store(struct kobject *kobj, struct attribute *attr,
		    const char *page, size_t length)
{
	struct queue_sysfs_entry *entry = to_queue(attr);
	struct request_queue *q;

	q = container_of(kobj, struct request_queue, kobj);
	if (!entry->store)
		return -EINVAL;

	return entry->store(q, page, length);
}

static struct sysfs_ops queue_sysfs_ops = {
	.show	= queue_attr_show,
	.store	= queue_attr_store,
};

struct kobj_type queue_ktype = {
	.sysfs_ops	= &queue_sysfs_ops,
	.default_attrs	= default_attrs,
};

int blk_register_queue(struct gendisk *disk)
{
	int ret;

	request_queue_t *q = disk->queue;

	if (!q || !q->request_fn)
		return -ENXIO;

	q->kobj.parent = kobject_get(&disk->kobj);
	if (!q->kobj.parent)
		return -EBUSY;

	snprintf(q->kobj.name, KOBJ_NAME_LEN, "%s", "queue");
	q->kobj.ktype = &queue_ktype;

	ret = kobject_register(&q->kobj);
	if (ret < 0)
		return ret;

	ret = elv_register_queue(q);
	if (ret) {
		kobject_unregister(&q->kobj);
		return ret;
	}

	return 0;
}

void blk_unregister_queue(struct gendisk *disk)
{
	panic("in blk_unregister_queue");
}