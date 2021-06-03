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

long blk_congestion_wait(int rw, long timeout)
{
	panic("in blk_congestion_wait");
    return 0;
}

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