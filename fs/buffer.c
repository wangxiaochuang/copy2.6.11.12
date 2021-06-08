#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/blkdev.h>
#include <linux/file.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/hash.h>
#include <linux/suspend.h>
#include <linux/buffer_head.h>
#include <linux/bio.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/bitops.h>

static int fsync_buffers_list(spinlock_t *lock, struct list_head *list);
static void invalidate_bh_lrus(void);

#define BH_ENTRY(list) list_entry((list), struct buffer_head, b_assoc_buffers)

inline void
init_buffer(struct buffer_head *bh, bh_end_io_t *handler, void *private)
{
	bh->b_end_io = handler;
	bh->b_private = private;
}

static int sync_buffer(void *word)
{
	struct block_device *bd;
	struct buffer_head *bh
		= container_of(word, struct buffer_head, b_state);

	smp_mb();
	bd = bh->b_bdev;
	if (bd)
		blk_run_address_space(bd->bd_inode->i_mapping);
	io_schedule();
	return 0;
}

void fastcall __lock_buffer(struct buffer_head *bh)
{
	wait_on_bit_lock(&bh->b_state, BH_Lock, sync_buffer,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__lock_buffer);

void fastcall unlock_buffer(struct buffer_head *bh)
{
	clear_buffer_locked(bh);
	smp_mb__after_clear_bit();
	wake_up_bit(&bh->b_state, BH_Lock);
}

void __wait_on_buffer(struct buffer_head * bh)
{
	wait_on_bit(&bh->b_state, BH_Lock, sync_buffer, TASK_UNINTERRUPTIBLE);
}

static void
__clear_page_buffers(struct page *page)
{
	ClearPagePrivate(page);
	page->private = 0;
	page_cache_release(page);
}

int sync_blockdev(struct block_device *bdev)
{
	int ret = 0;

	if (bdev) {
		int err;

		ret = filemap_fdatawrite(bdev->bd_inode->i_mapping);
		err = filemap_fdatawait(bdev->bd_inode->i_mapping);
		if (!ret)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(sync_blockdev);

int fsync_super(struct super_block *sb)
{
	sync_inodes_sb(sb, 0);
	DQUOT_SYNC(sb);
	lock_super(sb);
	if (sb->s_dirt && sb->s_op->write_super)
		sb->s_op->write_super(sb);
	unlock_super(sb);
	if (sb->s_op->sync_fs)
		sb->s_op->sync_fs(sb, 1);
	sync_blockdev(sb->s_bdev);
	sync_inodes_sb(sb, 1);

	return sync_blockdev(sb->s_bdev);
}

int fsync_bdev(struct block_device *bdev)
{
	struct super_block *sb = get_super(bdev);
	if (sb) {
		int res = fsync_super(sb);
		drop_super(sb);
		return res;
	}
	return sync_blockdev(bdev);
}

static void do_sync(unsigned long wait)
{
	panic("in do_sync");
}

asmlinkage long sys_sync(void)
{
	do_sync(1);
	return 0;
}

void invalidate_bdev(struct block_device *bdev, int destroy_dirty_buffers)
{
	invalidate_bh_lrus();
	invalidate_inode_pages(bdev->bd_inode->i_mapping);
}

static void free_more_memory(void)
{
	struct zone **zones;
	pg_data_t *pgdat;

	wakeup_bdflush(1024);
	yield();

	for_each_pgdat(pgdat) {
		zones = pgdat->node_zonelists[GFP_NOFS&GFP_ZONEMASK].zones;
		if (*zones)
			try_to_free_pages(zones, GFP_NOFS, 0);
	}
}

static void end_buffer_async_read(struct buffer_head *bh, int uptodate)
{
	panic("in end_buffer_async_read");
}

void end_buffer_async_write(struct buffer_head *bh, int uptodate)
{
	panic("in end_buffer_async_write");
}

static void mark_buffer_async_read(struct buffer_head *bh)
{
	bh->b_end_io = end_buffer_async_read;
	set_buffer_async_read(bh);
}

void mark_buffer_async_write(struct buffer_head *bh)
{
	bh->b_end_io = end_buffer_async_write;
	set_buffer_async_write(bh);
}
EXPORT_SYMBOL(mark_buffer_async_write);

static inline void __remove_assoc_queue(struct buffer_head *bh)
{
	list_del_init(&bh->b_assoc_buffers);
}

int inode_has_buffers(struct inode *inode)
{
	return !list_empty(&inode->i_data.private_list);
}

int __set_page_dirty_buffers(struct page *page)
{
	struct address_space * const mapping = page->mapping;

	spin_lock(&mapping->private_lock);
	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);
		struct buffer_head *bh = head;

		do {
			set_buffer_dirty(bh);
			bh = bh->b_this_page;
		} while (bh != head);
	}
	spin_unlock(&mapping->private_lock);

	if (!TestSetPageDirty(page)) {
		spin_lock_irq(&mapping->tree_lock);
		if (page->mapping) {	/* Race with truncate? */
			if (!mapping->backing_dev_info->memory_backed)
				inc_page_state(nr_dirty);
			radix_tree_tag_set(&mapping->page_tree,
						page_index(page),
						PAGECACHE_TAG_DIRTY);
		}
		spin_unlock_irq(&mapping->tree_lock);
		__mark_inode_dirty(mapping->host, I_DIRTY_PAGES);
	}
	
	return 0;
}
EXPORT_SYMBOL(__set_page_dirty_buffers);

void invalidate_inode_buffers(struct inode *inode)
{
	if (inode_has_buffers(inode)) {
		struct address_space *mapping = &inode->i_data;
		struct list_head *list = &mapping->private_list;
		struct address_space *buffer_mapping = mapping->assoc_mapping;

		spin_lock(&buffer_mapping->private_lock);
		while (!list_empty(list))
			__remove_assoc_queue(BH_ENTRY(list->next));
		spin_unlock(&buffer_mapping->private_lock);
	}
}

int remove_inode_buffers(struct inode *inode)
{
	panic(" in remove_inode_buffers");
	return 0;
}

struct buffer_head *alloc_page_buffers(struct page *page, unsigned long size,
		int retry)
{
	struct buffer_head *bh, *head;
	long offset;

try_again:
	head = NULL;
	offset = PAGE_SIZE;
	while ((offset -= size) >= 0) {
		bh = alloc_buffer_head(GFP_NOFS);
		if (!bh)
			goto no_grow;

		bh->b_bdev = NULL;
		bh->b_this_page = head;
		bh->b_blocknr = -1;
		head = bh;

		bh->b_state = 0;
		atomic_set(&bh->b_count, 0);
		bh->b_size = size;

		/* Link the buffer to its page */
		set_bh_page(bh, page, offset);

		bh->b_end_io = NULL;
	}
	return head;
/*
 * In case anything failed, we just free everything we got.
 */
no_grow:
	if (head) {
		do {
			bh = head;
			head = head->b_this_page;
			free_buffer_head(bh);
		} while (head);
	}

	if (!retry)
		return NULL;

	free_more_memory();
	goto try_again;
}
EXPORT_SYMBOL_GPL(alloc_page_buffers);

void __brelse(struct buffer_head * buf)
{
	if (atomic_read(&buf->b_count)) {
		put_bh(buf);
		return;
	}
	printk(KERN_ERR "VFS: brelse: Trying to free free buffer\n");
	WARN_ON(1);
}

#define BH_LRU_SIZE	8

struct bh_lru {
	struct buffer_head *bhs[BH_LRU_SIZE];
};

static DEFINE_PER_CPU(struct bh_lru, bh_lrus) = {{ NULL }};

#ifdef CONFIG_SMP
#define bh_lru_lock()	local_irq_disable()
#define bh_lru_unlock()	local_irq_enable()
#else
#define bh_lru_lock()	preempt_disable()
#define bh_lru_unlock()	preempt_enable()
#endif

static void invalidate_bh_lru(void *arg)
{
	struct bh_lru *b = &get_cpu_var(bh_lrus);
	int i;

	for (i = 0; i < BH_LRU_SIZE; i++) {
		brelse(b->bhs[i]);
		b->bhs[i] = NULL;
	}
	put_cpu_var(bh_lrus);
}

static void invalidate_bh_lrus(void)
{
	on_each_cpu(invalidate_bh_lru, NULL, 1, 1);
}

void set_bh_page(struct buffer_head *bh,
		struct page *page, unsigned long offset)
{
	bh->b_page = page;
	if (offset >= PAGE_SIZE)
		BUG();
	if (PageHighMem(page))
		/*
		 * This catches illegal uses and preserves the offset:
		 */
		bh->b_data = (char *)(0 + offset);
	else
		bh->b_data = page_address(page) + offset;
}
EXPORT_SYMBOL(set_bh_page);

static inline void discard_buffer(struct buffer_head * bh)
{
	lock_buffer(bh);
	clear_buffer_dirty(bh);
	bh->b_bdev = NULL;
	clear_buffer_mapped(bh);
	clear_buffer_req(bh);
	clear_buffer_new(bh);
	clear_buffer_delay(bh);
	unlock_buffer(bh);
}

int try_to_release_page(struct page *page, int gfp_mask)
{
	struct address_space * const mapping = page->mapping;

	BUG_ON(!PageLocked(page));
	if (PageWriteback(page))
		return 0;
	
	if (mapping && mapping->a_ops->releasepage)
		return mapping->a_ops->releasepage(page, gfp_mask);
	return try_to_free_buffers(page);
}
EXPORT_SYMBOL(try_to_release_page);

int block_invalidatepage(struct page *page, unsigned long offset)
{
	panic("in block_invalidatepage");
	return 0;
}

EXPORT_SYMBOL(block_invalidatepage);

void create_empty_buffers(struct page *page,
			unsigned long blocksize, unsigned long b_state)
{
	struct buffer_head *bh, *head, *tail;

	head = alloc_page_buffers(page, blocksize, 1);
	bh = head;
	do {
		bh->b_state |= b_state;
		tail = bh;
		bh = bh->b_this_page;
	} while (bh);
	tail->b_this_page = head;

	spin_lock(&page->mapping->private_lock);
	if (PageUptodate(page) || PageDirty(page)) {
		bh = head;
		do {
			if (PageDirty(page))
				set_buffer_dirty(bh);
			if (PageUptodate(page))
				set_buffer_uptodate(bh);
			bh = bh->b_this_page;
		} while (bh != head);
	}
	attach_page_buffers(page, head);
	spin_unlock(&page->mapping->private_lock);
}

EXPORT_SYMBOL(create_empty_buffers);

void unmap_underlying_metadata(struct block_device *bdev, sector_t block)
{
	panic("in unmap_underlying_metadata");
}

EXPORT_SYMBOL(unmap_underlying_metadata);

static int __block_write_full_page(struct inode *inode, struct page *page,
			get_block_t *get_block, struct writeback_control *wbc)
{
	panic("in __block_write_full_page");
	return 0;
}

static int __block_prepare_write(struct inode *inode, struct page *page,
		unsigned from, unsigned to, get_block_t *get_block)
{
	panic("in __block_prepare_write");
	return 0;
}

static int __block_commit_write(struct inode *inode, struct page *page,
		unsigned from, unsigned to)
{
	panic("in __block_commit_write");
	return 0;
}


int block_read_full_page(struct page *page, get_block_t *get_block)
{
	struct inode *inode = page->mapping->host;
	sector_t iblock, lblock;
	struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
	unsigned int blocksize;
	int nr, i;
	int fully_mapped = 1;

	if (!PageLocked(page))
		PAGE_BUG(page);
	blocksize = 1 << inode->i_blkbits;
	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);
	head = page_buffers(page);

	iblock = (sector_t)page->index << (PAGE_CACHE_SHIFT - inode->i_blkbits);
	lblock = (i_size_read(inode)+blocksize-1) >> inode->i_blkbits;
	bh = head;
	nr = 0;
	i = 0;

	do {
		if (buffer_uptodate(bh))
			continue;

		if (!buffer_mapped(bh)) {
			fully_mapped = 0;
			if (iblock < lblock) {
				if (get_block(inode, iblock, bh, 0))
					SetPageError(page);
			}
			if (!buffer_mapped(bh)) {
				void *kaddr = kmap_atomic(page, KM_USER0);
				memset(kaddr + i * blocksize, 0, blocksize);
				flush_dcache_page(page);
				kunmap_atomic(kaddr, KM_USER0);
				set_buffer_uptodate(bh);
				continue;
			}
			/*
			 * get_block() might have updated the buffer
			 * synchronously
			 */
			if (buffer_uptodate(bh))
				continue;
		}
		arr[nr++] = bh;
	} while (i++, iblock++, (bh = bh->b_this_page) != head);

	if (fully_mapped)
		SetPageMappedToDisk(page);

	if (!nr) {
		/*
		 * All buffers are uptodate - we can set the page uptodate
		 * as well. But not if get_block() returned an error.
		 */
		if (!PageError(page))
			SetPageUptodate(page);
		unlock_page(page);
		return 0;
	}

	/* Stage two: lock the buffers */
	for (i = 0; i < nr; i++) {
		bh = arr[i];
		lock_buffer(bh);
		mark_buffer_async_read(bh);
	}

	/*
	 * Stage 3: start the IO.  Check for uptodateness
	 * inside the buffer lock in case another process reading
	 * the underlying blockdev brought it uptodate (the sct fix).
	 */
	for (i = 0; i < nr; i++) {
		bh = arr[i];
		if (buffer_uptodate(bh))
			end_buffer_async_read(bh, 1);
		else
			submit_bh(READ, bh);
	}
	return 0;
}

int generic_cont_expand(struct inode *inode, loff_t size)
{
	panic("in generic_cont_expand");
	return 0;
}

int cont_prepare_write(struct page *page, unsigned offset,
		unsigned to, get_block_t *get_block, loff_t *bytes)
{
	panic("in cont_prepare_write");
	return 0;
}

int block_prepare_write(struct page *page, unsigned from, unsigned to,
			get_block_t *get_block)
{
	struct inode *inode = page->mapping->host;
	int err = __block_prepare_write(inode, page, from, to, get_block);
	if (err)
		ClearPageUptodate(page);
	return err;
}

int block_commit_write(struct page *page, unsigned from, unsigned to)
{
	struct inode *inode = page->mapping->host;
	__block_commit_write(inode,page,from,to);
	return 0;
}

int generic_commit_write(struct file *file, struct page *page,
		unsigned from, unsigned to)
{
	panic("in generic_commit_write");
	return 0;
}

static void end_buffer_read_nobh(struct buffer_head *bh, int uptodate)
{
	panic("in end_buffer_read_nobh");
}

int nobh_prepare_write(struct page *page, unsigned from, unsigned to,
			get_block_t *get_block)
{
	panic("in nobh_prepare_write");
	return 0;
}

int nobh_commit_write(struct file *file, struct page *page,
		unsigned from, unsigned to)
{
	panic("in nobh_commit_write");
	return 0;
}

int nobh_truncate_page(struct address_space *mapping, loff_t from)
{
	panic("in nobh_truncate_page");
	return 0;
}

int block_truncate_page(struct address_space *mapping,
			loff_t from, get_block_t *get_block)
{
	panic("in block_truncate_page");
	return 0;
}

int block_write_full_page(struct page *page, get_block_t *get_block,
			struct writeback_control *wbc)
{
	panic("in block_write_full_page");
	return 0;
}

sector_t generic_block_bmap(struct address_space *mapping, sector_t block,
			    get_block_t *get_block)
{
	panic("in generic_block_bmap");
	return 0;
}

static int end_bio_bh_io_sync(struct bio *bio, unsigned int bytes_done, int err)
{
	panic("in end_bio_bh_io_sync");
	return 0;
}

int submit_bh(int rw, struct buffer_head * bh)
{
	struct bio *bio;
	int ret = 0;

	BUG_ON(!buffer_locked(bh));
	BUG_ON(!buffer_mapped(bh));
	BUG_ON(!bh->b_end_io);

	if (buffer_ordered(bh) && (rw == WRITE))
		rw = WRITE_BARRIER;

	/*
	 * Only clear out a write error when rewriting, should this
	 * include WRITE_SYNC as well?
	 */
	if (test_set_buffer_req(bh) && (rw == WRITE || rw == WRITE_BARRIER))
		clear_buffer_write_io_error(bh);

	/*
	 * from here on down, it's all bio -- do the initial mapping,
	 * submit_bio -> generic_make_request may further map this bio around
	 */
	bio = bio_alloc(GFP_NOIO, 1);

	bio->bi_sector = bh->b_blocknr * (bh->b_size >> 9);
	bio->bi_bdev = bh->b_bdev;
	bio->bi_io_vec[0].bv_page = bh->b_page;
	bio->bi_io_vec[0].bv_len = bh->b_size;
	bio->bi_io_vec[0].bv_offset = bh_offset(bh);

	bio->bi_vcnt = 1;
	bio->bi_idx = 0;
	bio->bi_size = bh->b_size;

	bio->bi_end_io = end_bio_bh_io_sync;
	bio->bi_private = bh;

	bio_get(bio);
	submit_bio(rw, bio);

	if (bio_flagged(bio, BIO_EOPNOTSUPP))
		ret = -EOPNOTSUPP;

	bio_put(bio);
	return ret;
}

void ll_rw_block(int rw, int nr, struct buffer_head *bhs[])
{
	panic(" in ll_rw_block");
}

int sync_dirty_buffer(struct buffer_head *bh)
{
	panic("in sync_dirty_buffer");
	return 0;
}








static inline int buffer_busy(struct buffer_head *bh)
{
	return atomic_read(&bh->b_count) |
		(bh->b_state & ((1 << BH_Dirty) | (1 << BH_Lock)));
}

static int
drop_buffers(struct page *page, struct buffer_head **buffers_to_free)
{
	struct buffer_head *head = page_buffers(page);
	struct buffer_head *bh;

	bh = head;
	do {
		if (buffer_write_io_error(bh))
			set_bit(AS_EIO, &page->mapping->flags);
		if (buffer_busy(bh))
			goto failed;
		bh = bh->b_this_page;
	} while (bh != head);

	do {
		struct buffer_head *next = bh->b_this_page;

		if (!list_empty(&bh->b_assoc_buffers))
			__remove_assoc_queue(bh);
		bh = next;
	} while (bh != head);
	*buffers_to_free = head;
	__clear_page_buffers(page);
	return 1;
failed:
	return 0;
}

int try_to_free_buffers(struct page *page)
{
	struct address_space * const mapping = page->mapping;
	struct buffer_head *buffers_to_free = NULL;
	int ret = 0;

	BUG_ON(!PageLocked(page));
	if (PageWriteback(page))
		return 0;

	if (mapping == NULL) {		/* can this still happen? */
		ret = drop_buffers(page, &buffers_to_free);
		goto out;
	}

	spin_lock(&mapping->private_lock);
	ret = drop_buffers(page, &buffers_to_free);
	if (ret) {
		clear_page_dirty(page);
	}
	spin_unlock(&mapping->private_lock);
out:
	if (buffers_to_free) {
		struct buffer_head *bh = buffers_to_free;

		do {
			struct buffer_head *next = bh->b_this_page;
			free_buffer_head(bh);
			bh = next;
		} while (bh != buffers_to_free);
	}
	return ret;
}
EXPORT_SYMBOL(try_to_free_buffers);

int block_sync_page(struct page *page)
{
	struct address_space *mapping;

	smp_mb();
	mapping = page_mapping(page);
	if (mapping)
		blk_run_backing_dev(mapping->backing_dev_info, page);
	return 0;
}

/*
 * Buffer-head allocation
 */
static kmem_cache_t *bh_cachep;

/*
 * Once the number of bh's in the machine exceeds this level, we start
 * stripping them in writeback.
 */
static int max_buffer_heads;

int buffer_heads_over_limit;

struct bh_accounting {
	int nr;			/* Number of live bh's */
	int ratelimit;		/* Limit cacheline bouncing */
};

static DEFINE_PER_CPU(struct bh_accounting, bh_accounting) = {0, 0};

static void recalc_bh_state(void)
{
	int i;
	int tot = 0;

	if (__get_cpu_var(bh_accounting).ratelimit++ < 4096)
		return;
	__get_cpu_var(bh_accounting).ratelimit = 0;
	for_each_cpu(i)
		tot += per_cpu(bh_accounting, i).nr;
	buffer_heads_over_limit = (tot > max_buffer_heads);
}
	
struct buffer_head *alloc_buffer_head(int gfp_flags)
{
	struct buffer_head *ret = kmem_cache_alloc(bh_cachep, gfp_flags);
	if (ret) {
		preempt_disable();
		__get_cpu_var(bh_accounting).nr++;
		recalc_bh_state();
		preempt_enable();
	}
	return ret;
}
EXPORT_SYMBOL(alloc_buffer_head);

void free_buffer_head(struct buffer_head *bh)
{
	BUG_ON(!list_empty(&bh->b_assoc_buffers));
	kmem_cache_free(bh_cachep, bh);
	preempt_disable();
	__get_cpu_var(bh_accounting).nr--;
	recalc_bh_state();
	preempt_enable();
}

EXPORT_SYMBOL(free_buffer_head);

static void
init_buffer_head(void *data, kmem_cache_t *cachep, unsigned long flags)
{
    if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
			    SLAB_CTOR_CONSTRUCTOR) {
		struct buffer_head * bh = (struct buffer_head *)data;

		memset(bh, 0, sizeof(*bh));
		INIT_LIST_HEAD(&bh->b_assoc_buffers);
	}
}

void __init buffer_init(void)
{
	int nrpages;

	bh_cachep = kmem_cache_create("buffer_head",
			sizeof(struct buffer_head), 0,
			SLAB_PANIC, init_buffer_head, NULL);
    
    nrpages = (nr_free_buffer_pages() * 10) / 100;
    max_buffer_heads = nrpages * (PAGE_SIZE / sizeof(struct buffer_head));
    hotcpu_notifier(buffer_cpu_notify, 0);
}