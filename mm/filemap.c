#include <linux/config.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/syscalls.h>
/*
 * This is needed for the following functions:
 *  - try_to_release_page
 *  - block_invalidatepage
 *  - generic_osync_inode
 *
 * FIXME: remove all knowledge of the buffer layer from the core VM
 */
#include <linux/buffer_head.h> /* for generic_osync_inode */

#include <asm/uaccess.h>
#include <asm/mman.h>

void __remove_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;

	radix_tree_delete(&mapping->page_tree, page->index);
	page->mapping = NULL;
	mapping->nrpages--;
	pagecache_acct(-1);
}

void remove_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;

	if (unlikely(!PageLocked(page)))
		PAGE_BUG(page);

	spin_lock_irq(&mapping->tree_lock);
	__remove_from_page_cache(page);
	spin_unlock_irq(&mapping->tree_lock);
}

static int sync_page(void *word)
{
	struct address_space *mapping;
	struct page *page;

	page = container_of((page_flags_t *)word, struct page, flags);

	/*
	 * FIXME, fercrissake.  What is this barrier here for?
	 */
	smp_mb();
	mapping = page_mapping(page);
	if (mapping && mapping->a_ops && mapping->a_ops->sync_page)
		mapping->a_ops->sync_page(page);
	io_schedule();
	return 0;
}

static int __filemap_fdatawrite_range(struct address_space *mapping,
	loff_t start, loff_t end, int sync_mode)
{
	int ret;
	struct writeback_control wbc = {
		.sync_mode = sync_mode,
		.nr_to_write = mapping->nrpages * 2,
		.start = start,
		.end = end,
	};

	if (mapping->backing_dev_info->memory_backed)
		return 0;

	ret = do_writepages(mapping, &wbc);
	return ret;
}

static inline int __filemap_fdatawrite(struct address_space *mapping,
	int sync_mode)
{
	return __filemap_fdatawrite_range(mapping, 0, 0, sync_mode);
}

int filemap_fdatawrite(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_ALL);
}

EXPORT_SYMBOL(filemap_fdatawrite);


static int wait_on_page_writeback_range(struct address_space *mapping,
				pgoff_t start, pgoff_t end)
{
	struct pagevec pvec;
	int nr_pages;
	int ret = 0;
	pgoff_t index;

	if (end < start)
		return 0;

	pagevec_init(&pvec, 0);
	index = start;
	while ((index <= end) &&
			(nr_pages = pagevec_lookup_tag(&pvec, mapping, &index,
			PAGECACHE_TAG_WRITEBACK,
			min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1)) != 0) {
		unsigned i;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			/* until radix tree lookup accepts end_index */
			if (page->index > end)
				continue;

			wait_on_page_writeback(page);
			if (PageError(page))
				ret = -EIO;
		}
		pagevec_release(&pvec);
		cond_resched();
	}

	/* Check for outstanding write errors */
	if (test_and_clear_bit(AS_ENOSPC, &mapping->flags))
		ret = -ENOSPC;
	if (test_and_clear_bit(AS_EIO, &mapping->flags))
		ret = -EIO;

	return ret;
}

int sync_page_range(struct inode *inode, struct address_space *mapping,
			loff_t pos, size_t count)
{
	panic("in sync_page_range");
	return 0;
}

EXPORT_SYMBOL(sync_page_range);

int sync_page_range_nolock(struct inode *inode, struct address_space *mapping,
			loff_t pos, size_t count)
{
	panic("in sync_page_range_nolock");
	return 0;
}

EXPORT_SYMBOL(sync_page_range_nolock);

int filemap_fdatawait(struct address_space *mapping)
{
	loff_t i_size = i_size_read(mapping->host);

	if (i_size == 0)
		return 0;

	return wait_on_page_writeback_range(mapping, 0,
				(i_size - 1) >> PAGE_CACHE_SHIFT);
}

EXPORT_SYMBOL(filemap_fdatawait);

int filemap_write_and_wait(struct address_space *mapping)
{
	int retval = 0;

	if (mapping->nrpages) {
		retval = filemap_fdatawrite(mapping);
		if (retval == 0)
			retval = filemap_fdatawait(mapping);
	}
	return retval;
}

int add_to_page_cache(struct page *page, struct address_space *mapping,
		pgoff_t offset, int gfp_mask)
{
	int error = radix_tree_preload(gfp_mask & ~__GFP_HIGHMEM);

	if (error == 0) {
		spin_lock_irq(&mapping->tree_lock);
		error = radix_tree_insert(&mapping->page_tree, offset, page);
		if (!error) {
			page_cache_get(page);
			SetPageLocked(page);
			page->mapping = mapping;
			page->index = offset;
			mapping->nrpages++;
			pagecache_acct(1);
		}
		spin_unlock_irq(&mapping->tree_lock);
		radix_tree_preload_end();
	}
	return error;
}

EXPORT_SYMBOL(add_to_page_cache);

int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
				pgoff_t offset, int gfp_mask)
{
	int ret = add_to_page_cache(page, mapping, offset, gfp_mask);
	if (ret == 0)
		lru_cache_add(page);
	return ret;
}

static wait_queue_head_t *page_waitqueue(struct page *page)
{
	const struct zone *zone = page_zone(page);

	return &zone->wait_table[hash_ptr(page, zone->wait_table_bits)];
}

static inline void wake_up_page(struct page *page, int bit)
{
	__wake_up_bit(page_waitqueue(page), &page->flags, bit);
}

void fastcall wait_on_page_bit(struct page *page, int bit_nr)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	if (test_bit(bit_nr, &page->flags))
		__wait_on_bit(page_waitqueue(page), &wait, sync_page,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(wait_on_page_bit);

void fastcall unlock_page(struct page *page)
{
	smp_mb__before_clear_bit();
	if (!TestClearPageLocked(page))
		BUG();
	smp_mb__after_clear_bit(); 
	wake_up_page(page, PG_locked);
}
EXPORT_SYMBOL(unlock_page);

void fastcall __lock_page(struct page *page)
{
	DEFINE_WAIT_BIT(wait, &page->flags, PG_locked);

	__wait_on_bit_lock(page_waitqueue(page), &wait, sync_page,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__lock_page);

struct page * find_get_page(struct address_space *mapping, unsigned long offset)
{
	struct page *page;

	spin_lock_irq(&mapping->tree_lock);
	page = radix_tree_lookup(&mapping->page_tree, offset);
	if (page)
		page_cache_get(page);
	spin_unlock_irq(&mapping->tree_lock);
	return page;
}

EXPORT_SYMBOL(find_get_page);

struct page *find_trylock_page(struct address_space *mapping, unsigned long offset)
{
	struct page *page;

	spin_lock_irq(&mapping->tree_lock);
	page = radix_tree_lookup(&mapping->page_tree, offset);
	if (page && TestSetPageLocked(page))
		page = NULL;
	spin_unlock_irq(&mapping->tree_lock);
	return page;
}

EXPORT_SYMBOL(find_trylock_page);

/**
 * find_lock_page - locate, pin and lock a pagecache page
 *
 * @mapping - the address_space to search
 * @offset - the page index
 *
 * Locates the desired pagecache page, locks it, increments its reference
 * count and returns its address.
 *
 * Returns zero if the page was not present. find_lock_page() may sleep.
 */
struct page *find_lock_page(struct address_space *mapping,
				unsigned long offset)
{
	struct page *page;

	spin_lock_irq(&mapping->tree_lock);
repeat:
	page = radix_tree_lookup(&mapping->page_tree, offset);
	if (page) {
		page_cache_get(page);
		if (TestSetPageLocked(page)) {
			spin_unlock_irq(&mapping->tree_lock);
			lock_page(page);
			spin_lock_irq(&mapping->tree_lock);

			/* Has the page been truncated while we slept? */
			if (page->mapping != mapping || page->index != offset) {
				unlock_page(page);
				page_cache_release(page);
				goto repeat;
			}
		}
	}
	spin_unlock_irq(&mapping->tree_lock);
	return page;
}

EXPORT_SYMBOL(find_lock_page);

struct page *find_or_create_page(struct address_space *mapping,
		unsigned long index, unsigned int gfp_mask)
{
	struct page *page, *cached_page = NULL;
	int err;
repeat:
	page = find_lock_page(mapping, index);
	if (!page) {
		if (!cached_page) {
			cached_page = alloc_page(gfp_mask);
			if (!cached_page)
				return NULL;
		}
		err = add_to_page_cache_lru(cached_page, mapping,
					index, gfp_mask);
		if (!err) {
			page = cached_page;
			cached_page = NULL;
		} else if (err == -EEXIST)
			goto repeat;
	}
	if (cached_page)
		page_cache_release(cached_page);
	return page;
}

EXPORT_SYMBOL(find_or_create_page);

unsigned find_get_pages(struct address_space *mapping, pgoff_t start,
			    unsigned int nr_pages, struct page **pages)
{
	unsigned int i;
	unsigned int ret;

	spin_lock_irq(&mapping->tree_lock);
	ret = radix_tree_gang_lookup(&mapping->page_tree,
				(void **)pages, start, nr_pages);
	for (i = 0; i < ret; i++)
		page_cache_get(pages[i]);
	spin_unlock_irq(&mapping->tree_lock);
	return ret;
}

unsigned find_get_pages_tag(struct address_space *mapping, pgoff_t *index,
			int tag, unsigned int nr_pages, struct page **pages)
{
	unsigned int i;
	unsigned int ret;

	spin_lock_irq(&mapping->tree_lock);
	ret = radix_tree_gang_lookup_tag(&mapping->page_tree,
				(void **)pages, *index, nr_pages, tag);
	for (i = 0; i < ret; i++)
		page_cache_get(pages[i]);
	if (ret)
		*index = pages[ret - 1]->index + 1;
	spin_unlock_irq(&mapping->tree_lock);
	return ret;
}


void do_generic_mapping_read(struct address_space *mapping,
			     struct file_ra_state *_ra,
			     struct file *filp,
			     loff_t *ppos,
			     read_descriptor_t *desc,
			     read_actor_t actor)
{
	struct inode *inode = mapping->host;
	unsigned long index;
	unsigned long end_index;
	unsigned long offset;
	unsigned long req_size;
	unsigned long next_index;
	unsigned long prev_index;
	loff_t isize;
	struct page *cached_page;
	int error;
	struct file_ra_state ra = *_ra;

	cached_page = NULL;
	index = *ppos >> PAGE_CACHE_SHIFT;
	next_index = index;
	prev_index = ra.prev_page;
	req_size = (desc->count + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	offset = *ppos & ~PAGE_CACHE_MASK;

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
	for (;;) {
		struct page *page;
		unsigned long ret_size, nr, ret;

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_CACHE_SIZE;
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				goto out;
			}
		}
		nr = nr - offset;

		cond_resched();
		if (index == next_index && req_size) {
			ret_size = page_cache_readahead(mapping, &ra,
					filp, index, req_size);
			next_index += ret_size;
			req_size -= ret_size;
		}

find_page:
		page = find_get_page(mapping, index);
		if (unlikely(page == NULL)) {
			handle_ra_miss(mapping, &ra, index);
			goto no_cached_page;
		}
		if (!PageUptodate(page))
			goto page_not_up_to_date;
page_ok:

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/*
		 * When (part of) the same page is read multiple times
		 * in succession, only mark it as accessed the first time.
		 */
		if (prev_index != index)
			mark_page_accessed(page);
		prev_index = index;

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		ret = actor(desc, page, offset, nr);
		offset += ret;
		index += offset >> PAGE_CACHE_SHIFT;
		offset &= ~PAGE_CACHE_MASK;

		page_cache_release(page);
		if (ret == nr && desc->count)
			continue;
		goto out;

page_not_up_to_date:
		/* Get exclusive access to the page ... */
		lock_page(page);

		/* Did it get unhashed before we got the lock? */
		if (!page->mapping) {
			unlock_page(page);
			page_cache_release(page);
			continue;
		}

		/* Did somebody else fill it already? */
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		/* Start the actual read. The read will unlock the page. */
		error = mapping->a_ops->readpage(filp, page);

		if (unlikely(error))
			goto readpage_error;

		if (!PageUptodate(page)) {
			lock_page(page);
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					/*
					 * invalidate_inode_pages got it
					 */
					unlock_page(page);
					page_cache_release(page);
					goto find_page;
				}
				unlock_page(page);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		/*
		 * i_size must be checked after we have done ->readpage.
		 *
		 * Checking i_size after the readpage allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */
		isize = i_size_read(inode);
		end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
		if (unlikely(!isize || index > end_index)) {
			page_cache_release(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_CACHE_SIZE;
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				page_cache_release(page);
				goto out;
			}
		}
		nr = nr - offset;
		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		desc->error = error;
		page_cache_release(page);
		goto out;

no_cached_page:
		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 */
		if (!cached_page) {
			cached_page = page_cache_alloc_cold(mapping);
			if (!cached_page) {
				desc->error = -ENOMEM;
				goto out;
			}
		}
		error = add_to_page_cache_lru(cached_page, mapping,
						index, GFP_KERNEL);
		if (error) {
			if (error == -EEXIST)
				goto find_page;
			desc->error = error;
			goto out;
		}
		page = cached_page;
		cached_page = NULL;
		goto readpage;
	}

out:
	*_ra = ra;

	*ppos = ((loff_t) index << PAGE_CACHE_SHIFT) + offset;
	if (cached_page)
		page_cache_release(cached_page);
	if (filp)
		file_accessed(filp);
}

EXPORT_SYMBOL(do_generic_mapping_read);

int file_read_actor(read_descriptor_t *desc, struct page *page,
			unsigned long offset, unsigned long size)
{
	char *kaddr;
	unsigned long left, count = desc->count;

	if (size > count)
		size = count;

	/*
	 * Faults on the destination of a read are common, so do it before
	 * taking the kmap.
	 */
	if (!fault_in_pages_writeable(desc->arg.buf, size)) {
		kaddr = kmap_atomic(page, KM_USER0);
		left = __copy_to_user_inatomic(desc->arg.buf,
						kaddr + offset, size);
		kunmap_atomic(kaddr, KM_USER0);
		if (left == 0)
			goto success;
	}

	/* Do it the slow way */
	kaddr = kmap(page);
	left = __copy_to_user(desc->arg.buf, kaddr + offset, size);
	kunmap(page);

	if (left) {
		size -= left;
		desc->error = -EFAULT;
	}
success:
	desc->count = count - size;
	desc->written += size;
	desc->arg.buf += size;
	return size;
}

ssize_t
__generic_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t *ppos)
{
	struct file *filp = iocb->ki_filp;
	ssize_t retval;
	unsigned long seg;
	size_t count;

	count = 0;
	for (seg = 0; seg < nr_segs; seg++) {
		const struct iovec *iv = &iov[seg];

		/*
		 * If any segment has a negative length, or the cumulative
		 * length ever wraps negative then return -EINVAL.
		 */
		count += iv->iov_len;
		if (unlikely((ssize_t)(count|iv->iov_len) < 0))
			return -EINVAL;
		if (access_ok(VERIFY_WRITE, iv->iov_base, iv->iov_len))
			continue;
		if (seg == 0)
			return -EFAULT;
		nr_segs = seg;
		count -= iv->iov_len;	/* This segment is no good */
		break;
	}

	/* coalesce the iovecs and go direct-to-BIO for O_DIRECT */
	if (filp->f_flags & O_DIRECT) {
		loff_t pos = *ppos, size;
		struct address_space *mapping;
		struct inode *inode;

		mapping = filp->f_mapping;
		inode = mapping->host;
		retval = 0;
		if (!count)
			goto out; /* skip atime */
		size = i_size_read(inode);
		if (pos < size) {
			retval = generic_file_direct_IO(READ, iocb,
						iov, pos, nr_segs);
			if (retval >= 0 && !is_sync_kiocb(iocb))
				retval = -EIOCBQUEUED;
			if (retval > 0)
				*ppos = pos + retval;
		}
		file_accessed(filp);
		goto out;
	}

	retval = 0;
	if (count) {
		for (seg = 0; seg < nr_segs; seg++) {
			read_descriptor_t desc;

			desc.written = 0;
			desc.arg.buf = iov[seg].iov_base;
			desc.count = iov[seg].iov_len;
			if (desc.count == 0)
				continue;
			desc.error = 0;
			do_generic_file_read(filp,ppos,&desc,file_read_actor);
			retval += desc.written;
			if (!retval) {
				retval = desc.error;
				break;
			}
		}
	}
out:
	return retval;
}

EXPORT_SYMBOL(__generic_file_aio_read);

ssize_t
generic_file_aio_read(struct kiocb *iocb, char __user *buf, size_t count, loff_t pos)
{
	struct iovec local_iov = { .iov_base = buf, .iov_len = count };

	BUG_ON(iocb->ki_pos != pos);
	return __generic_file_aio_read(iocb, &local_iov, 1, &iocb->ki_pos);
}

EXPORT_SYMBOL(generic_file_aio_read);

ssize_t
generic_file_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
	struct iovec local_iov = { .iov_base = buf, .iov_len = count };
	struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	ret = __generic_file_aio_read(&kiocb, &local_iov, 1, ppos);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);
	return ret;
}

EXPORT_SYMBOL(generic_file_read);

ssize_t generic_file_sendfile(struct file *in_file, loff_t *ppos,
			 size_t count, read_actor_t actor, void *target)
{
	panic("in generic_file_sendfile");
	return 0;
}

EXPORT_SYMBOL(generic_file_sendfile);

struct page * filemap_nopage(struct vm_area_struct * area, unsigned long address, int *type)
{
	panic("in filemap_nopage");
	return 0;
}

EXPORT_SYMBOL(filemap_nopage);

int filemap_populate(struct vm_area_struct *vma, unsigned long addr,
		unsigned long len, pgprot_t prot, unsigned long pgoff,
		int nonblock)
{
	panic("in filemap_populate");
	return 0;
}

EXPORT_SYMBOL(filemap_populate);

struct vm_operations_struct generic_file_vm_ops = {
	.nopage		= filemap_nopage,
	.populate	= filemap_populate,
};

int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct address_space *mapping = file->f_mapping;

	if (!mapping->a_ops->readpage)
		return -ENOEXEC;
	file_accessed(file);
	vma->vm_ops = &generic_file_vm_ops;
	return 0;
}

static inline struct page *__read_cache_page(struct address_space *mapping,
				unsigned long index,
				int (*filler)(void *,struct page*),
				void *data)
{
	struct page *page, *cached_page = NULL;
	int err;
repeat:
	page = find_get_page(mapping, index);
	if (!page) {
		if (!cached_page) {
			cached_page = page_cache_alloc_cold(mapping);
			if (!cached_page)
				return ERR_PTR(-ENOMEM);
		}
		err = add_to_page_cache_lru(cached_page, mapping,
					index, GFP_KERNEL);
		if (err == -EEXIST)
			goto repeat;
		if (err < 0) {
			/* Presumably ENOMEM for radix tree node */
			page_cache_release(cached_page);
			return ERR_PTR(err);
		}
		page = cached_page;
		cached_page = NULL;
		err = filler(data, page);
		if (err < 0) {
			page_cache_release(page);
			page = ERR_PTR(err);
		}
	}
	if (cached_page)
		page_cache_release(cached_page);
	return page;
}

/*
 * Read into the page cache. If a page already exists,
 * and PageUptodate() is not set, try to fill the page.
 */
struct page *read_cache_page(struct address_space *mapping,
				unsigned long index,
				int (*filler)(void *,struct page*),
				void *data)
{
	struct page *page;
	int err;

retry:
	page = __read_cache_page(mapping, index, filler, data);
	if (IS_ERR(page))
		goto out;
	mark_page_accessed(page);
	if (PageUptodate(page))
		goto out;

	lock_page(page);
	if (!page->mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto retry;
	}
	if (PageUptodate(page)) {
		unlock_page(page);
		goto out;
	}
	err = filler(data, page);
	if (err < 0) {
		page_cache_release(page);
		page = ERR_PTR(err);
	}
 out:
	return page;
}

EXPORT_SYMBOL(read_cache_page);



ssize_t
generic_file_write_nolock(struct file *file, const struct iovec *iov,
				unsigned long nr_segs, loff_t *ppos)
{
	panic("in generic_file_write_nolock");
	return 0;
}

EXPORT_SYMBOL(generic_file_write_nolock);

ssize_t generic_file_aio_write(struct kiocb *iocb, const char __user *buf,
			       size_t count, loff_t pos)
{
	panic("in generic_file_aio_write");
	return 0;
}

EXPORT_SYMBOL(generic_file_aio_write);

ssize_t generic_file_write(struct file *file, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	panic("in generic_file_write");
	return 0;
}

EXPORT_SYMBOL(generic_file_write);

ssize_t generic_file_readv(struct file *filp, const struct iovec *iov,
			unsigned long nr_segs, loff_t *ppos)
{
	panic("in generic_file_readv");
	return 0;
}

EXPORT_SYMBOL(generic_file_readv);

ssize_t generic_file_writev(struct file *file, const struct iovec *iov,
			unsigned long nr_segs, loff_t *ppos)
{
	panic("in generic_file_writev");
	return 0;
}

EXPORT_SYMBOL(generic_file_writev);

ssize_t
generic_file_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
	loff_t offset, unsigned long nr_segs)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	ssize_t retval;

	/*
	 * If it's a write, unmap all mmappings of the file up-front.  This
	 * will cause any pte dirty bits to be propagated into the pageframes
	 * for the subsequent filemap_write_and_wait().
	 */
	if (rw == WRITE && mapping_mapped(mapping))
		unmap_mapping_range(mapping, 0, -1, 0);

	retval = filemap_write_and_wait(mapping);
	if (retval == 0) {
		retval = mapping->a_ops->direct_IO(rw, iocb, iov,
						offset, nr_segs);
		if (rw == WRITE && mapping->nrpages) {
			int err = invalidate_inode_pages2(mapping);
			if (err)
				retval = err;
		}
	}
	return retval;
}
EXPORT_SYMBOL_GPL(generic_file_direct_IO);