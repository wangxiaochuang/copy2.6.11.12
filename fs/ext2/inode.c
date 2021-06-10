#include <linux/smp_lock.h>
#include <linux/time.h>
#include <linux/highuid.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include "ext2.h"
#include "acl.h"

MODULE_AUTHOR("Remy Card and others");
MODULE_DESCRIPTION("Second Extended Filesystem");
MODULE_LICENSE("GPL");

static int ext2_update_inode(struct inode * inode, int do_sync);

static inline int ext2_inode_is_fast_symlink(struct inode *inode)
{
	int ea_blocks = EXT2_I(inode)->i_file_acl ?
		(inode->i_sb->s_blocksize >> 9) : 0;

	return (S_ISLNK(inode->i_mode) &&
		inode->i_blocks - ea_blocks == 0);
}

void ext2_delete_inode (struct inode * inode)
{
    panic("in ext2_delete_inode");
}

void ext2_discard_prealloc (struct inode * inode)
{
    panic("in ext2_discard_prealloc");
}

static int ext2_alloc_block (struct inode * inode, unsigned long goal, int *err)
{
    panic("in ext2_alloc_block");
    return 0;
}

typedef struct {
	__le32	*p;
	__le32	key;
	struct buffer_head *bh;
} Indirect;

static inline void add_chain(Indirect *p, struct buffer_head *bh, __le32 *v)
{
	p->key = *(p->p = v);
	p->bh = bh;
}

static inline int verify_chain(Indirect *from, Indirect *to)
{
	while (from <= to && from->key == *from->p)
		from++;
	return (from > to);
}

static int ext2_block_to_path(struct inode *inode,
			long i_block, int offsets[4], int *boundary)
{
    panic("in ext2_block_to_path");
    return 0;
}

static Indirect *ext2_get_branch(struct inode *inode,
				 int depth,
				 int *offsets,
				 Indirect chain[4],
				 int *err)
{
    panic("in ext2_get_branch");
    return NULL;
}

static unsigned long ext2_find_near(struct inode *inode, Indirect *ind)
{
	panic("in ext2_find_near");
	return 0;
}

static inline int ext2_find_goal(struct inode *inode,
				 long block,
				 Indirect chain[4],
				 Indirect *partial,
				 unsigned long *goal)
{
	panic("in ext2_find_goal");
	return 0;
}

static int ext2_alloc_branch(struct inode *inode,
			     int num,
			     unsigned long goal,
			     int *offsets,
			     Indirect *branch)
{
	panic("in ext2_alloc_branch");
	return 0;
}

static inline int ext2_splice_branch(struct inode *inode,
				     long block,
				     Indirect chain[4],
				     Indirect *where,
				     int num)
{
	panic("in ext2_splice_branch");
	return 0;
}

int ext2_get_block(struct inode *inode, sector_t iblock, struct buffer_head *bh_result, int create)
{
    panic("in ext2_get_block");
    return 0;
}

static int ext2_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, ext2_get_block, wbc);
}

static int ext2_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, ext2_get_block);
}

static int
ext2_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, ext2_get_block);
}

static int
ext2_prepare_write(struct file *file, struct page *page,
			unsigned from, unsigned to)
{
	return block_prepare_write(page,from,to,ext2_get_block);
}

static int
ext2_nobh_prepare_write(struct file *file, struct page *page,
			unsigned from, unsigned to)
{
	return nobh_prepare_write(page,from,to,ext2_get_block);
}

static sector_t ext2_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping,block,ext2_get_block);
}

static int
ext2_get_blocks(struct inode *inode, sector_t iblock, unsigned long max_blocks,
			struct buffer_head *bh_result, int create)
{
	int ret;

	ret = ext2_get_block(inode, iblock, bh_result, create);
	if (ret == 0)
		bh_result->b_size = (1 << inode->i_blkbits);
	return ret;
}

static ssize_t
ext2_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
			loff_t offset, unsigned long nr_segs)
{
    panic("in ext2_direct_IO");
    return 0;
}

static int
ext2_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, ext2_get_block);
}

struct address_space_operations ext2_aops = {
	.readpage		= ext2_readpage,
	.readpages		= ext2_readpages,
	.writepage		= ext2_writepage,
	.sync_page		= block_sync_page,
	.prepare_write		= ext2_prepare_write,
	.commit_write		= generic_commit_write,
	.bmap			= ext2_bmap,
	.direct_IO		= ext2_direct_IO,
	.writepages		= ext2_writepages,
};

struct address_space_operations ext2_nobh_aops = {
	.readpage		= ext2_readpage,
	.readpages		= ext2_readpages,
	.writepage		= ext2_writepage,
	.sync_page		= block_sync_page,
	.prepare_write		= ext2_nobh_prepare_write,
	.commit_write		= nobh_commit_write,
	.bmap			= ext2_bmap,
	.direct_IO		= ext2_direct_IO,
	.writepages		= ext2_writepages,
};

static inline int all_zeroes(__le32 *p, __le32 *q)
{
	while (p < q)
		if (*p++)
			return 0;
	return 1;
}

static Indirect *ext2_find_shared(struct inode *inode,
				int depth,
				int offsets[4],
				Indirect chain[4],
				__le32 *top)
{
    panic("in ext2_find_shared");
    return NULL;
}

static inline void ext2_free_data(struct inode *inode, __le32 *p, __le32 *q)
{
	panic("in ext2_free_data");
}


static void ext2_free_branches(struct inode *inode, __le32 *p, __le32 *q, int depth)
{
	panic("in ext2_free_branches");
}

void ext2_truncate (struct inode * inode)
{
	panic("in ext2_truncate");
}

static struct ext2_inode *ext2_get_inode(struct super_block *sb, ino_t ino,
					struct buffer_head **p)
{
	panic("in ext2_get_inode");
	return NULL;
}


void ext2_set_inode_flags(struct inode *inode)
{
	unsigned int flags = EXT2_I(inode)->i_flags;

	inode->i_flags &= ~(S_SYNC|S_APPEND|S_IMMUTABLE|S_NOATIME|S_DIRSYNC);
	if (flags & EXT2_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & EXT2_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & EXT2_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & EXT2_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & EXT2_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
}

void ext2_read_inode (struct inode * inode)
{
    panic("in ext2_read_inode");
}

static int ext2_update_inode(struct inode * inode, int do_sync)
{
    panic("in ext2_update_inode");
    return 0;
}

int ext2_write_inode(struct inode *inode, int wait)
{
	return ext2_update_inode(inode, wait);
}

int ext2_sync_inode(struct inode *inode)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = 0,	/* sys_fsync did this */
	};
	return sync_inode(inode, &wbc);
}

int ext2_setattr(struct dentry *dentry, struct iattr *iattr)
{
    panic("in ext2_setattr");
    return 0;
}

