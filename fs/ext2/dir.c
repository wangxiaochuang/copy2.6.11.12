#include "ext2.h"
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

typedef struct ext2_dir_entry_2 ext2_dirent;

/*
 * ext2 uses block-sized chunks. Arguably, sector-sized ones would be
 * more robust, but we have what we have
 */
static inline unsigned ext2_chunk_size(struct inode *inode)
{
	return inode->i_sb->s_blocksize;
}

static inline void ext2_put_page(struct page *page)
{
	kunmap(page);
	page_cache_release(page);
}

static inline unsigned long dir_pages(struct inode *inode)
{
	return (inode->i_size+PAGE_CACHE_SIZE-1)>>PAGE_CACHE_SHIFT;
}

static unsigned
ext2_last_byte(struct inode *inode, unsigned long page_nr)
{
	unsigned last_byte = inode->i_size;

	last_byte -= page_nr << PAGE_CACHE_SHIFT;
	if (last_byte > PAGE_CACHE_SIZE)
		last_byte = PAGE_CACHE_SIZE;
	return last_byte;
}

static int ext2_commit_chunk(struct page *page, unsigned from, unsigned to)
{
	panic("in ext2_commit_chunk");
	return 0;
}

static void ext2_check_page(struct page *page)
{
	panic("in ext2_check_page");
}

static struct page * ext2_get_page(struct inode *dir, unsigned long n)
{
	panic("in ext2_get_page");
	return NULL;
}

static inline int ext2_match (int len, const char * const name,
					struct ext2_dir_entry_2 * de)
{
	if (len != de->name_len)
		return 0;
	if (!de->inode)
		return 0;
	return !memcmp(name, de->name, len);
}

static inline ext2_dirent *ext2_next_entry(ext2_dirent *p)
{
	return (ext2_dirent *)((char*)p + le16_to_cpu(p->rec_len));
}

static inline unsigned 
ext2_validate_entry(char *base, unsigned offset, unsigned mask)
{
	ext2_dirent *de = (ext2_dirent*)(base + offset);
	ext2_dirent *p = (ext2_dirent*)(base + (offset&mask));
	while ((char*)p < (char*)de) {
		if (p->rec_len == 0)
			break;
		p = ext2_next_entry(p);
	}
	return (char *)p - base;
}

static unsigned char ext2_filetype_table[EXT2_FT_MAX] = {
	[EXT2_FT_UNKNOWN]	= DT_UNKNOWN,
	[EXT2_FT_REG_FILE]	= DT_REG,
	[EXT2_FT_DIR]		= DT_DIR,
	[EXT2_FT_CHRDEV]	= DT_CHR,
	[EXT2_FT_BLKDEV]	= DT_BLK,
	[EXT2_FT_FIFO]		= DT_FIFO,
	[EXT2_FT_SOCK]		= DT_SOCK,
	[EXT2_FT_SYMLINK]	= DT_LNK,
};

#define S_SHIFT 12
static unsigned char ext2_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= EXT2_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= EXT2_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= EXT2_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= EXT2_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= EXT2_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= EXT2_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= EXT2_FT_SYMLINK,
};

static inline void ext2_set_de_type(ext2_dirent *de, struct inode *inode)
{
	mode_t mode = inode->i_mode;
	if (EXT2_HAS_INCOMPAT_FEATURE(inode->i_sb, EXT2_FEATURE_INCOMPAT_FILETYPE))
		de->file_type = ext2_type_by_mode[(mode & S_IFMT)>>S_SHIFT];
	else
		de->file_type = 0;
}

static int
ext2_readdir (struct file * filp, void * dirent, filldir_t filldir)
{
	panic("in ext2_readdir");
	return 0;
}

struct ext2_dir_entry_2 * ext2_find_entry (struct inode * dir,
			struct dentry *dentry, struct page ** res_page)
{
	panic("in ext2_find_entry");
	return NULL;
}

struct ext2_dir_entry_2 * ext2_dotdot (struct inode *dir, struct page **p)
{
	panic("in ext2_dotdot");
	return NULL;
}

ino_t ext2_inode_by_name(struct inode * dir, struct dentry *dentry)
{
	panic("in ext2_inode_by_name");
	return 0;
}

void ext2_set_link(struct inode *dir, struct ext2_dir_entry_2 *de,
			struct page *page, struct inode *inode)
{
	panic("in ext2_set_link");
}

int ext2_add_link (struct dentry *dentry, struct inode *inode)
{
	panic("in ext2_add_link");
	return 0;
}

int ext2_delete_entry (struct ext2_dir_entry_2 * dir, struct page * page )
{
	panic("in ext2_delete_entry");
	return 0;
}

int ext2_make_empty(struct inode *inode, struct inode *parent)
{
	panic("in ext2_make_empty");
	return 0;
}

int ext2_empty_dir (struct inode * inode)
{
	panic("in ext2_empty_dir");
	return 0;
}

struct file_operations ext2_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= ext2_readdir,
	.ioctl		= ext2_ioctl,
	.fsync		= ext2_sync_file,
};