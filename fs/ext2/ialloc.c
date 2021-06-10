#include <linux/config.h>
#include <linux/quotaops.h>
#include <linux/sched.h>
#include <linux/backing-dev.h>
#include <linux/buffer_head.h>
#include <linux/random.h>
#include "ext2.h"
#include "xattr.h"
#include "acl.h"


static struct buffer_head *
read_inode_bitmap(struct super_block * sb, unsigned long block_group)
{
    panic("in read_inode_bitmap");
	return NULL;
}

static void ext2_release_inode(struct super_block *sb, int group, int dir)
{
    panic("in ext2_release_inode");
}

void ext2_free_inode (struct inode * inode)
{
    panic("in ext2_free_inode");
}

static void ext2_preread_inode(struct inode *inode)
{
    panic("in ext2_preread_inode");
}

static int find_group_dir(struct super_block *sb, struct inode *parent)
{
    panic("in find_group_dir");
	return 0;
}

#define INODE_COST 64
#define BLOCK_COST 256

static int find_group_orlov(struct super_block *sb, struct inode *parent)
{
    panic("in find_group_orlov");
	return 0;
}

static int find_group_other(struct super_block *sb, struct inode *parent)
{
    panic("in find_group_other");
	return 0;
}

struct inode *ext2_new_inode(struct inode *dir, int mode)
{
    panic("in ext2_new_inode");
	return NULL;
}

unsigned long ext2_count_free_inodes (struct super_block * sb)
{
    panic("in ext2_count_free_inodes");
	return 0;
}

unsigned long ext2_count_dirs (struct super_block * sb)
{
    panic("in ext2_count_dirs");
	return 0;
}

#ifdef CONFIG_EXT2_CHECK
#error "CONFIG_EXT2_CHECK"
#endif /* CONFIG_EXT2_CHECK */