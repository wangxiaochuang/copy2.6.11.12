#include <linux/config.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/parser.h>
#include <linux/random.h>
#include <linux/buffer_head.h>
#include <linux/smp_lock.h>
#include <linux/vfs.h>
#include <asm/uaccess.h>
#include "ext2.h"
#include "xattr.h"
#include "acl.h"

static void ext2_sync_super(struct super_block *sb,
			    struct ext2_super_block *es);
static int ext2_remount (struct super_block * sb, int * flags, char * data);
static int ext2_statfs (struct super_block * sb, struct kstatfs * buf);

void ext2_error (struct super_block * sb, const char * function,
		 const char * fmt, ...)
{
	panic("in ext2_error");
}

void ext2_warning (struct super_block * sb, const char * function,
		   const char * fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	printk(KERN_WARNING "EXT2-fs warning (device %s): %s: ",
	       sb->s_id, function);
	vprintk(fmt, args);
	printk("\n");
	va_end(args);
}

void ext2_update_dynamic_rev(struct super_block *sb)
{
	panic("in ext2_update_dynamic_rev");
}

static void ext2_put_super (struct super_block * sb)
{
	panic("in ext2_put_super");
}

static kmem_cache_t * ext2_inode_cachep;

static struct inode *ext2_alloc_inode(struct super_block *sb)
{
	struct ext2_inode_info *ei;
	ei = (struct ext2_inode_info *)kmem_cache_alloc(ext2_inode_cachep, SLAB_KERNEL);
	if (!ei)
		return NULL;
#ifdef CONFIG_EXT2_FS_POSIX_ACL
	ei->i_acl = EXT2_ACL_NOT_CACHED;
	ei->i_default_acl = EXT2_ACL_NOT_CACHED;
#endif
	ei->vfs_inode.i_version = 1;
	return &ei->vfs_inode;
}

static void ext2_destroy_inode(struct inode *inode)
{
	kmem_cache_free(ext2_inode_cachep, EXT2_I(inode));
}

static void init_once(void * foo, kmem_cache_t * cachep, unsigned long flags)
{
	struct ext2_inode_info *ei = (struct ext2_inode_info *) foo;

	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
	    SLAB_CTOR_CONSTRUCTOR) {
		rwlock_init(&ei->i_meta_lock);
#ifdef CONFIG_EXT2_FS_XATTR
		init_rwsem(&ei->xattr_sem);
#endif
		inode_init_once(&ei->vfs_inode);
	}
}

static int init_inodecache(void)
{
	ext2_inode_cachep = kmem_cache_create("ext2_inode_cache",
					     sizeof(struct ext2_inode_info),
					     0, SLAB_RECLAIM_ACCOUNT,
					     init_once, NULL);
	if (ext2_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	if (kmem_cache_destroy(ext2_inode_cachep))
		printk(KERN_INFO "ext2_inode_cache: not all structures were freed\n");
}

static void ext2_clear_inode(struct inode *inode)
{
	panic("in ext2_clear_inode");
}

#ifdef CONFIG_QUOTA
static ssize_t ext2_quota_read(struct super_block *sb, int type, char *data, size_t len, loff_t off);
static ssize_t ext2_quota_write(struct super_block *sb, int type, const char *data, size_t len, loff_t off);
#endif

static struct super_operations ext2_sops = {
	.alloc_inode	= ext2_alloc_inode,
	.destroy_inode	= ext2_destroy_inode,
	.read_inode	= ext2_read_inode,
	.write_inode	= ext2_write_inode,
	.delete_inode	= ext2_delete_inode,
	.put_super	= ext2_put_super,
	.write_super	= ext2_write_super,
	.statfs		= ext2_statfs,
	.remount_fs	= ext2_remount,
	.clear_inode	= ext2_clear_inode,
#ifdef CONFIG_QUOTA
	.quota_read	= ext2_quota_read,
	.quota_write	= ext2_quota_write,
#endif
};

struct dentry *ext2_get_parent(struct dentry *child);
static struct export_operations ext2_export_ops = {
	.get_parent = ext2_get_parent,
};

static unsigned long get_sb_block(void **data)
{
	unsigned long sb_block;
	char *options = (char *) *data;

	if (!options || strncmp(options, "sb=", 3) != 0)
		return 1;
	options += 3;
	sb_block = simple_strtoul(options, &options, 0);
	if (*options && *options != ',') {
		printk("EXT2-fs: Invalid sb specification: %s\n",
		       (char *) *data);
		return 1;
	}
	if (*options == ',')
		options++;
	*data = (void *) options;
	return sb_block;
}

enum {
	Opt_bsd_df, Opt_minix_df, Opt_grpid, Opt_nogrpid,
	Opt_resgid, Opt_resuid, Opt_sb, Opt_err_cont, Opt_err_panic, Opt_err_ro,
	Opt_nouid32, Opt_check, Opt_nocheck, Opt_debug, Opt_oldalloc, Opt_orlov, Opt_nobh,
	Opt_user_xattr, Opt_nouser_xattr, Opt_acl, Opt_noacl,
	Opt_ignore, Opt_err,
};

static match_table_t tokens = {
	{Opt_bsd_df, "bsddf"},
	{Opt_minix_df, "minixdf"},
	{Opt_grpid, "grpid"},
	{Opt_grpid, "bsdgroups"},
	{Opt_nogrpid, "nogrpid"},
	{Opt_nogrpid, "sysvgroups"},
	{Opt_resgid, "resgid=%u"},
	{Opt_resuid, "resuid=%u"},
	{Opt_sb, "sb=%u"},
	{Opt_err_cont, "errors=continue"},
	{Opt_err_panic, "errors=panic"},
	{Opt_err_ro, "errors=remount-ro"},
	{Opt_nouid32, "nouid32"},
	{Opt_nocheck, "check=none"},
	{Opt_nocheck, "nocheck"},
	{Opt_check, "check"},
	{Opt_debug, "debug"},
	{Opt_oldalloc, "oldalloc"},
	{Opt_orlov, "orlov"},
	{Opt_nobh, "nobh"},
	{Opt_user_xattr, "user_xattr"},
	{Opt_nouser_xattr, "nouser_xattr"},
	{Opt_acl, "acl"},
	{Opt_noacl, "noacl"},
	{Opt_ignore, "grpquota"},
	{Opt_ignore, "noquota"},
	{Opt_ignore, "quota"},
	{Opt_ignore, "usrquota"},
	{Opt_err, NULL}
};

static int parse_options (char * options,
			  struct ext2_sb_info *sbi)
{
	panic("in parse_options");
}

static int ext2_setup_super (struct super_block * sb,
			      struct ext2_super_block * es,
			      int read_only)
{
	panic("in ext2_setup_super");
	return 0;
}

static int ext2_check_descriptors (struct super_block * sb)
{
	panic("in ext2_check_descriptors");
	return 0;
}

#define log2(n) ffz(~(n))

static loff_t ext2_max_size(int bits)
{
	loff_t res = EXT2_NDIR_BLOCKS;
	res += 1LL << (bits-2);
	res += 1LL << (2*(bits-2));
	res += 1LL << (3*(bits-2));
	res <<= bits;
	if (res > (512LL << 32) - (1 << bits))
		res = (512LL << 32) - (1 << bits);
	return res;
}

static unsigned long descriptor_loc(struct super_block *sb,
				    unsigned long logic_sb_block,
				    int nr)
{
	panic("in descriptor_loc");
	return 0;
}



static int ext2_fill_super(struct super_block *sb, void *data, int silent)
{
    struct buffer_head * bh;
	struct ext2_sb_info * sbi;
	struct ext2_super_block * es;
	struct inode *root;
	unsigned long block;
	unsigned long sb_block = get_sb_block(&data);
	unsigned long logic_sb_block;
	unsigned long offset = 0;
	unsigned long def_mount_opts;
	int blocksize = BLOCK_SIZE;
	int db_count;
	int i, j;
	__le32 features;

	sbi = kmalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;
	memset(sbi, 0, sizeof(*sbi));

	blocksize = sb_min_blocksize(sb, BLOCK_SIZE);
	if (!blocksize) {
		printk ("EXT2-fs: unable to set blocksize\n");
		goto failed_sbi;
	}

	if (blocksize != BLOCK_SIZE) {
		logic_sb_block = (sb_block*BLOCK_SIZE) / blocksize;
		offset = (sb_block*BLOCK_SIZE) % blocksize;
	} else {
		logic_sb_block = sb_block;
	}

	if (!(bh = sb_bread(sb, logic_sb_block))) {
		printk ("EXT2-fs: unable to read superblock\n");
		goto failed_sbi;
	}

	es = (struct ext2_super_block *) (((char *)bh->b_data) + offset);
	sbi->s_es = es;
	sb->s_magic = le16_to_cpu(es->s_magic);

	if (sb->s_magic != EXT2_SUPER_MAGIC)
		goto cantfind_ext2;

	/* Set defaults before we parse the mount options */
	def_mount_opts = le32_to_cpu(es->s_default_mount_opts);
	if (def_mount_opts & EXT2_DEFM_DEBUG)
		set_opt(sbi->s_mount_opt, DEBUG);
	if (def_mount_opts & EXT2_DEFM_BSDGROUPS)
		set_opt(sbi->s_mount_opt, GRPID);
	if (def_mount_opts & EXT2_DEFM_UID16)
		set_opt(sbi->s_mount_opt, NO_UID32);
	if (def_mount_opts & EXT2_DEFM_XATTR_USER)
		set_opt(sbi->s_mount_opt, XATTR_USER);
	if (def_mount_opts & EXT2_DEFM_ACL)
		set_opt(sbi->s_mount_opt, POSIX_ACL);
	
	if (le16_to_cpu(sbi->s_es->s_errors) == EXT2_ERRORS_PANIC)
		set_opt(sbi->s_mount_opt, ERRORS_PANIC);
	else if (le16_to_cpu(sbi->s_es->s_errors) == EXT2_ERRORS_RO)
		set_opt(sbi->s_mount_opt, ERRORS_RO);

	sbi->s_resuid = le16_to_cpu(es->s_def_resuid);
	sbi->s_resgid = le16_to_cpu(es->s_def_resgid);

	if (!parse_options ((char *) data, sbi))
		goto failed_mount;

	sb->s_flags = (sb->s_flags & ~MS_POSIXACL) |
		((EXT2_SB(sb)->s_mount_opt & EXT2_MOUNT_POSIX_ACL) ?
		 MS_POSIXACL : 0);

	if (le32_to_cpu(es->s_rev_level) == EXT2_GOOD_OLD_REV &&
	    (EXT2_HAS_COMPAT_FEATURE(sb, ~0U) ||
	     EXT2_HAS_RO_COMPAT_FEATURE(sb, ~0U) ||
	     EXT2_HAS_INCOMPAT_FEATURE(sb, ~0U)))
		printk("EXT2-fs warning: feature flags set on rev 0 fs, "
		       "running e2fsck is recommended\n");

	features = EXT2_HAS_INCOMPAT_FEATURE(sb, ~EXT2_FEATURE_INCOMPAT_SUPP);
	if (features) {
		printk("EXT2-fs: %s: couldn't mount because of "
		       "unsupported optional features (%x).\n",
		       sb->s_id, le32_to_cpu(features));
		goto failed_mount;
	}
	if (!(sb->s_flags & MS_RDONLY) &&
	    (features = EXT2_HAS_RO_COMPAT_FEATURE(sb, ~EXT2_FEATURE_RO_COMPAT_SUPP))){
		printk("EXT2-fs: %s: couldn't mount RDWR because of "
		       "unsupported optional features (%x).\n",
		       sb->s_id, le32_to_cpu(features));
		goto failed_mount;
	}

	blocksize = BLOCK_SIZE << le32_to_cpu(sbi->s_es->s_log_block_size);

	if (sb->s_blocksize != blocksize) {
		brelse(bh);

		if (!sb_set_blocksize(sb, blocksize)) {
			printk(KERN_ERR "EXT2-fs: blocksize too small for device.\n");
			goto failed_sbi;
		}

		logic_sb_block = (sb_block*BLOCK_SIZE) / blocksize;
		offset = (sb_block*BLOCK_SIZE) % blocksize;
		bh = sb_bread(sb, logic_sb_block);
		if(!bh) {
			printk("EXT2-fs: Couldn't read superblock on "
			       "2nd try.\n");
			goto failed_sbi;
		}
		es = (struct ext2_super_block *) (((char *)bh->b_data) + offset);
		sbi->s_es = es;
		if (es->s_magic != cpu_to_le16(EXT2_SUPER_MAGIC)) {
			printk ("EXT2-fs: Magic mismatch, very weird !\n");
			goto failed_mount;
		}
	}

	sb->s_maxbytes = ext2_max_size(sb->s_blocksize_bits);

	if (le32_to_cpu(es->s_rev_level) == EXT2_GOOD_OLD_REV) {
		sbi->s_inode_size = EXT2_GOOD_OLD_INODE_SIZE;
		sbi->s_first_ino = EXT2_GOOD_OLD_FIRST_INO;
	} else {
		sbi->s_inode_size = le16_to_cpu(es->s_inode_size);
		sbi->s_first_ino = le32_to_cpu(es->s_first_ino);
		if ((sbi->s_inode_size < EXT2_GOOD_OLD_INODE_SIZE) ||
		    (sbi->s_inode_size & (sbi->s_inode_size - 1)) ||
		    (sbi->s_inode_size > blocksize)) {
			printk ("EXT2-fs: unsupported inode size: %d\n",
				sbi->s_inode_size);
			goto failed_mount;
		}
	}

	sbi->s_frag_size = EXT2_MIN_FRAG_SIZE <<
				   le32_to_cpu(es->s_log_frag_size);
	if (sbi->s_frag_size == 0)
		goto cantfind_ext2;
	sbi->s_frags_per_block = sb->s_blocksize / sbi->s_frag_size;

	sbi->s_blocks_per_group = le32_to_cpu(es->s_blocks_per_group);
	sbi->s_frags_per_group = le32_to_cpu(es->s_frags_per_group);
	sbi->s_inodes_per_group = le32_to_cpu(es->s_inodes_per_group);

	if (EXT2_INODE_SIZE(sb) == 0)
		goto cantfind_ext2;
	sbi->s_inodes_per_block = sb->s_blocksize / EXT2_INODE_SIZE(sb);
	if (sbi->s_inodes_per_block == 0)
		goto cantfind_ext2;
	sbi->s_itb_per_group = sbi->s_inodes_per_group /
					sbi->s_inodes_per_block;
	sbi->s_desc_per_block = sb->s_blocksize /
					sizeof (struct ext2_group_desc);
	sbi->s_sbh = bh;
	sbi->s_mount_state = le16_to_cpu(es->s_state);
	sbi->s_addr_per_block_bits =
		log2 (EXT2_ADDR_PER_BLOCK(sb));
	sbi->s_desc_per_block_bits =
		log2 (EXT2_DESC_PER_BLOCK(sb));

	if (sb->s_magic != EXT2_SUPER_MAGIC)
		goto cantfind_ext2;

	if (sb->s_blocksize != bh->b_size) {
		if (!silent)
			printk ("VFS: Unsupported blocksize on dev "
				"%s.\n", sb->s_id);
		goto failed_mount;
	}

	if (sb->s_blocksize != sbi->s_frag_size) {
		printk ("EXT2-fs: fragsize %lu != blocksize %lu (not supported yet)\n",
			sbi->s_frag_size, sb->s_blocksize);
		goto failed_mount;
	}

	if (sbi->s_blocks_per_group > sb->s_blocksize * 8) {
		printk ("EXT2-fs: #blocks per group too big: %lu\n",
			sbi->s_blocks_per_group);
		goto failed_mount;
	}
	if (sbi->s_frags_per_group > sb->s_blocksize * 8) {
		printk ("EXT2-fs: #fragments per group too big: %lu\n",
			sbi->s_frags_per_group);
		goto failed_mount;
	}

	if (sbi->s_inodes_per_group > sb->s_blocksize * 8) {
		printk ("EXT2-fs: #inodes per group too big: %lu\n",
			sbi->s_inodes_per_group);
		goto failed_mount;
	}

	if (EXT2_BLOCKS_PER_GROUP(sb) == 0)
		goto cantfind_ext2;
	sbi->s_groups_count = (le32_to_cpu(es->s_blocks_count) -
				        le32_to_cpu(es->s_first_data_block) +
				       EXT2_BLOCKS_PER_GROUP(sb) - 1) /
				       EXT2_BLOCKS_PER_GROUP(sb);
	db_count = (sbi->s_groups_count + EXT2_DESC_PER_BLOCK(sb) - 1) /
		   EXT2_DESC_PER_BLOCK(sb);
	sbi->s_group_desc = kmalloc (db_count * sizeof (struct buffer_head *), GFP_KERNEL);
	if (sbi->s_group_desc == NULL) {
		printk ("EXT2-fs: not enough memory\n");
		goto failed_mount;
	}
	percpu_counter_init(&sbi->s_freeblocks_counter);
	percpu_counter_init(&sbi->s_freeinodes_counter);
	percpu_counter_init(&sbi->s_dirs_counter);
	bgl_lock_init(&sbi->s_blockgroup_lock);
	sbi->s_debts = kmalloc(sbi->s_groups_count * sizeof(*sbi->s_debts),
			       GFP_KERNEL);

	if (!sbi->s_debts) {
		printk ("EXT2-fs: not enough memory\n");
		goto failed_mount_group_desc;
	}
	memset(sbi->s_debts, 0, sbi->s_groups_count * sizeof(*sbi->s_debts));
	for (i = 0; i < db_count; i++) {
		block = descriptor_loc(sb, logic_sb_block, i);
		sbi->s_group_desc[i] = sb_bread(sb, block);
		if (!sbi->s_group_desc[i]) {
			for (j = 0; j < i; j++)
				brelse (sbi->s_group_desc[j]);
			printk ("EXT2-fs: unable to read group descriptors\n");
			goto failed_mount_group_desc;
		}
	}
	if (!ext2_check_descriptors (sb)) {
		printk ("EXT2-fs: group descriptors corrupted!\n");
		db_count = i;
		goto failed_mount2;
	}
	sbi->s_gdb_count = db_count;
	get_random_bytes(&sbi->s_next_generation, sizeof(u32));
	spin_lock_init(&sbi->s_next_gen_lock);
	/*
	 * set up enough so that it can read an inode
	 */
	sb->s_op = &ext2_sops;
	sb->s_export_op = &ext2_export_ops;
	sb->s_xattr = ext2_xattr_handlers;
	root = iget(sb, EXT2_ROOT_INO);
	sb->s_root = d_alloc_root(root);
	if (!sb->s_root) {
		iput(root);
		printk(KERN_ERR "EXT2-fs: get root inode failed\n");
		goto failed_mount2;
	}
	if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		dput(sb->s_root);
		sb->s_root = NULL;
		printk(KERN_ERR "EXT2-fs: corrupt root inode, run e2fsck\n");
		goto failed_mount2;
	}
	if (EXT2_HAS_COMPAT_FEATURE(sb, EXT3_FEATURE_COMPAT_HAS_JOURNAL))
		ext2_warning(sb, __FUNCTION__,
			"mounting ext3 filesystem as ext2\n");
	ext2_setup_super (sb, es, sb->s_flags & MS_RDONLY);
	percpu_counter_mod(&sbi->s_freeblocks_counter,
				ext2_count_free_blocks(sb));
	percpu_counter_mod(&sbi->s_freeinodes_counter,
				ext2_count_free_inodes(sb));
	percpu_counter_mod(&sbi->s_dirs_counter,
				ext2_count_dirs(sb));
	return 0;
cantfind_ext2:
	if (!silent)
		printk("VFS: Can't find an ext2 filesystem on dev %s.\n",
		       sb->s_id);
	goto failed_mount;

failed_mount2:
	for (i = 0; i < db_count; i++)
		brelse(sbi->s_group_desc[i]);
failed_mount_group_desc:
	kfree(sbi->s_group_desc);
	kfree(sbi->s_debts);
failed_mount:
	brelse(bh);
failed_sbi:
	sb->s_fs_info = NULL;
	kfree(sbi);
	return -EINVAL;
}

static void ext2_commit_super (struct super_block * sb,
			       struct ext2_super_block * es)
{
	panic("in ext2_commit_super");
}

static void ext2_sync_super(struct super_block *sb, struct ext2_super_block *es)
{
	panic("in ext2_sync_super");
}

void ext2_write_super (struct super_block * sb)
{
	panic("in ext2_write_super");
}

static int ext2_remount (struct super_block * sb, int * flags, char * data)
{
	panic("in ext2_remount");
	return 0;
}

static int ext2_statfs (struct super_block * sb, struct kstatfs * buf)
{
	panic("in ext2_statfs");
	return 0;
}

static struct super_block *ext2_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return get_sb_bdev(fs_type, flags, dev_name, data, ext2_fill_super);
}

#ifdef CONFIG_QUOTA
static ssize_t ext2_quota_read(struct super_block *sb, int type, char *data,
			       size_t len, loff_t off)
{
	panic("in ext2_quota_read");
	return 0;
}

static ssize_t ext2_quota_write(struct super_block *sb, int type,
				const char *data, size_t len, loff_t off)
{
	panic("in ext2_quota_write");
	return 0;
}
#endif /* CONFIG_QUOTA */

static struct file_system_type ext2_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ext2",
	.get_sb		= ext2_get_sb,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};

static int __init init_ext2_fs(void)
{
	int err = init_ext2_xattr();
	if (err)
		return err;
	err = init_inodecache();
	if (err)
		goto out1;
	err = register_filesystem(&ext2_fs_type);
	if (err)
		goto out;
	return 0;
out:
	destroy_inodecache();
out1:
	exit_ext2_xattr();
	return err;
}

static void __exit exit_ext2_fs(void)
{
	unregister_filesystem(&ext2_fs_type);
	destroy_inodecache();
	exit_ext2_xattr();
}
module_init(init_ext2_fs)
module_exit(exit_ext2_fs)