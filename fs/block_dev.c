#include <linux/config.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/major.h>
#include <linux/devfs_fs_kernel.h>
#include <linux/smp_lock.h>
#include <linux/highmem.h>
#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/blkpg.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/mount.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <asm/uaccess.h>

struct bdev_inode {
	struct block_device bdev;
	struct inode vfs_inode;
};

static inline struct bdev_inode *BDEV_I(struct inode *inode)
{
	return container_of(inode, struct bdev_inode, vfs_inode);
}

static loff_t block_llseek(struct file *file, loff_t offset, int origin)
{
	return 0;
}

static int block_fsync(struct file *filp, struct dentry *dentry, int datasync)
{
	return 0;
}

static  __cacheline_aligned_in_smp DEFINE_SPINLOCK(bdev_lock);
static kmem_cache_t * bdev_cachep;

static struct inode *bdev_alloc_inode(struct super_block *sb)
{
	struct bdev_inode *ei = kmem_cache_alloc(bdev_cachep, SLAB_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void bdev_destroy_inode(struct inode *inode)
{
	struct bdev_inode *bdi = BDEV_I(inode);

	bdi->bdev.bd_inode_backing_dev_info = NULL;
	kmem_cache_free(bdev_cachep, bdi);
}

static void init_once(void * foo, kmem_cache_t * cachep, unsigned long flags)
{
	struct bdev_inode *ei = (struct bdev_inode *) foo;
	struct block_device *bdev = &ei->bdev;

	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
	    SLAB_CTOR_CONSTRUCTOR)
	{
		memset(bdev, 0, sizeof(*bdev));
		sema_init(&bdev->bd_sem, 1);
		sema_init(&bdev->bd_mount_sem, 1);
		INIT_LIST_HEAD(&bdev->bd_inodes);
		INIT_LIST_HEAD(&bdev->bd_list);
		inode_init_once(&ei->vfs_inode);
	}
}

static inline void __bd_forget(struct inode *inode)
{
	list_del_init(&inode->i_devices);
	inode->i_bdev = NULL;
	inode->i_mapping = &inode->i_data;
}

static void bdev_clear_inode(struct inode *inode)
{
	struct block_device *bdev = &BDEV_I(inode)->bdev;
	struct list_head *p;
	spin_lock(&bdev_lock);
	while ( (p = bdev->bd_inodes.next) != &bdev->bd_inodes ) {
		__bd_forget(list_entry(p, struct inode, i_devices));
	}
	list_del_init(&bdev->bd_list);
	spin_unlock(&bdev_lock);
}

static struct super_operations bdev_sops = {
	.statfs = simple_statfs,
	.alloc_inode = bdev_alloc_inode,
	.destroy_inode = bdev_destroy_inode,
	.drop_inode = generic_delete_inode,
	.clear_inode = bdev_clear_inode,
};

static struct super_block *bd_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return get_sb_pseudo(fs_type, "bdev:", &bdev_sops, 0x62646576);
}

static struct file_system_type bd_type = {
	.name		= "bdev",
	.get_sb		= bd_get_sb,
	.kill_sb	= kill_anon_super,
};

static struct vfsmount *bd_mnt;
struct super_block *blockdev_superblock;

void __init bdev_cache_init(void)
{
	int err;
	bdev_cachep = kmem_cache_create("bdev_cache", sizeof(struct bdev_inode),
			0, SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT|SLAB_PANIC,
			init_once, NULL);
	err = register_filesystem(&bd_type);
	if (err)
		panic("Cannot register bdev pseudo-fs");
	bd_mnt = kern_mount(&bd_type);
	err = PTR_ERR(bd_mnt);
	if (IS_ERR(bd_mnt))
		panic("Cannot create bdev pseudo-fs");
	blockdev_superblock = bd_mnt->mnt_sb;	/* For writeback */
}

void bd_forget(struct inode *inode)
{
	spin_lock(&bdev_lock);
	if (inode->i_bdev)
		__bd_forget(inode);
	spin_unlock(&bdev_lock);
}









static int blkdev_open(struct inode * inode, struct file * filp)
{
	panic("in blkdev_open function");
	return 0;
}

int blkdev_put(struct block_device *bdev)
{
	return 0;
}

EXPORT_SYMBOL(blkdev_put);

static int blkdev_close(struct inode * inode, struct file * filp)
{
	return 0;
}

static ssize_t blkdev_file_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t blkdev_file_aio_write(struct kiocb *iocb, const char __user *buf,
				   size_t count, loff_t pos)
{
	return 0;
}

static int block_ioctl(struct inode *inode, struct file *file, unsigned cmd,
			unsigned long arg)
{
	return 0;
}

struct file_operations def_blk_fops = {
	.open		= blkdev_open,
	.release	= blkdev_close,
	.llseek		= block_llseek,
	.read		= generic_file_read,
	.write		= blkdev_file_write,
  	.aio_read	= generic_file_aio_read,
  	.aio_write	= blkdev_file_aio_write, 
	.mmap		= generic_file_mmap,
	.fsync		= block_fsync,
	.ioctl		= block_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_blkdev_ioctl,
#endif
	.readv		= generic_file_readv,
	.writev		= generic_file_write_nolock,
	.sendfile	= generic_file_sendfile,
};