#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/init.h>

#include "sysfs.h"

struct vfsmount *sysfs_mount;
struct super_block * sysfs_sb = NULL;
kmem_cache_t *sysfs_dir_cachep;

static int sysfs_fill_super(struct super_block *sb, void *data, int silent)
{
    return 0;
}

static struct super_block *sysfs_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return get_sb_single(fs_type, flags, data, sysfs_fill_super);
}

static struct file_system_type sysfs_fs_type = {
	.name		= "sysfs",
	.get_sb		= sysfs_get_sb,
	.kill_sb	= kill_litter_super,
};

int __init sysfs_init(void)
{
    int err = -ENOMEM;

    sysfs_dir_cachep = kmem_cache_create("sysfs_dir_cache",
					      sizeof(struct sysfs_dirent),
					      0, 0, NULL, NULL);
    if (!sysfs_dir_cachep)
		goto out;
    
    err = register_filesystem(&sysfs_fs_type);
    if (!err) {
        sysfs_mount = kern_mount(&sysfs_fs_type);
        if (IS_ERR(sysfs_mount)) {
			printk(KERN_ERR "sysfs: could not mount!\n");
			err = PTR_ERR(sysfs_mount);
			sysfs_mount = NULL;
			goto out_err;
		}
    } else
        goto out_err;
out:
    return err;
out_err:
    kmem_cache_destroy(sysfs_dir_cachep);
    goto out;
}