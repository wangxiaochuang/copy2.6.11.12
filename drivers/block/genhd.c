#include <linux/config.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/kobj_map.h>

#define MAX_PROBE_HASH 255	/* random */

static struct subsystem block_subsys;

static DECLARE_MUTEX(block_subsys_sem);

static struct blk_major_name {
	struct blk_major_name *next;
	int major;
	char name[16];
} *major_names[MAX_PROBE_HASH];

static inline int major_to_index(int major)
{
	return major % MAX_PROBE_HASH;
}

#ifdef CONFIG_PROC_FS
int get_blkdev_list(char *p)
{
	panic("in get_blkdev_list");
	return 0;
}
#endif

int register_blkdev(unsigned int major, const char *name)
{
	struct blk_major_name **n, *p;
	int index, ret = 0;

	down(&block_subsys_sem);

	if (major == 0) {
		panic("in register_blkdev");
	}

	p = kmalloc(sizeof(struct blk_major_name), GFP_KERNEL);
	if (p == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	p->major = major;
	strlcpy(p->name, name, sizeof(p->name));
	p->next = NULL;
	index = major_to_index(major);

	for (n = &major_names[index]; *n; n = &(*n)->next) {
		if ((*n)->major == major)
			break;
	}
	if (!*n)
		*n = p;
	else
		ret = -EBUSY;

	if (ret < 0) {
		printk("register_blkdev: cannot get major %d for %s\n",
		       major, name);
		kfree(p);
	}

out:
	up(&block_subsys_sem);
	return ret;
}

EXPORT_SYMBOL(register_blkdev);

int unregister_blkdev(unsigned int major, const char *name)
{
	panic("in unregister_blkdev");
	return 0;
}

EXPORT_SYMBOL(unregister_blkdev);

static struct kobj_map *bdev_map;

void blk_register_region(dev_t dev, unsigned long range, struct module *module,
			 struct kobject *(*probe)(dev_t, int *, void *),
			 int (*lock)(dev_t, void *), void *data)
{
	kobj_map(bdev_map, dev, range, module, probe, lock, data);
}

EXPORT_SYMBOL(blk_register_region);

void blk_unregister_region(dev_t dev, unsigned long range)
{
	kobj_unmap(bdev_map, dev, range);
}

EXPORT_SYMBOL(blk_unregister_region);

static struct kobject *exact_match(dev_t dev, int *part, void *data)
{
	struct gendisk *p = data;
	return &p->kobj;
}

static int exact_lock(dev_t dev, void *data)
{
	struct gendisk *p = data;

	if (!get_disk(p))
		return -1;
	return 0;
}

void add_disk(struct gendisk *disk)
{
	disk->flags |= GENHD_FL_UP;
	blk_register_region(MKDEV(disk->major, disk->first_minor),
			    disk->minors, NULL, exact_match, exact_lock, disk);
	register_disk(disk);
	blk_register_queue(disk);
}

EXPORT_SYMBOL(add_disk);

#define to_disk(obj) container_of(obj,struct gendisk,kobj)

struct gendisk *get_gendisk(dev_t dev, int *part)
{
	struct kobject *kobj = kobj_lookup(bdev_map, dev, part);
	return  kobj ? to_disk(kobj) : NULL;
}


extern int blk_dev_init(void);

static struct kobject *base_probe(dev_t dev, int *part, void *data)
{
	if (request_module("block-major-%d-%d", MAJOR(dev), MINOR(dev)) > 0)
		/* Make old-style 2.4 aliases work */
		request_module("block-major-%d", MAJOR(dev));
	return NULL;
}

static int __init genhd_device_init(void)
{
	bdev_map = kobj_map_init(base_probe, &block_subsys);
	blk_dev_init();
	subsystem_register(&block_subsys);
	return 0;
}

subsys_initcall(genhd_device_init);


static ssize_t disk_attr_show(struct kobject *kobj, struct attribute *attr,
			      char *page)
{
	struct gendisk *disk = to_disk(kobj);
	struct disk_attribute *disk_attr =
		container_of(attr, struct disk_attribute, attr);
	ssize_t ret = 0;

	if (disk_attr->show)
		ret = disk_attr->show(disk,page);
	return ret;
}

static struct sysfs_ops disk_sysfs_ops = {
	.show	= &disk_attr_show,
};

static ssize_t disk_dev_read(struct gendisk * disk, char *page)
{
	dev_t base = MKDEV(disk->major, disk->first_minor); 
	return print_dev_t(page, base);
}
static ssize_t disk_range_read(struct gendisk * disk, char *page)
{
	return sprintf(page, "%d\n", disk->minors);
}
static ssize_t disk_removable_read(struct gendisk * disk, char *page)
{
	return sprintf(page, "%d\n",
		       (disk->flags & GENHD_FL_REMOVABLE ? 1 : 0));

}
static ssize_t disk_size_read(struct gendisk * disk, char *page)
{
	return sprintf(page, "%llu\n", (unsigned long long)get_capacity(disk));
}

static ssize_t disk_stats_read(struct gendisk * disk, char *page)
{
	preempt_disable();
	disk_round_stats(disk);
	preempt_enable();
	return sprintf(page,
		"%8u %8u %8llu %8u "
		"%8u %8u %8llu %8u "
		"%8u %8u %8u"
		"\n",
		disk_stat_read(disk, reads), disk_stat_read(disk, read_merges),
		(unsigned long long)disk_stat_read(disk, read_sectors),
		jiffies_to_msecs(disk_stat_read(disk, read_ticks)),
		disk_stat_read(disk, writes), 
		disk_stat_read(disk, write_merges),
		(unsigned long long)disk_stat_read(disk, write_sectors),
		jiffies_to_msecs(disk_stat_read(disk, write_ticks)),
		disk->in_flight,
		jiffies_to_msecs(disk_stat_read(disk, io_ticks)),
		jiffies_to_msecs(disk_stat_read(disk, time_in_queue)));
}
static struct disk_attribute disk_attr_dev = {
	.attr = {.name = "dev", .mode = S_IRUGO },
	.show	= disk_dev_read
};
static struct disk_attribute disk_attr_range = {
	.attr = {.name = "range", .mode = S_IRUGO },
	.show	= disk_range_read
};
static struct disk_attribute disk_attr_removable = {
	.attr = {.name = "removable", .mode = S_IRUGO },
	.show	= disk_removable_read
};
static struct disk_attribute disk_attr_size = {
	.attr = {.name = "size", .mode = S_IRUGO },
	.show	= disk_size_read
};
static struct disk_attribute disk_attr_stat = {
	.attr = {.name = "stat", .mode = S_IRUGO },
	.show	= disk_stats_read
};

static struct attribute * default_attrs[] = {
	&disk_attr_dev.attr,
	&disk_attr_range.attr,
	&disk_attr_removable.attr,
	&disk_attr_size.attr,
	&disk_attr_stat.attr,
	NULL,
};

static void disk_release(struct kobject * kobj)
{
	panic("in disk_release");
}

static struct kobj_type ktype_block = {
	.release	= disk_release,
	.sysfs_ops	= &disk_sysfs_ops,
	.default_attrs	= default_attrs,
};

extern struct kobj_type ktype_part;

static int block_hotplug_filter(struct kset *kset, struct kobject *kobj)
{
	struct kobj_type *ktype = get_ktype(kobj);

	return ((ktype == &ktype_block) || (ktype == &ktype_part));
}

static int block_hotplug(struct kset *kset, struct kobject *kobj, char **envp,
			 int num_envp, char *buffer, int buffer_size)
{
	struct device *dev = NULL;
	struct kobj_type *ktype = get_ktype(kobj);
	int length = 0;
	int i = 0;

	if (ktype == &ktype_block) {
		struct gendisk *disk = container_of(kobj, struct gendisk, kobj);
		dev = disk->driverfs_dev;
	} else if (ktype == &ktype_part) {
		struct gendisk *disk = container_of(kobj->parent, struct gendisk, kobj);
		dev = disk->driverfs_dev;
	}

	if (dev) {
		char *path = kobject_get_path(&dev->kobj, GFP_KERNEL);
		add_hotplug_env_var(envp, num_envp, &i, buffer, buffer_size,
				    &length, "PHYSDEVPATH=%s", path);
		kfree(path);
		if (dev->bus)
			add_hotplug_env_var(envp, num_envp, &i,
					    buffer, buffer_size, &length,
					    "PHYSDEVBUS=%s", dev->bus->name);
		if (dev->driver)
			add_hotplug_env_var(envp, num_envp, &i,
					    buffer, buffer_size, &length,
					    "PHYSDEVDRIVER=%s", dev->driver->name);
		envp[i] = NULL;
	}
	return 0;
}

static struct kset_hotplug_ops block_hotplug_ops = {
	.filter		= block_hotplug_filter,
	.hotplug	= block_hotplug,
};

static decl_subsys(block, &ktype_block, &block_hotplug_ops);


static void *diskstats_start(struct seq_file *part, loff_t *pos)
{
	panic("in diskstats_start");
	return NULL;
}

static void *diskstats_next(struct seq_file *part, void *v, loff_t *pos)
{
	panic("in diskstats_next");
	return NULL;
}

static void diskstats_stop(struct seq_file *part, void *v)
{
	up(&block_subsys_sem);
}

static int diskstats_show(struct seq_file *s, void *v)
{
	panic("in diskstats_show");
	return 0;
}

struct seq_operations diskstats_op = {
	.start	= diskstats_start,
	.next	= diskstats_next,
	.stop	= diskstats_stop,
	.show	= diskstats_show
};

struct gendisk *alloc_disk(int minors)
{
	struct gendisk *disk = kmalloc(sizeof(struct gendisk), GFP_KERNEL);
	if (disk) {
		memset(disk, 0, sizeof(struct gendisk));
		if (!init_disk_stats(disk)) {
			kfree(disk);
			return NULL;
		}
		if (minors > 1) {
			int size = (minors - 1) * sizeof(struct hd_struct *);
			disk->part = kmalloc(size, GFP_KERNEL);
			if (!disk->part) {
				kfree(disk);
				return NULL;
			}
			memset(disk->part, 0, size);
		}
		disk->minors = minors;
		kobj_set_kset_s(disk, block_subsys);
		kobject_init(&disk->kobj);
		rand_initialize_disk(disk);
	}
	return disk;
}

EXPORT_SYMBOL(alloc_disk);

struct kobject *get_disk(struct gendisk *disk)
{
	struct module *owner;
	struct kobject *kobj;

	if (!disk->fops)
		return NULL;
	owner = disk->fops->owner;
	if (owner && !try_module_get(owner))
		return NULL;
	kobj = kobject_get(&disk->kobj);
	if (kobj == NULL) {
		module_put(owner);
		return NULL;
	}
	return kobj;

}

EXPORT_SYMBOL(get_disk);

void put_disk(struct gendisk *disk)
{
	if (disk)
		kobject_put(&disk->kobj);
}

EXPORT_SYMBOL(put_disk);

int bdev_read_only(struct block_device *bdev)
{
	if (!bdev)
		return 0;
	else if (bdev->bd_contains != bdev)
		return bdev->bd_part->policy;
	else
		return bdev->bd_disk->policy;
}

EXPORT_SYMBOL(bdev_read_only);


int invalidate_partition(struct gendisk *disk, int index)
{
	int res = 0;
	struct block_device *bdev = bdget_disk(disk, index);
	if (bdev) {
		res = __invalidate_device(bdev, 1);
		bdput(bdev);
	}
	return res;
}

EXPORT_SYMBOL(invalidate_partition);