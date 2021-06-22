#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/errno.h>
#include <linux/tty.h>
#include <linux/devfs_fs_kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/vt_kern.h>
#include <linux/selection.h>
#include <linux/kbd_kern.h>
#include <linux/console.h>
#include <linux/smp_lock.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <asm/byteorder.h>
#include <asm/unaligned.h>

#undef attr
#undef org
#undef addr
#define HEADER_SIZE	4

static int
vcs_size(struct inode *inode)
{
	panic("in vcs_size");
	return 0;
}

static loff_t vcs_lseek(struct file *file, loff_t offset, int orig)
{
	panic("in vcs_lseek");
	return 0;
}

static ssize_t
vcs_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	panic("in vcs_read");
	return 0;
}

static ssize_t
vcs_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	panic("in vcs_write");
	return 0;
}

static int
vcs_open(struct inode *inode, struct file *filp)
{
	panic("in vcs_open");
	return 0;
}

static struct file_operations vcs_fops = {
	.llseek		= vcs_lseek,
	.read		= vcs_read,
	.write		= vcs_write,
	.open		= vcs_open,
};

static struct class_simple *vc_class;

void vcs_make_devfs(struct tty_struct *tty)
{
	panic("in vcs_make_devfs");
}

void vcs_remove_devfs(struct tty_struct *tty)
{
	panic("in vcs_remove_devfs");
}

int __init vcs_init(void)
{
	if (register_chrdev(VCS_MAJOR, "vcs", &vcs_fops))
		panic("unable to get major %d for vcs device", VCS_MAJOR);
	vc_class = class_simple_create(THIS_MODULE, "vc");

	devfs_mk_cdev(MKDEV(VCS_MAJOR, 0), S_IFCHR|S_IRUSR|S_IWUSR, "vcc/0");
	devfs_mk_cdev(MKDEV(VCS_MAJOR, 128), S_IFCHR|S_IRUSR|S_IWUSR, "vcc/a0");
	class_simple_device_add(vc_class, MKDEV(VCS_MAJOR, 0), NULL, "vcs");
	class_simple_device_add(vc_class, MKDEV(VCS_MAJOR, 128), NULL, "vcsa");
	return 0;
}