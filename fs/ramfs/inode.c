#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/smp_lock.h>
#include <linux/backing-dev.h>
#include <linux/ramfs.h>

#include <asm/uaccess.h>

int __init init_rootfs(void)
{
    panic("in init rootfs");
    return 0;
}