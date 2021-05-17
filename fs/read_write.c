#include <linux/slab.h> 
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/smp_lock.h>
#include <linux/dnotify.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/syscalls.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

loff_t generic_file_llseek(struct file *file, loff_t offset, int origin)
{
    return 0;
}