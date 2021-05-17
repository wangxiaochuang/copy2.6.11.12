#include <linux/config.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/user.h>
#include <linux/a.out.h>
#include <linux/elf.h>
#include <linux/elfcore.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include <asm/io.h>

static int open_kcore(struct inode * inode, struct file * filp)
{
	return 0;
}

static ssize_t read_kcore(struct file *, char __user *, size_t, loff_t *);

struct file_operations proc_kcore_operations = {
	.read		= read_kcore,
	.open		= open_kcore,
};

static struct kcore_list *kclist;
static DEFINE_RWLOCK(kclist_lock);

void
kclist_add(struct kcore_list *new, void *addr, size_t size)
{
    new->addr = (unsigned long)addr;
    new->size = size;

    write_lock(&kclist_lock);
    new->next = kclist;
    kclist = new;
    write_unlock(&kclist_lock);
}

/*****************************************************************************/
/*
 * read from the ELF header and then kernel memory
 */
static ssize_t
read_kcore(struct file *file, char __user *buffer, size_t buflen, loff_t *fpos)
{
    return 0;
}