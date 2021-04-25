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