#include <linux/config.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/io.h>

struct resource ioport_resource = {
	.name	= "PCI IO",
	.start	= 0x0000,
	.end	= IO_SPACE_LIMIT,
	.flags	= IORESOURCE_IO,
};

struct resource iomem_resource = {
	.name	= "PCI mem",
	.start	= 0UL,
	.end	= ~0UL,
	.flags	= IORESOURCE_MEM,
};

EXPORT_SYMBOL(iomem_resource);

static DEFINE_RWLOCK(resource_lock);

/* Return the conflict entry if you can't request it */
static struct resource * __request_resource(struct resource *root, struct resource *new)
{
    unsigned long start = new->start;
    unsigned long end = new->end;
    struct resource *tmp, **p;

    if (end < start)
        return root;
    if (start < root->start)
        return root;
    if (end > root->end)
        return root;
    p = &root->child;
    for (;;) {
        tmp = *p;
        if (!tmp || tmp->start > end) {
            new->sibling = tmp;
            *p = new;
            new->parent = root;
            return NULL;
        }
        p = &tmp->sibling;
        if (tmp->end < start)
            continue;
        return tmp;
    }
}

int request_resource(struct resource *root, struct resource *new) {
	struct resource *conflict;

	write_lock(&resource_lock);
	conflict = __request_resource(root, new);
	write_unlock(&resource_lock);
	return conflict ? -EBUSY : 0;
}

EXPORT_SYMBOL(request_resource);