#include <linux/irq.h>
#include <linux/proc_fs.h>
#include <linux/interrupt.h>

static struct proc_dir_entry *root_irq_dir, *irq_dir[NR_IRQS];

#ifdef CONFIG_SMP

/*
 * The /proc/irq/<irq>/smp_affinity values:
 */
static struct proc_dir_entry *smp_affinity_entry[NR_IRQS];

static int irq_affinity_read_proc(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	return 0;
}

int no_irq_affinity;
static int irq_affinity_write_proc(struct file *file, const char __user *buffer,
				   unsigned long count, void *data)
{
	return 0;
}

#endif

#define MAX_NAMELEN 128

static int name_unique(unsigned int irq, struct irqaction *new_action)
{
	struct irq_desc *desc = irq_desc + irq;
	struct irqaction *action;

	for (action = desc->action ; action; action = action->next)
		if ((action != new_action) && action->name &&
				!strcmp(new_action->name, action->name))
			return 0;
	return 1;
}

void register_handler_proc(unsigned int irq, struct irqaction *action)
{
	char name [MAX_NAMELEN];

	if (!irq_dir[irq] || action->dir || !action->name ||
					!name_unique(irq, action))
		return;

	memset(name, 0, MAX_NAMELEN);
	snprintf(name, MAX_NAMELEN, "%s", action->name);

	/* create /proc/irq/1234/handler/ */
	action->dir = proc_mkdir(name, irq_dir[irq]);
}

#undef MAX_NAMELEN

#define MAX_NAMELEN 10


void register_irq_proc(unsigned int irq) {
    char name [MAX_NAMELEN];

    if (!root_irq_dir ||
        (irq_desc[irq].handler == &no_irq_type) ||
            irq_dir[irq])
        return;

    memset(name, 0, MAX_NAMELEN);
	sprintf(name, "%d", irq);

	/* create /proc/irq/1234 */
	irq_dir[irq] = proc_mkdir(name, root_irq_dir);

#ifdef CONFIG_SMP
	{
		struct proc_dir_entry *entry;

		/* create /proc/irq/<irq>/smp_affinity */
		entry = create_proc_entry("smp_affinity", 0600, irq_dir[irq]);

		if (entry) {
			entry->nlink = 1;
			entry->data = (void *) (long) irq;
			entry->read_proc = irq_affinity_read_proc;
			entry->write_proc = irq_affinity_write_proc;
		}
		smp_affinity_entry[irq] = entry;
	}
#endif
}

#undef MAX_NAMELEN

void unregister_handler_proc(unsigned int irq, struct irqaction *action)
{
	if (action->dir)
		remove_proc_entry(action->dir->name, irq_dir[irq]);
}

void init_irq_proc(void)
{
	int i;

	root_irq_dir = proc_mkdir("irq", NULL);
	if (!root_irq_dir)
		return;

	for (i = 0; i < NR_IRQS; i++)
		register_irq_proc(i);
}