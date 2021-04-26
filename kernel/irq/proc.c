#include <linux/irq.h>
#include <linux/proc_fs.h>
#include <linux/interrupt.h>

static struct proc_dir_entry *root_irq_dir, *irq_dir[NR_IRQS];

#undef MAX_NAMELEN

#define MAX_NAMELEN 10

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

    printk("##### in register_handler_proc");
}

void register_irq_proc(unsigned int irq) {
    char name [MAX_NAMELEN];

    if (!root_irq_dir ||
        (irq_desc[irq].handler == &no_irq_type) ||
            irq_dir[irq])
        return;

    memset(name, 0, MAX_NAMELEN);
	sprintf(name, "%d", irq);

    printk("##### in register_irq_proc\n");
}