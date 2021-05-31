#include <linux/irq.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/interrupt.h>

#include "internals.h"

#ifdef CONFIG_SMP

cpumask_t irq_affinity[NR_IRQS] = { [0 ... NR_IRQS-1] = CPU_MASK_ALL };

/**
 *	synchronize_irq - wait for pending IRQ handlers (on other CPUs)
 *
 *	This function waits for any pending IRQ handlers for this interrupt
 *	to complete before returning. If you use this function while
 *	holding a resource the IRQ handler may need you will deadlock.
 *
 *	This function may be called - with care - from IRQ context.
 */
void synchronize_irq(unsigned int irq)
{
	struct irq_desc *desc = irq_desc + irq;

	while (desc->status & IRQ_INPROGRESS)
		cpu_relax();
}

EXPORT_SYMBOL(synchronize_irq);

#endif

/**
 *	disable_irq_nosync - disable an irq without waiting
 *	@irq: Interrupt to disable
 *
 *	Disable the selected interrupt line.  Disables and Enables are
 *	nested.
 *	Unlike disable_irq(), this function does not ensure existing
 *	instances of the IRQ handler have completed before returning.
 *
 *	This function may be called from IRQ context.
 */
void disable_irq_nosync(unsigned int irq)
{
	irq_desc_t *desc = irq_desc + irq;
	unsigned long flags;

	spin_lock_irqsave(&desc->lock, flags);
	if (!desc->depth++) {
		desc->status |= IRQ_DISABLED;
		desc->handler->disable(irq);
	}
	spin_unlock_irqrestore(&desc->lock, flags);
}

EXPORT_SYMBOL(disable_irq_nosync);

/**
 *	disable_irq - disable an irq and wait for completion
 *	@irq: Interrupt to disable
 *
 *	Disable the selected interrupt line.  Enables and Disables are
 *	nested.
 *	This function waits for any pending IRQ handlers for this interrupt
 *	to complete before returning. If you use this function while
 *	holding a resource the IRQ handler may need you will deadlock.
 *
 *	This function may be called - with care - from IRQ context.
 */
void disable_irq(unsigned int irq)
{
	irq_desc_t *desc = irq_desc + irq;

	disable_irq_nosync(irq);
	if (desc->action)
		synchronize_irq(irq);
}

EXPORT_SYMBOL(disable_irq);

/**
 *	enable_irq - enable handling of an irq
 *	@irq: Interrupt to enable
 *
 *	Undoes the effect of one call to disable_irq().  If this
 *	matches the last disable, processing of interrupts on this
 *	IRQ line is re-enabled.
 *
 *	This function may be called from IRQ context.
 */
void enable_irq(unsigned int irq)
{
	irq_desc_t *desc = irq_desc + irq;
	unsigned long flags;

	spin_lock_irqsave(&desc->lock, flags);
	switch (desc->depth) {
	case 0:
		WARN_ON(1);
		break;
	case 1: {
		unsigned int status = desc->status & ~IRQ_DISABLED;

		desc->status = status;
		if ((status & (IRQ_PENDING | IRQ_REPLAY)) == IRQ_PENDING) {
			desc->status = status | IRQ_REPLAY;
			hw_resend_irq(desc->handler,irq);
		}
		desc->handler->enable(irq);
		/* fall-through */
	}
	default:
		desc->depth--;
	}
	spin_unlock_irqrestore(&desc->lock, flags);
}

EXPORT_SYMBOL(enable_irq);

/*
 * Internal function to register an irqaction - typically used to
 * allocate special interrupts that are part of the architecture.
 */
int setup_irq(unsigned int irq, struct irqaction * new)
{
	struct irq_desc *desc = irq_desc + irq;
	struct irqaction *old, **p;
	unsigned long flags;
	int shared = 0;

	if (desc->handler == &no_irq_type)
		return -ENOSYS;

	if (new->flags & SA_SAMPLE_RANDOM) {
		rand_initialize_irq(irq);
	}

	/*
	 * The following block of code has to be executed atomically
	 */
	spin_lock_irqsave(&desc->lock,flags);
	p = &desc->action;
	if ((old = *p) != NULL) {
		/* Can't share interrupts unless both agree to */
		if (!(old->flags & new->flags & SA_SHIRQ)) {
			spin_unlock_irqrestore(&desc->lock,flags);
			return -EBUSY;
		}

		do {
			p = &old->next;
			old = *p;
		} while (old);
		shared = 1;
	}

	*p = new;

	if (!shared) {
		desc->depth = 0;
		desc->status &= ~(IRQ_DISABLED | IRQ_AUTODETECT |
				  IRQ_WAITING | IRQ_INPROGRESS);
		if (desc->handler->startup)
			desc->handler->startup(irq);
		else
			desc->handler->enable(irq);
	}
	spin_unlock_irqrestore(&desc->lock,flags);

	new->irq = irq;
	register_irq_proc(irq);
	new->dir = NULL;
	register_handler_proc(irq, new);

	return 0;
}

void free_irq(unsigned int irq, void *dev_id)
{
	struct irq_desc *desc;
	struct irqaction **p;
	unsigned long flags;

	if (irq >= NR_IRQS)
		return;

	desc = irq_desc + irq;
	spin_lock_irqsave(&desc->lock,flags);
	p = &desc->action;
	for (;;) {
		struct irqaction * action = *p;

		if (action) {
			struct irqaction **pp = p;

			p = &action->next;
			if (action->dev_id != dev_id)
				continue;

			/* Found it - now remove it from the list of entries */
			*pp = action->next;
			if (!desc->action) {
				desc->status |= IRQ_DISABLED;
				if (desc->handler->shutdown)
					desc->handler->shutdown(irq);
				else
					desc->handler->disable(irq);
			}
			spin_unlock_irqrestore(&desc->lock,flags);
			unregister_handler_proc(irq, action);

			/* Make sure it's not being used on another CPU */
			synchronize_irq(irq);
			kfree(action);
			return;
		}
		printk(KERN_ERR "Trying to free free IRQ%d\n",irq);
		spin_unlock_irqrestore(&desc->lock,flags);
		return;
	}
}

EXPORT_SYMBOL(free_irq);