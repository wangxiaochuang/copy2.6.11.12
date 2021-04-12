#include <linux/config.h>
#include <linux/linkage.h>
#include <linux/preempt.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/module.h>

#ifndef CONFIG_PREEMPT

unsigned long __lockfunc _spin_lock_irqsave(spinlock_t *lock)
{
	unsigned long flags;

	local_irq_save(flags);
	preempt_disable();
	_raw_spin_lock_flags(lock, flags);
	return flags;
}
EXPORT_SYMBOL(_spin_lock_irqsave);

void __lockfunc _spin_lock(spinlock_t *lock)
{
	preempt_disable();
	_raw_spin_lock(lock);
}

EXPORT_SYMBOL(_spin_lock);

void __lockfunc _write_lock(rwlock_t *lock)
{
	preempt_disable();
	_raw_write_lock(lock);
}

EXPORT_SYMBOL(_write_lock);

#else /* CONFIG_PREEMPT: */

#endif

void __lockfunc _spin_unlock(spinlock_t *lock)
{
	_raw_spin_unlock(lock);
	preempt_enable();
}
EXPORT_SYMBOL(_spin_unlock);

void __lockfunc _write_unlock(rwlock_t *lock)
{
	_raw_write_unlock(lock);
	preempt_enable();
}
EXPORT_SYMBOL(_write_unlock);

void __lockfunc _spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
	_raw_spin_unlock(lock);
	local_irq_restore(flags);
	preempt_enable();
}
EXPORT_SYMBOL(_spin_unlock_irqrestore);