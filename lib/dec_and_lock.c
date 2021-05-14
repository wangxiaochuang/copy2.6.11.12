#include <linux/module.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

#ifndef ATOMIC_DEC_AND_LOCK
int _atomic_dec_and_lock(atomic_t *atomic, spinlock_t *lock)
{
	spin_lock(lock);
	if (atomic_dec_and_test(atomic))
		return 1;
	spin_unlock(lock);
	return 0;
}

EXPORT_SYMBOL(_atomic_dec_and_lock);
#endif