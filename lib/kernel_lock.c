#include <linux/smp_lock.h>
#include <linux/module.h>
#include <linux/kallsyms.h>

#if defined(CONFIG_PREEMPT) && defined(__smp_processor_id) && \
		defined(CONFIG_DEBUG_PREEMPT)

#endif

#ifdef CONFIG_PREEMPT_BKL       // 没配置
    #error "CONFIG_PREEMPT_BKL"
#else

static __cacheline_aligned_in_smp DEFINE_SPINLOCK(kernel_flag);

int __lockfunc __reacquire_kernel_lock(void)
{
	while (!_raw_spin_trylock(&kernel_flag)) {
		if (test_thread_flag(TIF_NEED_RESCHED))
			return -EAGAIN;
		cpu_relax();
	}
	preempt_disable();
	return 0;
}

void __lockfunc __release_kernel_lock(void)
{
	_raw_spin_unlock(&kernel_flag);
	preempt_enable_no_resched();
}

#ifdef CONFIG_PREEMPT           // 没配置
    #error "CONFIG_PREEMPT"
#else
/*
 * Non-preemption case - just get the spinlock
 */
static inline void __lock_kernel(void) {
    _raw_spin_lock(&kernel_flag);
}
#endif /* CONFIG_PREEMPT */   

static inline void __unlock_kernel(void)
{
	_raw_spin_unlock(&kernel_flag);
	preempt_enable();
}

void __lockfunc lock_kernel(void) {
    int depth = current->lock_depth + 1;
    if (likely(!depth))
        __lock_kernel();
    current->lock_depth = depth;
}

void __lockfunc unlock_kernel(void) {
    BUG_ON(current->lock_depth < 0);
	if (likely(--current->lock_depth < 0))
		__unlock_kernel();
}
#endif /* CONFIG_PREEMPT_BKL */

EXPORT_SYMBOL(lock_kernel);
EXPORT_SYMBOL(unlock_kernel);