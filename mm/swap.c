#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm_inline.h>
#include <linux/buffer_head.h>	/* for try_to_release_page() */
#include <linux/module.h>
#include <linux/percpu_counter.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/init.h>

void __pagevec_release(struct pagevec *pvec)
{
	panic("in __pagevec_release function");
}

unsigned pagevec_lookup_tag(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t *index, int tag, unsigned nr_pages)
{
	pvec->nr = find_get_pages_tag(mapping, index, tag,
					nr_pages, pvec->pages);
	return pagevec_count(pvec);
}

#ifdef CONFIG_SMP

#define ACCT_THRESHOLD	max(16, NR_CPUS * 2)

static DEFINE_PER_CPU(long, committed_space) = 0;

void vm_acct_memory(long pages)
{
	long *local;

	preempt_disable();
	local = &__get_cpu_var(committed_space);
	*local += pages;
	if (*local > ACCT_THRESHOLD || *local < -ACCT_THRESHOLD) {
		atomic_add(*local, &vm_committed_space);
		*local = 0;
	}
	preempt_enable();
}
EXPORT_SYMBOL(vm_acct_memory);

#endif /* CONFIG_SMP */