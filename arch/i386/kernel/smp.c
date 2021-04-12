#include <linux/init.h>

#include <linux/mm.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/kernel_stat.h>
#include <linux/mc146818rtc.h>
#include <linux/cache.h>
#include <linux/interrupt.h>

#include <asm/mtrr.h>
#include <asm/tlbflush.h>
#include <mach_apic.h>

DEFINE_PER_CPU(struct tlb_state, cpu_tlbstate) ____cacheline_aligned = { &init_mm, 0, };

static inline void leave_mm(unsigned long cpu) {
    if (per_cpu(cpu_tlbstate, cpu).state == TLBSTATE_OK)
		BUG();
	cpu_clear(cpu, per_cpu(cpu_tlbstate, cpu).active_mm->cpu_vm_mask);
	load_cr3(swapper_pg_dir);
}

static void do_flush_tlb_all(void* info) {
	unsigned long cpu = smp_processor_id();

	__flush_tlb_all();
	if (per_cpu(cpu_tlbstate, cpu).state == TLBSTATE_LAZY)
		leave_mm(cpu);
}

void flush_tlb_all(void) {
    on_each_cpu(do_flush_tlb_all, NULL, 1, 1);
}

int smp_call_function (void (*func) (void *info), void *info, int nonatomic,
			int wait) {
    return 0;
}