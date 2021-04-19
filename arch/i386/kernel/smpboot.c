#include <linux/module.h>
#include <linux/config.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/smp_lock.h>
#include <linux/irq.h>
#include <linux/bootmem.h>

#include <linux/delay.h>
#include <linux/mc146818rtc.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/arch_hooks.h>

#include <mach_apic.h>
#include <mach_wakecpu.h>
#include <smpboot_hooks.h>

/* bitmap of online cpus */
cpumask_t cpu_online_map;

cpumask_t cpu_callout_map;

/* Per CPU bogomips and other parameters */
struct cpuinfo_x86 cpu_data[NR_CPUS] __cacheline_aligned;

extern unsigned char trampoline_data [];
extern unsigned char trampoline_end  [];
static unsigned char *trampoline_base;
static int trampoline_exec;

/*
 * We are called very early to get the low memory for the
 * SMP bootup trampoline page.
 */
void __init smp_alloc_memory(void) {
	trampoline_base = (void *) alloc_bootmem_low_pages(PAGE_SIZE);

	if (__pa(trampoline_base) >= 0x9F000)
		BUG();

	trampoline_exec = set_kernel_exec((unsigned long) trampoline_base, 1);
}

void __init initialize_secondary(void) {
    asm volatile(
		"movl %0,%%esp\n\t"
		"jmp *%1"
		:
		:"r" (current->thread.esp),"r" (current->thread.eip));
}


void __devinit smp_prepare_boot_cpu(void) {
	cpu_set(smp_processor_id(), cpu_online_map);
	cpu_set(smp_processor_id(), cpu_callout_map);
}

void __init smp_intr_init(void) {
	/*
	 * IRQ0 must be given a fixed assignment and initialized,
	 * because it's used before the IO-APIC is set up.
	 */
	set_intr_gate(FIRST_DEVICE_VECTOR, interrupt[0]);

	/*
	 * The reschedule interrupt is a CPU-to-CPU reschedule-helper
	 * IPI, driven by wakeup.
	 */
	set_intr_gate(RESCHEDULE_VECTOR, reschedule_interrupt);

	/* IPI for invalidation */
	set_intr_gate(INVALIDATE_TLB_VECTOR, invalidate_interrupt);

	/* IPI for generic function call */
	set_intr_gate(CALL_FUNCTION_VECTOR, call_function_interrupt);
}