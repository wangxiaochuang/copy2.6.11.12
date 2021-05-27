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

static inline int __prepare_ICR (unsigned int shortcut, int vector)
{
	return APIC_DM_FIXED | shortcut | vector | APIC_DEST_LOGICAL;
}

static inline int __prepare_ICR2 (unsigned int mask)
{
	return SET_APIC_DEST_FIELD(mask);
}

void __send_IPI_shortcut(unsigned int shortcut, int vector)
{
	/*
	 * Subtle. In the case of the 'never do double writes' workaround
	 * we have to lock out interrupts to be safe.  As we don't care
	 * of the value read we use an atomic rmw access to avoid costly
	 * cli/sti.  Otherwise we use an even cheaper single atomic write
	 * to the APIC.
	 */
	unsigned int cfg;

	/*
	 * Wait for idle.
	 */
	apic_wait_icr_idle();

	/*
	 * No need to touch the target chip field
	 */
	cfg = __prepare_ICR(shortcut, vector);

	/*
	 * Send the IPI. The write to APIC_ICR fires this off.
	 */
	apic_write_around(APIC_ICR, cfg);
}

void fastcall send_IPI_self(int vector)
{
	__send_IPI_shortcut(APIC_DEST_SELF, vector);
}

/*
 * This is only used on smaller machines.
 */
void send_IPI_mask_bitmask(cpumask_t cpumask, int vector)
{
	panic("in send_IPI_mask_bitmask function");
}

#include <mach_ipi.h>

static cpumask_t flush_cpumask;
static struct mm_struct * flush_mm;
static unsigned long flush_va;
static DEFINE_SPINLOCK(tlbstate_lock);
#define FLUSH_ALL	0xffffffff

static inline void leave_mm(unsigned long cpu) {
    if (per_cpu(cpu_tlbstate, cpu).state == TLBSTATE_OK)
		BUG();
	cpu_clear(cpu, per_cpu(cpu_tlbstate, cpu).active_mm->cpu_vm_mask);
	load_cr3(swapper_pg_dir);
}

/*
 * TLB flush IPI:
 *
 * 1) Flush the tlb entries if the cpu uses the mm that's being flushed.
 * 2) Leave the mm if we are in the lazy tlb mode.
 */

fastcall void smp_invalidate_interrupt(struct pt_regs *regs)
{
}

static void flush_tlb_others(cpumask_t cpumask, struct mm_struct *mm,
						unsigned long va)
{
	cpumask_t tmp;
	/*
	 * A couple of (to be removed) sanity checks:
	 *
	 * - we do not send IPIs to not-yet booted CPUs.
	 * - current CPU must not be in mask
	 * - mask must exist :)
	 */
	BUG_ON(cpus_empty(cpumask));

	cpus_and(tmp, cpumask, cpu_online_map);
	BUG_ON(!cpus_equal(cpumask, tmp));
	BUG_ON(cpu_isset(smp_processor_id(), cpumask));
	BUG_ON(!mm);

	/*
	 * i'm not happy about this global shared spinlock in the
	 * MM hot path, but we'll see how contended it is.
	 * Temporarily this turns IRQs off, so that lockups are
	 * detected by the NMI watchdog.
	 */
	spin_lock(&tlbstate_lock);
	
	flush_mm = mm;
	flush_va = va;
#if NR_CPUS <= BITS_PER_LONG
	atomic_set_mask(cpumask, &flush_cpumask);
#else
	{
		int k;
		unsigned long *flush_mask = (unsigned long *)&flush_cpumask;
		unsigned long *cpu_mask = (unsigned long *)&cpumask;
		for (k = 0; k < BITS_TO_LONGS(NR_CPUS); ++k)
			atomic_set_mask(cpu_mask[k], &flush_mask[k]);
	}
#endif
	/*
	 * We have to send the IPI only to
	 * CPUs affected.
	 */
	send_IPI_mask(cpumask, INVALIDATE_TLB_VECTOR);

	while (!cpus_empty(flush_cpumask))
		/* nothing. lockup detection does not belong here */
		mb();

	flush_mm = NULL;
	flush_va = 0;
	spin_unlock(&tlbstate_lock);
}

void flush_tlb_current_task(void)
{
	struct mm_struct *mm = current->mm;
	cpumask_t cpu_mask;

	preempt_disable();
	cpu_mask = mm->cpu_vm_mask;
	cpu_clear(smp_processor_id(), cpu_mask);

	local_flush_tlb();
	if (!cpus_empty(cpu_mask))
		flush_tlb_others(cpu_mask, mm, FLUSH_ALL);
	preempt_enable();
}

void flush_tlb_mm (struct mm_struct * mm)
{
	cpumask_t cpu_mask;

	preempt_disable();
	cpu_mask = mm->cpu_vm_mask;
	cpu_clear(smp_processor_id(), cpu_mask);

	if (current->active_mm == mm) {
		if (current->mm)
			local_flush_tlb();
		else
			leave_mm(smp_processor_id());
	}
	if (!cpus_empty(cpu_mask))
		flush_tlb_others(cpu_mask, mm, FLUSH_ALL);

	preempt_enable();
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

void smp_send_reschedule(int cpu)
{
	send_IPI_mask(cpumask_of_cpu(cpu), RESCHEDULE_VECTOR);
}

static DEFINE_SPINLOCK(call_lock);

struct call_data_struct {
	void (*func) (void *info);
	void *info;
	atomic_t started;
	atomic_t finished;
	int wait;
};

static struct call_data_struct * call_data;

int smp_call_function (void (*func) (void *info), void *info, int nonatomic,
			int wait) {
    struct call_data_struct data;
	int cpus = num_online_cpus()-1;

	if (!cpus)
		return 0;
	
	/* Can deadlock when called with interrupts disabled */
	WARN_ON(irqs_disabled());

	data.func = func;
	data.info = info;
	atomic_set(&data.started, 0);
	data.wait = wait;
	if (wait)
		atomic_set(&data.finished, 0);

	spin_lock(&call_lock);
	call_data = &data;
	mb();
	
	/* Send a message to all other CPUs and wait for them to respond */
	send_IPI_allbutself(CALL_FUNCTION_VECTOR);

	/* Wait for response */
	while (atomic_read(&data.started) != cpus)
		cpu_relax();

	if (wait)
		while (atomic_read(&data.finished) != cpus)
			cpu_relax();
	spin_unlock(&call_lock);

	return 0;
}

/*
 * Reschedule call back. Nothing to do,
 * all the work is done automatically when
 * we return from the interrupt.
 */
fastcall void smp_reschedule_interrupt(struct pt_regs *regs)
{
	ack_APIC_irq();
}

fastcall void smp_call_function_interrupt(struct pt_regs *regs)
{
	void (*func) (void *info) = call_data->func;
	void *info = call_data->info;
	int wait = call_data->wait;

	ack_APIC_irq();
	/*
	 * Notify initiating CPU that I've grabbed the data and am
	 * about to execute the function
	 */
	mb();
	atomic_inc(&call_data->started);
	/*
	 * At this point the info structure may be out of scope unless wait==1
	 */
	irq_enter();
	(*func)(info);
	irq_exit();

	if (wait) {
		mb();
		atomic_inc(&call_data->finished);
	}
}