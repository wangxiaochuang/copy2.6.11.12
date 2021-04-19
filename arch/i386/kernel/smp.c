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

/*
 * Reschedule call back. Nothing to do,
 * all the work is done automatically when
 * we return from the interrupt.
 */
fastcall void smp_reschedule_interrupt(struct pt_regs *regs)
{
}

fastcall void smp_call_function_interrupt(struct pt_regs *regs)
{
}