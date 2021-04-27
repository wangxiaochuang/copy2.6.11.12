#include <linux/config.h>
#include <linux/init.h>

#include <linux/mm.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/bootmem.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/mc146818rtc.h>
#include <linux/kernel_stat.h>
#include <linux/sysdev.h>

#include <asm/atomic.h>
#include <asm/smp.h>
#include <asm/mtrr.h>
#include <asm/mpspec.h>
#include <asm/desc.h>
#include <asm/arch_hooks.h>
#include <asm/hpet.h>

#include <mach_apic.h>

#include "io_ports.h"

/*
 * Debug level
 */
int apic_verbosity;

/*
 * 'what should we do if we get a hw irq event on an illegal vector'.
 * each architecture has to answer this themselves.
 */
void ack_bad_irq(unsigned int irq)
{
	printk("unexpected IRQ trap at vector %02x\n", irq);
	/*
	 * Currently unexpected vectors happen only on SMP and APIC.
	 * We _must_ ack these because every local APIC has only N
	 * irq slots per priority level, and a 'hanging, unacked' IRQ
	 * holds up an irq slot - in excessive cases (when multiple
	 * unexpected vectors occur) that might lock up the APIC
	 * completely.
	 */
	ack_APIC_irq();
}

void __init apic_intr_init(void)
{
#ifdef CONFIG_SMP
	smp_intr_init();
#endif
	/* self generated IPI for local APIC timer */
	set_intr_gate(LOCAL_TIMER_VECTOR, apic_timer_interrupt);

	/* IPI vectors for APIC spurious and error interrupts */
	set_intr_gate(SPURIOUS_APIC_VECTOR, spurious_interrupt);
	set_intr_gate(ERROR_APIC_VECTOR, error_interrupt);

	/* thermal monitor LVT interrupt */
#ifdef CONFIG_X86_MCE_P4THERMAL
#error "CONFIG_X86_MCE_P4THERMAL"
#endif
}

/* Using APIC to generate smp_local_timer_interrupt? */
int using_apic_timer = 0;

static DEFINE_PER_CPU(int, prof_multiplier) = 1;
static DEFINE_PER_CPU(int, prof_old_multiplier) = 1;
static DEFINE_PER_CPU(int, prof_counter) = 1;

int get_physical_broadcast(void)
{
	unsigned int lvr, version;
	lvr = apic_read(APIC_LVR);
	version = GET_APIC_VERSION(lvr);
	if (!APIC_INTEGRATED(version) || version >= 0x14)
		return 0xff;
	else
		return 0xf;
}

int get_maxlvt(void)
{
	unsigned int v, ver, maxlvt;

	v = apic_read(APIC_LVR);
	ver = GET_APIC_VERSION(v);
	/* 82489DXs do not report # of LVT entries. */
	maxlvt = APIC_INTEGRATED(ver) ? GET_APIC_MAXLVT(v) : 2;
	return maxlvt;
}

void clear_local_APIC(void) {
    int maxlvt;
	unsigned long v;

	maxlvt = get_maxlvt();

	/*
	 * Masking an LVT entry on a P6 can trigger a local APIC error
	 * if the vector is zero. Mask LVTERR first to prevent this.
	 */
	if (maxlvt >= 3) {
		v = ERROR_APIC_VECTOR; /* any non-zero vector will do */
		apic_write_around(APIC_LVTERR, v | APIC_LVT_MASKED);
	}
	/*
	 * Careful: we have to set masks only first to deassert
	 * any level-triggered sources.
	 */
	v = apic_read(APIC_LVTT);
	apic_write_around(APIC_LVTT, v | APIC_LVT_MASKED);
	v = apic_read(APIC_LVT0);
	apic_write_around(APIC_LVT0, v | APIC_LVT_MASKED);
	v = apic_read(APIC_LVT1);
	apic_write_around(APIC_LVT1, v | APIC_LVT_MASKED);
	if (maxlvt >= 4) {
		v = apic_read(APIC_LVTPC);
		apic_write_around(APIC_LVTPC, v | APIC_LVT_MASKED);
	}

/* lets not touch this if we didn't frob it */
#ifdef CONFIG_X86_MCE_P4THERMAL
	if (maxlvt >= 5) {
		v = apic_read(APIC_LVTTHMR);
		apic_write_around(APIC_LVTTHMR, v | APIC_LVT_MASKED);
	}
#endif
	/*
	 * Clean APIC state for other OSs:
	 */
	apic_write_around(APIC_LVTT, APIC_LVT_MASKED);
	apic_write_around(APIC_LVT0, APIC_LVT_MASKED);
	apic_write_around(APIC_LVT1, APIC_LVT_MASKED);
	if (maxlvt >= 3)
		apic_write_around(APIC_LVTERR, APIC_LVT_MASKED);
	if (maxlvt >= 4)
		apic_write_around(APIC_LVTPC, APIC_LVT_MASKED);

#ifdef CONFIG_X86_MCE_P4THERMAL
	if (maxlvt >= 5)
		apic_write_around(APIC_LVTTHMR, APIC_LVT_MASKED);
#endif
	v = GET_APIC_VERSION(apic_read(APIC_LVR));
	if (APIC_INTEGRATED(v)) {	/* !82489DX */
		if (maxlvt > 3)		/* Due to Pentium errata 3AP and 11AP. */
			apic_write(APIC_ESR, 0);
		apic_read(APIC_ESR);
	}
}

/*
 * An initial setup of the virtual wire mode.
 */
void __init init_bsp_APIC(void) {
    unsigned long value, ver;

	/*
	 * Don't do the setup now if we have a SMP BIOS as the
	 * through-I/O-APIC virtual wire mode might be active.
	 */
	if (smp_found_config || !cpu_has_apic)
		return;

	value = apic_read(APIC_LVR);
	ver = GET_APIC_VERSION(value);

	/*
	 * Do not trust the local APIC being empty at bootup.
	 */
	clear_local_APIC();

	/*
	 * Enable APIC.
	 */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_VECTOR_MASK;
	value |= APIC_SPIV_APIC_ENABLED;
	
	/* This bit is reserved on P4/Xeon and should be cleared */
	if ((boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) && (boot_cpu_data.x86 == 15))
		value &= ~APIC_SPIV_FOCUS_DISABLED;
	else
		value |= APIC_SPIV_FOCUS_DISABLED;
	value |= SPURIOUS_APIC_VECTOR;
	apic_write_around(APIC_SPIV, value);

	/*
	 * Set up the virtual wire mode.
	 */
	apic_write_around(APIC_LVT0, APIC_DM_EXTINT);
	value = APIC_DM_NMI;
	if (!APIC_INTEGRATED(ver))		/* 82489DX */
		value |= APIC_LVT_LEVEL_TRIGGER;
	apic_write_around(APIC_LVT1, value);
}

static int __init detect_init_APIC (void) {
    return 0;
}
void __init init_apic_mappings(void) {
    unsigned long apic_phys;

    if (!smp_found_config && detect_init_APIC()) {
        apic_phys = (unsigned long) alloc_bootmem_pages(PAGE_SIZE);
        apic_phys = __pa(apic_phys);
    } else 
        apic_phys = mp_lapic_addr;
    
    set_fixmap_nocache(FIX_APIC_BASE, apic_phys);
    printk(KERN_DEBUG "mapped APIC to %08lx (%08lx)\n", APIC_BASE,
	       apic_phys);
    
    if (boot_cpu_physical_apicid == -1U)
        boot_cpu_physical_apicid = GET_APIC_ID(apic_read(APIC_ID));
    
#ifdef CONFIG_X86_IO_APIC
    {
        unsigned long ioapic_phys, idx = FIX_IO_APIC_BASE_0;
        int i;

        for (i = 0; i < nr_ioapics; i++) {
            if (smp_found_config) {
                ioapic_phys = mp_ioapics[i].mpc_apicaddr;
                if (!ioapic_phys) {
					printk(KERN_ERR
					       "WARNING: bogus zero IO-APIC "
					       "address found in MPTABLE, "
					       "disabling IO/APIC support!\n");
					smp_found_config = 0;
					skip_ioapic_setup = 1;
					goto fake_ioapic_page;
				}
            } else {
fake_ioapic_page:
                ioapic_phys = (unsigned long)
                        alloc_bootmem_pages(PAGE_SIZE);
                ioapic_phys = __pa(ioapic_phys);
            }
            set_fixmap_nocache(idx, ioapic_phys);
            printk(KERN_DEBUG "mapped IOAPIC to %08lx (%08lx)\n",
			       __fix_to_virt(idx), ioapic_phys);
			idx++;
        }
    }
#endif
}

#define APIC_DIVISOR 16

void __setup_APIC_LVTT(unsigned int clocks)
{
	unsigned int lvtt_value, tmp_value, ver;

	ver = GET_APIC_VERSION(apic_read(APIC_LVR));
	lvtt_value = APIC_LVT_TIMER_PERIODIC | LOCAL_TIMER_VECTOR;
	if (!APIC_INTEGRATED(ver))
		lvtt_value |= SET_APIC_TIMER_BASE(APIC_TIMER_BASE_DIV);
	apic_write_around(APIC_LVTT, lvtt_value);

	/*
	 * Divide PICLK by 16
	 */
	tmp_value = apic_read(APIC_TDCR);
	apic_write_around(APIC_TDCR, (tmp_value
				& ~(APIC_TDR_DIV_1 | APIC_TDR_DIV_TMBASE))
				| APIC_TDR_DIV_16);

	apic_write_around(APIC_TMICT, clocks/APIC_DIVISOR);
}

static unsigned int calibration_result;

#undef APIC_DIVISOR

inline void smp_local_timer_interrupt(struct pt_regs * regs)
{
	int cpu = smp_processor_id();

	profile_tick(CPU_PROFILING, regs);
	if (--per_cpu(prof_counter, cpu) <= 0) {
		/*
		 * The multiplier may have changed since the last time we got
		 * to this point as a result of the user writing to
		 * /proc/profile. In this case we need to adjust the APIC
		 * timer accordingly.
		 *
		 * Interrupts are already masked off at this point.
		 */
		per_cpu(prof_counter, cpu) = per_cpu(prof_multiplier, cpu);
		if (per_cpu(prof_counter, cpu) !=
					per_cpu(prof_old_multiplier, cpu)) {
			__setup_APIC_LVTT(
					calibration_result/
					per_cpu(prof_counter, cpu));
			per_cpu(prof_old_multiplier, cpu) =
						per_cpu(prof_counter, cpu);
		}

#ifdef CONFIG_SMP
		update_process_times(user_mode(regs));
#endif
	}
}

/*
 * Local APIC timer interrupt. This is the most natural way for doing
 * local interrupts, but local timer interrupts can be emulated by
 * broadcast interrupts too. [in case the hw doesn't support APIC timers]
 *
 * [ if a single-CPU system runs an SMP kernel then we call the local
 *   interrupt as well. Thus we cannot inline the local irq ... ]
 */

fastcall void smp_apic_timer_interrupt(struct pt_regs *regs)
{
	panic(" arch i386 kernel apic.c 256\n");
}

/*
 * This interrupt should _never_ happen with our APIC/SMP architecture
 */
fastcall void smp_spurious_interrupt(struct pt_regs *regs)
{
}

/*
 * This interrupt should never happen with our APIC/SMP architecture
 */

fastcall void smp_error_interrupt(struct pt_regs *regs)
{
}
