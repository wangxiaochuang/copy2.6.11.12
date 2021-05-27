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

static void apic_pm_activate(void);

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

void enable_NMI_through_LVT0 (void * dummy)
{
	unsigned int v, ver;

	ver = apic_read(APIC_LVR);
	ver = GET_APIC_VERSION(ver);
	v = APIC_DM_NMI;			/* unmask and set to NMI */
	if (!APIC_INTEGRATED(ver))		/* 82489DX */
		v |= APIC_LVT_LEVEL_TRIGGER;
	apic_write_around(APIC_LVT0, v);
}

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

void __init connect_bsp_APIC(void)
{
	if (pic_mode) {
		clear_local_APIC();
		/*
		 * PIC mode, enable APIC mode in the IMCR, i.e.
		 * connect BSP's local APIC to INT and NMI lines.
		 */
		apic_printk(APIC_VERBOSE, "leaving PIC mode, "
				"enabling APIC mode.\n");
		outb(0x70, 0x22);
		outb(0x01, 0x23);
	}
	enable_apic_mode();
}


int __init verify_local_APIC(void)
{
	unsigned int reg0, reg1;

	/*
	 * The version register is read-only in a real APIC.
	 */
	reg0 = apic_read(APIC_LVR);
	apic_printk(APIC_DEBUG, "Getting VERSION: %x\n", reg0);
	apic_write(APIC_LVR, reg0 ^ APIC_LVR_MASK);
	reg1 = apic_read(APIC_LVR);
	apic_printk(APIC_DEBUG, "Getting VERSION: %x\n", reg1);

	/*
	 * The two version reads above should print the same
	 * numbers.  If the second one is different, then we
	 * poke at a non-APIC.
	 */
	if (reg1 != reg0)
		return 0;

	/*
	 * Check if the version looks reasonably.
	 */
	reg1 = GET_APIC_VERSION(reg0);
	if (reg1 == 0x00 || reg1 == 0xff)
		return 0;
	reg1 = get_maxlvt();
	if (reg1 < 0x02 || reg1 == 0xff)
		return 0;

	/*
	 * The ID register is read/write in a real APIC.
	 */
	reg0 = apic_read(APIC_ID);
	apic_printk(APIC_DEBUG, "Getting ID: %x\n", reg0);

	/*
	 * The next two are just to see if we have sane values.
	 * They're only really relevant if we're in Virtual Wire
	 * compatibility mode, but most boxes are anymore.
	 */
	reg0 = apic_read(APIC_LVT0);
	apic_printk(APIC_DEBUG, "Getting LVT0: %x\n", reg0);
	reg1 = apic_read(APIC_LVT1);
	apic_printk(APIC_DEBUG, "Getting LVT1: %x\n", reg1);

	return 1;
}


extern void __error_in_apic_c (void);

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

void __init setup_local_APIC (void)
{
	unsigned long oldvalue, value, ver, maxlvt;

	if (esr_disable) {
		apic_write(APIC_ESR, 0);
		apic_write(APIC_ESR, 0);
		apic_write(APIC_ESR, 0);
		apic_write(APIC_ESR, 0);
	}

	value = apic_read(APIC_LVR);
	ver = GET_APIC_VERSION(value);

	if ((SPURIOUS_APIC_VECTOR & 0x0f) != 0x0f)
		panic("SPURIOUS_APIC_VECTOR & 0x0f");

	if (!apic_id_registered())
		BUG();

	init_apic_ldr();

	/*
	 * Set Task Priority to 'accept all'. We never change this
	 * later on.
	 */
	value = apic_read(APIC_TASKPRI);
	value &= ~APIC_TPRI_MASK;
	apic_write_around(APIC_TASKPRI, value);

	/*
	 * Now that we are all set up, enable the APIC
	 */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_VECTOR_MASK;
	/*
	 * Enable APIC
	 */
	value |= APIC_SPIV_APIC_ENABLED;

#if 1
	/* Enable focus processor (bit==0) */
	value &= ~APIC_SPIV_FOCUS_DISABLED;
#else
	/* Disable focus processor (bit==1) */
	value |= APIC_SPIV_FOCUS_DISABLED;
#endif

	/*
	 * Set spurious IRQ vector
	 */
	value |= SPURIOUS_APIC_VECTOR;
	apic_write_around(APIC_SPIV, value);

	value = apic_read(APIC_LVT0) & APIC_LVT_MASKED;
	if (!smp_processor_id() && (pic_mode || !value)) {
		value = APIC_DM_EXTINT;
		apic_printk(APIC_VERBOSE, "enabled ExtINT on CPU#%d\n",
				smp_processor_id());
	} else {
		value = APIC_DM_EXTINT | APIC_LVT_MASKED;
		apic_printk(APIC_VERBOSE, "masked ExtINT on CPU#%d\n",
				smp_processor_id());
	}
	apic_write_around(APIC_LVT0, value);

	if (!smp_processor_id())
		value = APIC_DM_NMI;
	else
		value = APIC_DM_NMI | APIC_LVT_MASKED;
	if (!APIC_INTEGRATED(ver))		/* 82489DX */
		value |= APIC_LVT_LEVEL_TRIGGER;
	apic_write_around(APIC_LVT1, value);

	if (APIC_INTEGRATED(ver) && !esr_disable) {		/* !82489DX */
		maxlvt = get_maxlvt();
		if (maxlvt > 3)		/* Due to the Pentium erratum 3AP. */
			apic_write(APIC_ESR, 0);
		oldvalue = apic_read(APIC_ESR);

		value = ERROR_APIC_VECTOR;      // enables sending errors
		apic_write_around(APIC_LVTERR, value);
		/*
		 * spec says clear errors after enabling vector.
		 */
		if (maxlvt > 3)
			apic_write(APIC_ESR, 0);
		value = apic_read(APIC_ESR);
		if (value != oldvalue)
			apic_printk(APIC_VERBOSE, "ESR value before enabling "
				"vector: 0x%08lx  after: 0x%08lx\n",
				oldvalue, value);
	} else {
		if (esr_disable)	
			/* 
			 * Something untraceble is creating bad interrupts on 
			 * secondary quads ... for the moment, just leave the
			 * ESR disabled - we can't do anything useful with the
			 * errors anyway - mbligh
			 */
			printk("Leaving ESR disabled.\n");
		else 
			printk("No ESR for 82489DX.\n");
	}

	if (nmi_watchdog == NMI_LOCAL_APIC)
		setup_apic_nmi_watchdog();
	apic_pm_activate();
}

static struct {
	int active;
	/* r/w apic fields */
	unsigned int apic_id;
	unsigned int apic_taskpri;
	unsigned int apic_ldr;
	unsigned int apic_dfr;
	unsigned int apic_spiv;
	unsigned int apic_lvtt;
	unsigned int apic_lvtpc;
	unsigned int apic_lvt0;
	unsigned int apic_lvt1;
	unsigned int apic_lvterr;
	unsigned int apic_tmict;
	unsigned int apic_tdcr;
	unsigned int apic_thmr;
} apic_pm_state;

static void __init apic_pm_activate(void)
{
	apic_pm_state.active = 1;
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

/*
 * The timer chip is already set up at HZ interrupts per second here,
 * but we do not accept timer interrupts yet. We only allow the BP
 * to calibrate.
 */
static unsigned int __init get_8254_timer_count(void)
{
	extern spinlock_t i8253_lock;
	unsigned long flags;

	unsigned int count;

	spin_lock_irqsave(&i8253_lock, flags);

	outb_p(0x00, PIT_MODE);
	count = inb_p(PIT_CH0);
	count |= inb_p(PIT_CH0) << 8;

	spin_unlock_irqrestore(&i8253_lock, flags);

	return count;
}

/* next tick in 8254 can be caught by catching timer wraparound */
static void __init wait_8254_wraparound(void)
{
	unsigned int curr_count, prev_count;

	curr_count = get_8254_timer_count();
	do {
		prev_count = curr_count;
		curr_count = get_8254_timer_count();

		/* workaround for broken Mercury/Neptune */
		if (prev_count >= curr_count + 0x100)
			curr_count = get_8254_timer_count();
	} while(prev_count >= curr_count);
}

void (*wait_timer_tick)(void) __initdata = wait_8254_wraparound;

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

static void __init setup_APIC_timer(unsigned int clocks)
{
	unsigned long flags;

	local_irq_save(flags);

	/*
	 * Wait for IRQ0's slice:
	 */
	wait_timer_tick();

	__setup_APIC_LVTT(clocks);

	local_irq_restore(flags);
}

int __init calibrate_APIC_clock(void)
{
	unsigned long long t1 = 0, t2 = 0;
	long tt1, tt2;
	long result;
	int i;
	const int LOOPS = HZ/10;

	apic_printk(APIC_VERBOSE, "calibrating APIC timer ...\n");

	/*
	 * Put whatever arbitrary (but long enough) timeout
	 * value into the APIC clock, we just want to get the
	 * counter running for calibration.
	 */
	__setup_APIC_LVTT(1000000000);

	/*
	 * The timer chip counts down to zero. Let's wait
	 * for a wraparound to start exact measurement:
	 * (the current tick might have been already half done)
	 */

	wait_timer_tick();

	/*
	 * We wrapped around just now. Let's start:
	 */
	if (cpu_has_tsc)
		rdtscll(t1);
	tt1 = apic_read(APIC_TMCCT);

	/*
	 * Let's wait LOOPS wraprounds:
	 */
	for (i = 0; i < LOOPS; i++)
		wait_timer_tick();

	tt2 = apic_read(APIC_TMCCT);
	if (cpu_has_tsc)
		rdtscll(t2);

	/*
	 * The APIC bus clock counter is 32 bits only, it
	 * might have overflown, but note that we use signed
	 * longs, thus no extra care needed.
	 *
	 * underflown to be exact, as the timer counts down ;)
	 */

	result = (tt1-tt2)*APIC_DIVISOR/LOOPS;

	if (cpu_has_tsc)
		apic_printk(APIC_VERBOSE, "..... CPU clock speed is "
			"%ld.%04ld MHz.\n",
			((long)(t2-t1)/LOOPS)/(1000000/HZ),
			((long)(t2-t1)/LOOPS)%(1000000/HZ));

	apic_printk(APIC_VERBOSE, "..... host bus clock speed is "
		"%ld.%04ld MHz.\n",
		result/(1000000/HZ),
		result%(1000000/HZ));

	return result;
}

static unsigned int calibration_result;

void __init setup_boot_APIC_clock(void)
{
	apic_printk(APIC_VERBOSE, "Using local APIC timer interrupts.\n");
	using_apic_timer = 1;

	local_irq_disable();

	calibration_result = calibrate_APIC_clock();
	/*
	 * Now set up the timer for real.
	 */
	setup_APIC_timer(calibration_result);

	local_irq_enable();
}

void __init setup_secondary_APIC_clock(void)
{
	setup_APIC_timer(calibration_result);
}

void __init disable_APIC_timer(void)
{
	if (using_apic_timer) {
		unsigned long v;

		v = apic_read(APIC_LVTT);
		apic_write_around(APIC_LVTT, v | APIC_LVT_MASKED);
	}
}

void enable_APIC_timer(void)
{
	if (using_apic_timer) {
		unsigned long v;

		v = apic_read(APIC_LVTT);
		apic_write_around(APIC_LVTT, v & ~APIC_LVT_MASKED);
	}
}

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
	int cpu = smp_processor_id();

	/*
	 * the NMI deadlock-detector uses this.
	 */
	irq_stat[cpu].apic_timer_irqs++;

	/*
	 * NOTE! We'd better ACK the irq immediately,
	 * because timer handling can be slow.
	 */
	ack_APIC_irq();
	/*
	 * update_process_times() expects us to have done irq_enter().
	 * Besides, if we don't timer interrupts ignore the global
	 * interrupt lock, which is the WrongThing (tm) to do.
	 */
	irq_enter();
	smp_local_timer_interrupt(regs);
	irq_exit();
}

/*
 * This interrupt should _never_ happen with our APIC/SMP architecture
 */
fastcall void smp_spurious_interrupt(struct pt_regs *regs)
{
	unsigned long v;

	irq_enter();
	/*
	 * Check if this really is a spurious interrupt and ACK it
	 * if it is a vectored one.  Just in case...
	 * Spurious interrupts should not be ACKed.
	 */
	v = apic_read(APIC_ISR + ((SPURIOUS_APIC_VECTOR & ~0x1f) >> 1));
	if (v & (1 << (SPURIOUS_APIC_VECTOR & 0x1f)))
		ack_APIC_irq();

	/* see sw-dev-man vol 3, chapter 7.4.13.5 */
	printk(KERN_INFO "spurious APIC interrupt on CPU#%d, should never happen.\n",
			smp_processor_id());
	irq_exit();
}

/*
 * This interrupt should never happen with our APIC/SMP architecture
 */

fastcall void smp_error_interrupt(struct pt_regs *regs)
{
	unsigned long v, v1;

	irq_enter();
	/* First tickle the hardware, only then report what went on. -- REW */
	v = apic_read(APIC_ESR);
	apic_write(APIC_ESR, 0);
	v1 = apic_read(APIC_ESR);
	ack_APIC_irq();
	atomic_inc(&irq_err_count);

	/* Here is what the APIC error bits mean:
	   0: Send CS error
	   1: Receive CS error
	   2: Send accept error
	   3: Receive accept error
	   4: Reserved
	   5: Send illegal vector
	   6: Received illegal vector
	   7: Illegal register address
	*/
	printk (KERN_DEBUG "APIC error on CPU%d: %02lx(%02lx)\n",
	        smp_processor_id(), v , v1);
	irq_exit();
}
