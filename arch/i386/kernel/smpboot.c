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

/* Set if we find a B stepping CPU */
static int __initdata smp_b_stepping;

/* bitmap of online cpus */
cpumask_t cpu_online_map;

cpumask_t cpu_callin_map;
cpumask_t cpu_callout_map;
static cpumask_t smp_commenced_mask;


/* Per CPU bogomips and other parameters */
struct cpuinfo_x86 cpu_data[NR_CPUS] __cacheline_aligned;

u8 x86_cpu_to_apicid[NR_CPUS] =
			{ [0 ... NR_CPUS-1] = 0xff };
EXPORT_SYMBOL(x86_cpu_to_apicid);

extern unsigned char trampoline_data [];
extern unsigned char trampoline_end  [];
static unsigned char *trampoline_base;
static int trampoline_exec;

static unsigned long __init setup_trampoline(void)
{
	memcpy(trampoline_base, trampoline_data, trampoline_end - trampoline_data);
	return virt_to_phys(trampoline_base);
}

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

static void __init smp_store_cpu_info(int id)
{
	struct cpuinfo_x86 *c = cpu_data + id;

	*c = boot_cpu_data;
	if (id != 0)
		identify_cpu(c);
	/*
	 * Mask B, Pentium, but not Pentium MMX
	 */
	if (c->x86_vendor == X86_VENDOR_INTEL &&
	    c->x86 == 5 &&
	    c->x86_mask >= 1 && c->x86_mask <= 4 &&
	    c->x86_model <= 3)
		/*
		 * Remember we have B step Pentia with bugs
		 */
		smp_b_stepping = 1;

	/*
	 * Certain Athlons might work (for various values of 'work') in SMP
	 * but they are not certified as MP capable.
	 */
	if ((c->x86_vendor == X86_VENDOR_AMD) && (c->x86 == 6)) {

		/* Athlon 660/661 is valid. */	
		if ((c->x86_model==6) && ((c->x86_mask==0) || (c->x86_mask==1)))
			goto valid_k7;

		/* Duron 670 is valid */
		if ((c->x86_model==7) && (c->x86_mask==0))
			goto valid_k7;

		/*
		 * Athlon 662, Duron 671, and Athlon >model 7 have capability bit.
		 * It's worth noting that the A5 stepping (662) of some Athlon XP's
		 * have the MP bit set.
		 * See http://www.heise.de/newsticker/data/jow-18.10.01-000 for more.
		 */
		if (((c->x86_model==6) && (c->x86_mask>=2)) ||
		    ((c->x86_model==7) && (c->x86_mask>=1)) ||
		     (c->x86_model> 7))
			if (cpu_has_mp)
				goto valid_k7;

		/* If we get here, it's not a certified SMP capable AMD system. */
		tainted |= TAINT_UNSAFE_SMP;
	}

valid_k7:
	;
}

int cpucount;

static atomic_t tsc_start_flag = ATOMIC_INIT(0);
static atomic_t tsc_count_start = ATOMIC_INIT(0);
static atomic_t tsc_count_stop = ATOMIC_INIT(0);
static unsigned long long tsc_values[NR_CPUS];

#define NR_LOOPS 5

static void __init synchronize_tsc_ap (void)
{
	int i;

	while (!atomic_read(&tsc_start_flag)) mb();

	for (i = 0; i < NR_LOOPS; i++) {
		atomic_inc(&tsc_count_start);
		while (atomic_read(&tsc_count_start) != num_booting_cpus())
			mb();

		rdtscll(tsc_values[smp_processor_id()]);
		if (i == NR_LOOPS - 1)
			write_tsc(0, 0);
		atomic_inc(&tsc_count_stop);
		while (atomic_read(&tsc_count_stop) != num_booting_cpus()) mb();
	}
}

#undef NR_LOOPS

extern void calibrate_delay(void);

static atomic_t init_deasserted;

void __init smp_callin(void)
{
	int cpuid, phys_id;
	unsigned long timeout;

	wait_for_init_deassert(&init_deasserted);
	phys_id = GET_APIC_ID(apic_read(APIC_ID));
	cpuid = smp_processor_id();
	if (cpu_isset(cpuid, cpu_callin_map)) {
		printk("huh, phys CPU#%d, CPU#%d already present??\n",
					phys_id, cpuid);
		BUG();
	}
	Dprintk("CPU#%d (phys ID: %d) waiting for CALLOUT\n", cpuid, phys_id);

	timeout = jiffies + 2 * HZ;
	while (time_before(jiffies, timeout)) {
		if (cpu_isset(cpuid, cpu_callout_map))
			break;
		rep_nop();
	}

	if (!time_before(jiffies, timeout)) {
		printk("BUG: CPU%d started up but did not get a callout!\n",
			cpuid);
		BUG();
	}

	Dprintk("CALLIN, before setup_local_APIC().\n");
	smp_callin_clear_local_apic();
	setup_local_APIC();
	map_cpu_to_logical_apicid();

	calibrate_delay();
	Dprintk("Stack at about %p\n",&cpuid);

	/*
	 * Save our processor parameters
	 */
 	smp_store_cpu_info(cpuid);

	disable_APIC_timer();

	/*
	 * Allow the master to continue.
	 */
	cpu_set(cpuid, cpu_callin_map);

	/*
	 *      Synchronize the TSC with the BP
	 */
	if (cpu_has_tsc && cpu_khz)
		synchronize_tsc_ap();
}

/*
 * Activate a secondary processor.
 */
static void __init start_secondary(void *unused)
{
	cpu_init();
	smp_callin();
	while (!cpu_isset(smp_processor_id(), smp_commenced_mask))
		rep_nop();
	setup_secondary_APIC_clock();
	if (nmi_watchdog == NMI_IO_APIC) {
		disable_8259A_irq(0);
		enable_NMI_through_LVT0(NULL);
		enable_8259A_irq(0);
	}
	enable_APIC_timer();

	local_flush_tlb();
	cpu_set(smp_processor_id(), cpu_online_map);

	local_irq_enable();

	wmb();
	cpu_idle();
}

void __init initialize_secondary(void) {
    asm volatile(
		"movl %0,%%esp\n\t"
		"jmp *%1"
		:
		:"r" (current->thread.esp),"r" (current->thread.eip));
}

extern struct {
	void * esp;
	unsigned short ss;
} stack_start;

#ifdef CONFIG_NUMA

#else /* !CONFIG_NUMA */

#define map_cpu_to_node(cpu, node)	({})
#define unmap_cpu_to_node(cpu)	({})

#endif /* CONFIG_NUMA */

u8 cpu_2_logical_apicid[NR_CPUS] = { [0 ... NR_CPUS-1] = BAD_APICID };

void map_cpu_to_logical_apicid(void)
{
	int cpu = smp_processor_id();
	int apicid = logical_smp_processor_id();

	cpu_2_logical_apicid[cpu] = apicid;
	map_cpu_to_node(cpu, apicid_to_node(apicid));
}

void unmap_cpu_to_logical_apicid(int cpu)
{
	cpu_2_logical_apicid[cpu] = BAD_APICID;
	unmap_cpu_to_node(cpu);
}

#if APIC_DEBUG
static inline void __inquire_remote_apic(int apicid)
{
	int i, regs[] = { APIC_ID >> 4, APIC_LVR >> 4, APIC_SPIV >> 4 };
	char *names[] = { "ID", "VERSION", "SPIV" };
	int timeout, status;

	printk("Inquiring remote APIC #%d...\n", apicid);

	for (i = 0; i < sizeof(regs) / sizeof(*regs); i++) {
		printk("... APIC #%d %s: ", apicid, names[i]);

		/*
		 * Wait for idle.
		 */
		apic_wait_icr_idle();

		apic_write_around(APIC_ICR2, SET_APIC_DEST_FIELD(apicid));
		apic_write_around(APIC_ICR, APIC_DM_REMRD | regs[i]);

		timeout = 0;
		do {
			udelay(100);
			status = apic_read(APIC_ICR) & APIC_ICR_RR_MASK;
		} while (status == APIC_ICR_RR_INPROG && timeout++ < 1000);

		switch (status) {
		case APIC_ICR_RR_VALID:
			status = apic_read(APIC_RRR);
			printk("%08x\n", status);
			break;
		default:
			printk("failed\n");
		}
	}
}
#endif

#ifdef WAKE_SECONDARY_VIA_INIT
static int __init
wakeup_secondary_cpu(int phys_apicid, unsigned long start_eip)
{
	unsigned long send_status = 0, accept_status = 0;
	int maxlvt, timeout, num_starts, j;

	if (APIC_INTEGRATED(apic_version[phys_apicid])) {
		apic_read_around(APIC_SPIV);
		apic_write(APIC_ESR, 0);
		apic_read(APIC_ESR);
	}

	Dprintk("Asserting INIT.\n");

	/*
	 * Turn INIT on target chip
	 */
	apic_write_around(APIC_ICR2, SET_APIC_DEST_FIELD(phys_apicid));

	/*
	 * Send IPI
	 */
	apic_write_around(APIC_ICR, APIC_INT_LEVELTRIG | APIC_INT_ASSERT
				| APIC_DM_INIT);

	Dprintk("Waiting for send to finish...\n");
	timeout = 0;
	do {
		Dprintk("+");
		udelay(100);
		send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
	} while (send_status && (timeout++ < 1000));

	mdelay(10);

	Dprintk("Deasserting INIT.\n");

	/* Target chip */
	apic_write_around(APIC_ICR2, SET_APIC_DEST_FIELD(phys_apicid));

	/* Send IPI */
	apic_write_around(APIC_ICR, APIC_INT_LEVELTRIG | APIC_DM_INIT);

	Dprintk("Waiting for send to finish...\n");
	timeout = 0;
	do {
		Dprintk("+");
		udelay(100);
		send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
	} while (send_status && (timeout++ < 1000));

	atomic_set(&init_deasserted, 1);

	/*
	 * Should we send STARTUP IPIs ?
	 *
	 * Determine this based on the APIC version.
	 * If we don't have an integrated APIC, don't send the STARTUP IPIs.
	 */
	if (APIC_INTEGRATED(apic_version[phys_apicid]))
		num_starts = 2;
	else
		num_starts = 0;

	/*
	 * Run STARTUP IPI loop.
	 */
	Dprintk("#startup loops: %d.\n", num_starts);

	maxlvt = get_maxlvt();

	for (j = 1; j <= num_starts; j++) {
		Dprintk("Sending STARTUP #%d.\n",j);
		apic_read_around(APIC_SPIV);
		apic_write(APIC_ESR, 0);
		apic_read(APIC_ESR);
		Dprintk("After apic_write.\n");

		/*
		 * STARTUP IPI
		 */

		/* Target chip */
		apic_write_around(APIC_ICR2, SET_APIC_DEST_FIELD(phys_apicid));

		/* Boot on the stack */
		/* Kick the second */
		apic_write_around(APIC_ICR, APIC_DM_STARTUP
					| (start_eip >> 12));

		/*
		 * Give the other CPU some time to accept the IPI.
		 */
		udelay(300);

		Dprintk("Startup point 1.\n");

		Dprintk("Waiting for send to finish...\n");
		timeout = 0;
		do {
			Dprintk("+");
			udelay(100);
			send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
		} while (send_status && (timeout++ < 1000));

		/*
		 * Give the other CPU some time to accept the IPI.
		 */
		udelay(200);
		/*
		 * Due to the Pentium erratum 3AP.
		 */
		if (maxlvt > 3) {
			apic_read_around(APIC_SPIV);
			apic_write(APIC_ESR, 0);
		}
		accept_status = (apic_read(APIC_ESR) & 0xEF);
		if (send_status || accept_status)
			break;
	}
	Dprintk("After Startup.\n");

	if (send_status)
		printk("APIC never delivered???\n");
	if (accept_status)
		printk("APIC delivery error (%lx).\n", accept_status);

	return (send_status | accept_status);
}
#endif

extern cpumask_t cpu_initialized;

static int __init do_boot_cpu(int apicid)
{
	struct task_struct *idle;
	unsigned long boot_error;
	int timeout, cpu;
	unsigned long start_eip;
	unsigned short nmi_high = 0, nmi_low = 0;

	cpu = ++cpucount;

	idle = fork_idle(cpu);
	if (IS_ERR(idle))
		panic("failed fork for CPU %d", cpu);
	idle->thread.eip = (unsigned long) start_secondary;
	start_eip = setup_trampoline();

	printk("Booting processor %d/%d eip %lx\n", cpu, apicid, start_eip);

	stack_start.esp = (void *) idle->thread.esp;

	irq_ctx_init(cpu);

	atomic_set(&init_deasserted, 0);

	Dprintk("Setting warm reset code and vector.\n");

	store_NMI_vector(&nmi_high, &nmi_low);

	smpboot_setup_warm_reset_vector(start_eip);

	boot_error = wakeup_secondary_cpu(apicid, start_eip);
	if (!boot_error) {
		/*
		 * allow APs to start initializing.
		 */
		Dprintk("Before Callout %d.\n", cpu);
		cpu_set(cpu, cpu_callout_map);
		Dprintk("After Callout %d.\n", cpu);

		/*
		 * Wait 5s total for a response
		 */
		for (timeout = 0; timeout < 50000; timeout++) {
			if (cpu_isset(cpu, cpu_callin_map))
				break;	/* It has booted */
			udelay(100);
		}

		if (cpu_isset(cpu, cpu_callin_map)) {
			/* number CPUs logically, starting from 1 (BSP is 0) */
			Dprintk("OK.\n");
			printk("CPU%d: ", cpu);
			print_cpu_info(&cpu_data[cpu]);
			Dprintk("CPU has booted.\n");
		} else {
			boot_error= 1;
			if (*((volatile unsigned char *)trampoline_base)
					== 0xA5)
				/* trampoline started but...? */
				printk("Stuck ??\n");
			else
				/* trampoline code not run */
				printk("Not responding.\n");
			inquire_remote_apic(apicid);
		}
	}
	x86_cpu_to_apicid[cpu] = apicid;
	if (boot_error) {
		/* Try to put things back the way they were before ... */
		unmap_cpu_to_logical_apicid(cpu);
		cpu_clear(cpu, cpu_callout_map); /* was set here (do_boot_cpu()) */
		cpu_clear(cpu, cpu_initialized); /* was set by cpu_init() */
		cpucount--;
	}

	/* mark "stuck" area as not stuck */
	*((volatile unsigned long *)trampoline_base) = 0;

	return boot_error;
}


cycles_t cacheflush_time;
unsigned long cache_decay_ticks;

static void smp_tune_scheduling (void)
{
	unsigned long cachesize;       /* kB   */
	unsigned long bandwidth = 350; /* MB/s */
	/*
	 * Rough estimation for SMP scheduling, this is the number of
	 * cycles it takes for a fully memory-limited process to flush
	 * the SMP-local cache.
	 *
	 * (For a P5 this pretty much means we will choose another idle
	 *  CPU almost always at wakeup time (this is due to the small
	 *  L1 cache), on PIIs it's around 50-100 usecs, depending on
	 *  the cache size)
	 */

	if (!cpu_khz) {
		/*
		 * this basically disables processor-affinity
		 * scheduling on SMP without a TSC.
		 */
		cacheflush_time = 0;
		return;
	} else {
		cachesize = boot_cpu_data.x86_cache_size;
		if (cachesize == -1) {
			cachesize = 16; /* Pentiums, 2x8kB cache */
			bandwidth = 100;
		}

		cacheflush_time = (cpu_khz>>10) * (cachesize<<10) / bandwidth;
	}

	cache_decay_ticks = (long)cacheflush_time/cpu_khz + 1;

	printk("per-CPU timeslice cutoff: %ld.%02ld usecs.\n",
		(long)cacheflush_time/(cpu_khz/1000),
		((long)cacheflush_time*100/(cpu_khz/1000)) % 100);
	printk("task migration cache decay timeout: %ld msecs.\n",
		cache_decay_ticks);
}


static int boot_cpu_logical_apicid;
/* Where the IO area was mapped on multiquad, always 0 otherwise */
void *xquad_portio;

cpumask_t cpu_sibling_map[NR_CPUS] __cacheline_aligned;

static void __init smp_boot_cpus(unsigned int max_cpus)
{
	int apicid, cpu, bit, kicked;
	unsigned long bogosum = 0;

	smp_store_cpu_info(0);
	printk("CPU%d: ", 0);
	print_cpu_info(&cpu_data[0]);

	boot_cpu_physical_apicid = GET_APIC_ID(apic_read(APIC_ID));
	boot_cpu_logical_apicid = logical_smp_processor_id();
	x86_cpu_to_apicid[0] = boot_cpu_physical_apicid;

	current_thread_info()->cpu = 0;
	smp_tune_scheduling();
	cpus_clear(cpu_sibling_map[0]);
	cpu_set(0, cpu_sibling_map[0]);

	if (!smp_found_config && !acpi_lapic) {
		panic("in smp_found_config if");
	}

	if (!check_phys_apicid_present(boot_cpu_physical_apicid)) {
		printk("weird, boot CPU (#%d) not listed by the BIOS.\n",
				boot_cpu_physical_apicid);
		physid_set(hard_smp_processor_id(), phys_cpu_present_map);
	}

	if (APIC_INTEGRATED(apic_version[boot_cpu_physical_apicid]) && !cpu_has_apic) {
		printk(KERN_ERR "BIOS bug, local APIC #%d not detected!...\n",
			boot_cpu_physical_apicid);
		printk(KERN_ERR "... forcing use of dummy APIC emulation. (tell your hw vendor)\n");
		smpboot_clear_io_apic_irqs();
		phys_cpu_present_map = physid_mask_of_physid(0);
		return;
	}

	verify_local_APIC();

	if (!max_cpus) {
		smp_found_config = 0;
		printk(KERN_INFO "SMP mode deactivated, forcing use of dummy APIC emulation.\n");
		smpboot_clear_io_apic_irqs();
		phys_cpu_present_map = physid_mask_of_physid(0);
		return;
	}
	connect_bsp_APIC();
	setup_local_APIC();
	map_cpu_to_logical_apicid();

	setup_portio_remap();

	Dprintk("CPU present map: %lx\n", physids_coerce(phys_cpu_present_map));

	kicked = 1;
	for (bit = 0; kicked < NR_CPUS && bit < MAX_APICS; bit++) {
		apicid = cpu_present_to_apicid(bit);
		/*
		 * Don't even attempt to start the boot CPU!
		 */
		if ((apicid == boot_cpu_apicid) || (apicid == BAD_APICID))
			continue;

		if (!check_apicid_present(bit))
			continue;
		if (max_cpus <= cpucount+1)
			continue;

		if (do_boot_cpu(apicid))
			printk("CPU #%d not responding - cannot use it.\n",
								apicid);
		else
			++kicked;
	}
}

void __init smp_prepare_cpus(unsigned int max_cpus)
{
	smp_boot_cpus(max_cpus);
}

void __devinit smp_prepare_boot_cpu(void) {
	cpu_set(smp_processor_id(), cpu_online_map);
	cpu_set(smp_processor_id(), cpu_callout_map);
}

int __devinit __cpu_up(unsigned int cpu)
{
	/* This only works at boot for x86.  See "rewrite" above. */
	if (cpu_isset(cpu, smp_commenced_mask)) {
		local_irq_enable();
		return -ENOSYS;
	}

	/* In case one didn't come up */
	if (!cpu_isset(cpu, cpu_callin_map)) {
		local_irq_enable();
		return -EIO;
	}

	local_irq_enable();
	/* Unleash the CPU! */
	cpu_set(cpu, smp_commenced_mask);
	while (!cpu_isset(cpu, cpu_online_map))
		mb();
	return 0;
}

void __init smp_cpus_done(unsigned int max_cpus)
{
#ifdef CONFIG_X86_IO_APIC
	setup_ioapic_dest();
#endif
	zap_low_mappings();
	/*
	 * Disable executability of the SMP trampoline:
	 */
	set_kernel_exec((unsigned long)trampoline_base, trampoline_exec);
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