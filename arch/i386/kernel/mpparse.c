#include <linux/mm.h>
#include <linux/irq.h>
#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/config.h>
#include <linux/bootmem.h>
#include <linux/smp_lock.h>
#include <linux/kernel_stat.h>
#include <linux/mc146818rtc.h>
#include <linux/bitops.h>

#include <asm/smp.h>
#include <asm/acpi.h>
#include <asm/mtrr.h>
#include <asm/mpspec.h>
#include <asm/io_apic.h>

#include <mach_apic.h>
#include <mach_mpparse.h>
#include <bios_ebda.h>

/* Have we found an MP table */
int smp_found_config;
unsigned int __initdata maxcpus = NR_CPUS;

/*
 * Various Linux-internal data structures created from the
 * MP-table.
 */
int apic_version [MAX_APICS];
int mp_bus_id_to_type [MAX_MP_BUSSES];
int mp_bus_id_to_node [MAX_MP_BUSSES];
int mp_bus_id_to_local [MAX_MP_BUSSES];
int quad_local_to_mp_bus_id [NR_CPUS/4][4];
int mp_bus_id_to_pci_bus [MAX_MP_BUSSES] = { [0 ... MAX_MP_BUSSES-1] = -1 };
int mp_current_pci_id;

/* I/O APIC entries */
struct mpc_config_ioapic mp_ioapics[MAX_IO_APICS];

/* # of MP IRQ source entries */
struct mpc_config_intsrc mp_irqs[MAX_IRQ_SOURCES];

/* MP IRQ source entries */
int mp_irq_entries;

int nr_ioapics;

int pic_mode;
unsigned long mp_lapic_addr;

/* Internal processor count */
static unsigned int __initdata num_processors;

/* Bitmask of physically existing CPUs */
physid_mask_t phys_cpu_present_map;

/* Processor that is doing the boot up */
unsigned int boot_cpu_physical_apicid = -1U;
unsigned int boot_cpu_logical_apicid = -1U;
/* Internal processor count */
static unsigned int __initdata num_processors;

/* Bitmask of physically existing CPUs */
physid_mask_t phys_cpu_present_map;

u8 bios_cpu_apicid[NR_CPUS] = { [0 ... NR_CPUS-1] = BAD_APICID };

static int __init mpf_checksum(unsigned char *mp, int len) {
	int sum = 0;

	while (len--)
		sum += *mp++;

	return sum & 0xFF;
}

static int mpc_record; 
static struct mpc_config_translation *translation_table[MAX_MPC_ENTRY] __initdata;

#ifdef CONFIG_X86_NUMAQ
#error "CONFIG_X86_NUMAQ"
#else
static int MP_valid_apicid(int apicid, int version)
{
	if (version >= 0x14)
		return apicid < 0xff;
	else
		return apicid < 0xf;
}
#endif

void __init MP_processor_info (struct mpc_config_processor *m)
{
 	int ver, apicid;
	physid_mask_t tmp;
 	
	if (!(m->mpc_cpuflag & CPU_ENABLED))
		return;

	apicid = mpc_apic_id(m, translation_table[mpc_record]);

	if (m->mpc_featureflag&(1<<0))
		Dprintk("    Floating point unit present.\n");
	if (m->mpc_featureflag&(1<<7))
		Dprintk("    Machine Exception supported.\n");
	if (m->mpc_featureflag&(1<<8))
		Dprintk("    64 bit compare & exchange supported.\n");
	if (m->mpc_featureflag&(1<<9))
		Dprintk("    Internal APIC present.\n");
	if (m->mpc_featureflag&(1<<11))
		Dprintk("    SEP present.\n");
	if (m->mpc_featureflag&(1<<12))
		Dprintk("    MTRR  present.\n");
	if (m->mpc_featureflag&(1<<13))
		Dprintk("    PGE  present.\n");
	if (m->mpc_featureflag&(1<<14))
		Dprintk("    MCA  present.\n");
	if (m->mpc_featureflag&(1<<15))
		Dprintk("    CMOV  present.\n");
	if (m->mpc_featureflag&(1<<16))
		Dprintk("    PAT  present.\n");
	if (m->mpc_featureflag&(1<<17))
		Dprintk("    PSE  present.\n");
	if (m->mpc_featureflag&(1<<18))
		Dprintk("    PSN  present.\n");
	if (m->mpc_featureflag&(1<<19))
		Dprintk("    Cache Line Flush Instruction present.\n");
	/* 20 Reserved */
	if (m->mpc_featureflag&(1<<21))
		Dprintk("    Debug Trace and EMON Store present.\n");
	if (m->mpc_featureflag&(1<<22))
		Dprintk("    ACPI Thermal Throttle Registers  present.\n");
	if (m->mpc_featureflag&(1<<23))
		Dprintk("    MMX  present.\n");
	if (m->mpc_featureflag&(1<<24))
		Dprintk("    FXSR  present.\n");
	if (m->mpc_featureflag&(1<<25))
		Dprintk("    XMM  present.\n");
	if (m->mpc_featureflag&(1<<26))
		Dprintk("    Willamette New Instructions  present.\n");
	if (m->mpc_featureflag&(1<<27))
		Dprintk("    Self Snoop  present.\n");
	if (m->mpc_featureflag&(1<<28))
		Dprintk("    HT  present.\n");
	if (m->mpc_featureflag&(1<<29))
		Dprintk("    Thermal Monitor present.\n");
	/* 30, 31 Reserved */


	if (m->mpc_cpuflag & CPU_BOOTPROCESSOR) {
		Dprintk("    Bootup CPU\n");
		boot_cpu_physical_apicid = m->mpc_apicid;
		boot_cpu_logical_apicid = apicid;
	}

	if (num_processors >= NR_CPUS) {
		printk(KERN_WARNING "WARNING: NR_CPUS limit of %i reached."
			"  Processor ignored.\n", NR_CPUS); 
		return;
	}

	if (num_processors >= maxcpus) {
		printk(KERN_WARNING "WARNING: maxcpus limit of %i reached."
			" Processor ignored.\n", maxcpus); 
		return;
	}
	num_processors++;
	ver = m->mpc_apicver;

	if (!MP_valid_apicid(apicid, ver)) {
		printk(KERN_WARNING "Processor #%d INVALID. (Max ID: %d).\n",
			m->mpc_apicid, MAX_APICS);
		--num_processors;
		return;
	}

	tmp = apicid_to_cpu_present(apicid);
	physids_or(phys_cpu_present_map, phys_cpu_present_map, tmp);
	
	/*
	 * Validate version
	 */
	if (ver == 0x0) {
		printk(KERN_WARNING "BIOS bug, APIC version is 0 for CPU#%d! fixing up to 0x10. (tell your hw vendor)\n", m->mpc_apicid);
		ver = 0x10;
	}
	apic_version[m->mpc_apicid] = ver;
	bios_cpu_apicid[num_processors - 1] = m->mpc_apicid;
}

static void __init MP_bus_info (struct mpc_config_bus *m)
{
	char str[7];
}

static int __init smp_read_mpc(struct mp_config_table *mpc)
{
	char str[16];
	char oem[10];
	int count=sizeof(*mpc);

	return 0;
}

static void __init construct_default_ioirq_mptable(int mpc_default_type)
{
	struct mpc_config_intsrc intsrc;
	int i;
	int ELCR_fallback = 0;
}

static inline void __init construct_default_ISA_mptable(int mpc_default_type)
{
	struct mpc_config_processor processor;
	struct mpc_config_bus bus;
	struct mpc_config_ioapic ioapic;
	struct mpc_config_lintsrc lintsrc;
}

static struct intel_mp_floating *mpf_found;

/*
 * Scan the memory blocks for an SMP configuration block.
 */
void __init get_smp_config (void) {
	struct intel_mp_floating *mpf = mpf_found;

	if (acpi_lapic && acpi_ioapic) {
		printk(KERN_INFO "Using ACPI (MADT) for SMP configuration information\n");
		return;
	} else if (acpi_lapic)
		printk(KERN_INFO "Using ACPI for processor (LAPIC) configuration information\n");

	printk(KERN_INFO "Intel MultiProcessor Specification v1.%d\n", mpf->mpf_specification);
	if (mpf->mpf_feature2 & (1 << 7)) {
		printk(KERN_INFO "    IMCR and PIC compatibility mode.\n");
		pic_mode = 1;
	} else {
		printk(KERN_INFO "    Virtual Wire compatibility mode.\n");
		pic_mode = 0;
	}

	if (mpf->mpf_feature1 != 0) {

		printk(KERN_INFO "Default MP configuration #%d\n", mpf->mpf_feature1);
		construct_default_ISA_mptable(mpf->mpf_feature1);

	} else if (mpf->mpf_physptr) {
		if (!smp_read_mpc((void *) mpf->mpf_physptr)) {
			smp_found_config = 0;
			printk(KERN_ERR "BIOS bug, MP table errors detected!...\n");
			printk(KERN_ERR "... disabling SMP support. (tell your hw vendor)\n");
			return;
		}

		if (!mp_irq_entries) {
			struct mpc_config_bus bus;

			printk(KERN_ERR "BIOS bug, no explicit IRQ entries, using default mptable. (tell your hw vendor)\n");

			bus.mpc_type = MP_BUS;
			bus.mpc_busid = 0;
			memcpy(bus.mpc_bustype, "ISA   ", 6);
			MP_bus_info(&bus);

			construct_default_ioirq_mptable(0);
		}

	} else
		BUG();
	printk(KERN_INFO "Processors: %d\n", num_processors);
}

static int __init smp_scan_config (unsigned long base, unsigned long length) {
	unsigned long *bp = phys_to_virt(base);
	struct intel_mp_floating *mpf;

	Dprintk("Scan SMP from %p for %ld bytes.\n", bp,length);
	if (sizeof(*mpf) != 16)
		printk("Error: MPF size\n");

	while (length > 0) {
		mpf = (struct intel_mp_floating *)bp;
		if ((*bp == SMP_MAGIC_IDENT) &&
			(mpf->mpf_length == 1) &&
			!mpf_checksum((unsigned char *)bp, 16) &&
			((mpf->mpf_specification == 1)
				|| (mpf->mpf_specification == 4)) ) {

			smp_found_config = 1;
			printk(KERN_INFO "found SMP MP-table at %08lx\n",
						virt_to_phys(mpf));
			reserve_bootmem(virt_to_phys(mpf), PAGE_SIZE);
			if (mpf->mpf_physptr) {
				/*
				 * We cannot access to MPC table to compute
				 * table size yet, as only few megabytes from
				 * the bottom is mapped now.
				 * PC-9800's MPC table places on the very last
				 * of physical memory; so that simply reserving
				 * PAGE_SIZE from mpg->mpf_physptr yields BUG()
				 * in reserve_bootmem.
				 */
				unsigned long size = PAGE_SIZE;
				unsigned long end = max_low_pfn * PAGE_SIZE;
				if (mpf->mpf_physptr + size > end)
					size = end - mpf->mpf_physptr;
				reserve_bootmem(mpf->mpf_physptr, size);
			}

			mpf_found = mpf;
			return 1;
		}
		bp += 4;
		length -= 16;
	}
	return 0;
}

void __init find_smp_config (void) {
	unsigned int address;

    if (smp_scan_config(0x0,0x400) ||
		smp_scan_config(639*0x400,0x400) ||
			smp_scan_config(0xF0000,0x10000))
		return;
    
    address = get_bios_ebda();
    if (address)
        smp_scan_config(address, 0x400);
}

/* --------------------------------------------------------------------------
                            ACPI-based MP Configuration
   -------------------------------------------------------------------------- */

#ifdef CONFIG_ACPI_BOOT

void __init mp_register_lapic_address (
	u64			address)
{
	mp_lapic_addr = (unsigned long) address;

	set_fixmap_nocache(FIX_APIC_BASE, mp_lapic_addr);

	if (boot_cpu_physical_apicid == -1U)
		boot_cpu_physical_apicid = GET_APIC_ID(apic_read(APIC_ID));

	Dprintk("Boot CPU = %d\n", boot_cpu_physical_apicid);
}

void __init mp_register_lapic (
	u8			id, 
	u8			enabled)
{
	struct mpc_config_processor processor;
	int			boot_cpu = 0;
	
	if (MAX_APICS - id <= 0) {
		printk(KERN_WARNING "Processor #%d invalid (max %d)\n",
			id, MAX_APICS);
		return;
	}

	if (id == boot_cpu_physical_apicid)
		boot_cpu = 1;

	processor.mpc_type = MP_PROCESSOR;
	processor.mpc_apicid = id;
	processor.mpc_apicver = GET_APIC_VERSION(apic_read(APIC_LVR));
	processor.mpc_cpuflag = (enabled ? CPU_ENABLED : 0);
	processor.mpc_cpuflag |= (boot_cpu ? CPU_BOOTPROCESSOR : 0);
	processor.mpc_cpufeature = (boot_cpu_data.x86 << 8) | 
		(boot_cpu_data.x86_model << 4) | boot_cpu_data.x86_mask;
	processor.mpc_featureflag = boot_cpu_data.x86_capability[0];
	processor.mpc_reserved[0] = 0;
	processor.mpc_reserved[1] = 0;

	MP_processor_info(&processor);
}

#if defined(CONFIG_X86_IO_APIC) && (defined(CONFIG_ACPI_INTERPRETER) || defined(CONFIG_ACPI_BOOT))

#define MP_ISA_BUS		0
#define MP_MAX_IOAPIC_PIN	127

struct mp_ioapic_routing {
	int			apic_id;
	int			gsi_base;
	int			gsi_end;
	u32			pin_programmed[4];
} mp_ioapic_routing[MAX_IO_APICS];

static int mp_find_ioapic (
	int			gsi)
{
	int			i = 0;

	/* Find the IOAPIC that manages this GSI. */
	for (i = 0; i < nr_ioapics; i++) {
		if ((gsi >= mp_ioapic_routing[i].gsi_base)
			&& (gsi <= mp_ioapic_routing[i].gsi_end))
			return i;
	}

	printk(KERN_ERR "ERROR: Unable to locate IOAPIC for GSI %d\n", gsi);

	return -1;
}

void __init mp_register_ioapic (
	u8			id, 
	u32			address,
	u32			gsi_base)
{
	int			idx = 0;

	if (nr_ioapics >= MAX_IO_APICS) {
		printk(KERN_ERR "ERROR: Max # of I/O APICs (%d) exceeded "
			"(found %d)\n", MAX_IO_APICS, nr_ioapics);
		panic("Recompile kernel with bigger MAX_IO_APICS!\n");
	}
	if (!address) {
		printk(KERN_ERR "WARNING: Bogus (zero) I/O APIC address"
			" found in MADT table, skipping!\n");
		return;
	}

	idx = nr_ioapics++;

	mp_ioapics[idx].mpc_type = MP_IOAPIC;
	mp_ioapics[idx].mpc_flags = MPC_APIC_USABLE;
	mp_ioapics[idx].mpc_apicaddr = address;

	set_fixmap_nocache(FIX_IO_APIC_BASE_0 + idx, address);
	mp_ioapics[idx].mpc_apicid = io_apic_get_unique_id(idx, id);
	mp_ioapics[idx].mpc_apicver = io_apic_get_version(idx);

	/* 
	 * Build basic GSI lookup table to facilitate gsi->io_apic lookups
	 * and to prevent reprogramming of IOAPIC pins (PCI GSIs).
	 */
	mp_ioapic_routing[idx].apic_id = mp_ioapics[idx].mpc_apicid;
	mp_ioapic_routing[idx].gsi_base = gsi_base;
	mp_ioapic_routing[idx].gsi_end = gsi_base + 
		io_apic_get_redir_entries(idx);

	printk("IOAPIC[%d]: apic_id %d, version %d, address 0x%lx, "
		"GSI %d-%d\n", idx, mp_ioapics[idx].mpc_apicid, 
		mp_ioapics[idx].mpc_apicver, mp_ioapics[idx].mpc_apicaddr,
		mp_ioapic_routing[idx].gsi_base,
		mp_ioapic_routing[idx].gsi_end);

	return;
}

void __init mp_override_legacy_irq (
	u8			bus_irq,
	u8			polarity, 
	u8			trigger, 
	u32			gsi)
{
	struct mpc_config_intsrc intsrc;
	int			ioapic = -1;
	int			pin = -1;

	/* 
	 * Convert 'gsi' to 'ioapic.pin'.
	 */
	ioapic = mp_find_ioapic(gsi);
	if (ioapic < 0)
		return;
	pin = gsi - mp_ioapic_routing[ioapic].gsi_base;

	/*
	 * TBD: This check is for faulty timer entries, where the override
	 *      erroneously sets the trigger to level, resulting in a HUGE 
	 *      increase of timer interrupts!
	 */
	if ((bus_irq == 0) && (trigger == 3))
		trigger = 1;

	intsrc.mpc_type = MP_INTSRC;
	intsrc.mpc_irqtype = mp_INT;
	intsrc.mpc_irqflag = (trigger << 2) | polarity;
	intsrc.mpc_srcbus = MP_ISA_BUS;
	intsrc.mpc_srcbusirq = bus_irq;				       /* IRQ */
	intsrc.mpc_dstapic = mp_ioapics[ioapic].mpc_apicid;	   /* APIC ID */
	intsrc.mpc_dstirq = pin;				    /* INTIN# */

	Dprintk("Int: type %d, pol %d, trig %d, bus %d, irq %d, %d-%d\n",
		intsrc.mpc_irqtype, intsrc.mpc_irqflag & 3, 
		(intsrc.mpc_irqflag >> 2) & 3, intsrc.mpc_srcbus, 
		intsrc.mpc_srcbusirq, intsrc.mpc_dstapic, intsrc.mpc_dstirq);

	mp_irqs[mp_irq_entries] = intsrc;
	if (++mp_irq_entries == MAX_IRQ_SOURCES)
		panic("Max # of irq sources exceeded!\n");

	return;
}

void __init mp_config_acpi_legacy_irqs (void)
{
	struct mpc_config_intsrc intsrc;
	int			i = 0;
	int			ioapic = -1;

	/* 
	 * Fabricate the legacy ISA bus (bus #31).
	 */
	mp_bus_id_to_type[MP_ISA_BUS] = MP_BUS_ISA;
	Dprintk("Bus #%d is ISA\n", MP_ISA_BUS);

	/*
	 * ES7000 has no legacy identity mappings
	 */
	if (es7000_plat)
		return;

	/* 
	 * Locate the IOAPIC that manages the ISA IRQs (0-15). 
	 */
	ioapic = mp_find_ioapic(0);
	if (ioapic < 0)
		return;

	intsrc.mpc_type = MP_INTSRC;
	intsrc.mpc_irqflag = 0;					/* Conforming */
	intsrc.mpc_srcbus = MP_ISA_BUS;
	intsrc.mpc_dstapic = mp_ioapics[ioapic].mpc_apicid;

	/* 
	 * Use the default configuration for the IRQs 0-15.  Unless
	 * overriden by (MADT) interrupt source override entries.
	 */
	for (i = 0; i < 16; i++) {
		int idx;

		for (idx = 0; idx < mp_irq_entries; idx++) {
			struct mpc_config_intsrc *irq = mp_irqs + idx;

			/* Do we already have a mapping for this ISA IRQ? */
			if (irq->mpc_srcbus == MP_ISA_BUS && irq->mpc_srcbusirq == i)
				break;

			/* Do we already have a mapping for this IOAPIC pin */
			if ((irq->mpc_dstapic == intsrc.mpc_dstapic) &&
				(irq->mpc_dstirq == i))
				break;
		}

		if (idx != mp_irq_entries) {
			printk(KERN_DEBUG "ACPI: IRQ%d used by override.\n", i);
			continue;			/* IRQ already used */
		}

		intsrc.mpc_irqtype = mp_INT;
		intsrc.mpc_srcbusirq = i;		   /* Identity mapped */
		intsrc.mpc_dstirq = i;

		Dprintk("Int: type %d, pol %d, trig %d, bus %d, irq %d, "
			"%d-%d\n", intsrc.mpc_irqtype, intsrc.mpc_irqflag & 3, 
			(intsrc.mpc_irqflag >> 2) & 3, intsrc.mpc_srcbus, 
			intsrc.mpc_srcbusirq, intsrc.mpc_dstapic, 
			intsrc.mpc_dstirq);

		mp_irqs[mp_irq_entries] = intsrc;
		if (++mp_irq_entries == MAX_IRQ_SOURCES)
			panic("Max # of irq sources exceeded!\n");
	}
}

#endif /*CONFIG_X86_IO_APIC && (CONFIG_ACPI_INTERPRETER || CONFIG_ACPI_BOOT)*/
#endif /*CONFIG_ACPI_BOOT*/