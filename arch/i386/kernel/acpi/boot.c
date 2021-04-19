#include <linux/init.h>
#include <linux/config.h>
#include <linux/acpi.h>
#include <linux/efi.h>
#include <linux/irq.h>
#include <linux/module.h>

#include <asm/pgtable.h>
#include <asm/io_apic.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/mpspec.h>

#ifdef	CONFIG_X86_64

#error "CONFIG_X86_64"

#else	/* X86 */

#ifdef	CONFIG_X86_LOCAL_APIC
#include <mach_apic.h>
#include <mach_mpparse.h>
#endif	/* CONFIG_X86_LOCAL_APIC */

#endif	/* X86 */

#define BAD_MADT_ENTRY(entry, end) (					    \
		(!entry) || (unsigned long)entry + sizeof(*entry) > end ||  \
		((acpi_table_entry_header *)entry)->length != sizeof(*entry))

#ifdef CONFIG_ACPI_PCI
int acpi_noirq __initdata;	/* skip ACPI IRQ initialization */
int acpi_pci_disabled __initdata; /* skip ACPI PCI scan and IRQ initialization */
#else
int acpi_noirq __initdata = 1;
int acpi_pci_disabled __initdata = 1;
#endif
int acpi_ht __initdata = 1;	/* enable HT */

int acpi_lapic;
int acpi_ioapic;
int acpi_strict;
EXPORT_SYMBOL(acpi_strict);

acpi_interrupt_flags acpi_sci_flags __initdata;
int acpi_sci_override_gsi __initdata;
int acpi_skip_timer_override __initdata;

#ifdef CONFIG_X86_LOCAL_APIC
static u64 acpi_lapic_addr __initdata = APIC_DEFAULT_PHYS_BASE;
#endif

#define MAX_MADT_ENTRIES	256
u8 x86_acpiid_to_apicid[MAX_MADT_ENTRIES] =
			{ [0 ... MAX_MADT_ENTRIES-1] = 0xff };
EXPORT_SYMBOL(x86_acpiid_to_apicid);

/* --------------------------------------------------------------------------
                              Boot-time Configuration
   -------------------------------------------------------------------------- */

/*
 * The default interrupt routing model is PIC (8259).  This gets
 * overriden if IOAPICs are enumerated (below).
 */
enum acpi_irq_model_id		acpi_irq_model = ACPI_IRQ_MODEL_PIC;

#ifdef	CONFIG_X86_64
#error "CONFIG_X86_64"
#else
char *__acpi_map_table(unsigned long phys, unsigned long size)
{
	unsigned long base, offset, mapped_size;
	int idx;

    // acpi在8M内直接返回虚拟地址
    if (phys + size < 8*1024*1024) 
		return __va(phys);
    
    offset = phys & (PAGE_SIZE - 1);
    mapped_size = PAGE_SIZE - offset;
    set_fixmap(FIX_ACPI_END, phys);
    base = fix_to_virt(FIX_ACPI_END);

    /*
	 * Most cases can be covered by the below.
	 */
	idx = FIX_ACPI_END;
    while (mapped_size < size) {
        if (--idx < FIX_ACPI_BEGIN)
            return NULL;
        phys += PAGE_SIZE;
        set_fixmap(idx, phys);
        mapped_size += PAGE_SIZE;
    }
    return ((unsigned char *) base + offset);
}
#endif

#ifdef CONFIG_PCI_MMCONFIG
static int __init acpi_parse_mcfg(unsigned long phys_addr, unsigned long size)
{
    struct acpi_table_mcfg *mcfg;

	if (!phys_addr || !size)
		return -EINVAL;

	mcfg = (struct acpi_table_mcfg *) __acpi_map_table(phys_addr, size);
	if (!mcfg) {
		printk(KERN_WARNING PREFIX "Unable to map MCFG\n");
		return -ENODEV;
	}

	if (mcfg->base_reserved) {
		printk(KERN_ERR PREFIX "MMCONFIG not in low 4GB of memory\n");
		return -ENODEV;
	}

	pci_mmcfg_base_addr = mcfg->base_address;

	return 0;
}
#else
#define	acpi_parse_mcfg NULL
#endif /* !CONFIG_PCI_MMCONFIG */

#ifdef CONFIG_X86_LOCAL_APIC
static int __init acpi_parse_madt ( unsigned long phys_addr, unsigned long size) {
	struct acpi_table_madt	*madt = NULL;

	if (!phys_addr || !size)
		return -EINVAL;

	madt = (struct acpi_table_madt *) __acpi_map_table(phys_addr, size);
	if (!madt) {
		printk(KERN_WARNING PREFIX "Unable to map MADT\n");
		return -ENODEV;
	}

	if (madt->lapic_address) {
		acpi_lapic_addr = (u64) madt->lapic_address;

		printk(KERN_DEBUG PREFIX "Local APIC address 0x%08x\n",
			madt->lapic_address);
	}

	acpi_madt_oem_check(madt->header.oem_id, madt->header.oem_table_id);

    return 0;
}

static int __init
acpi_parse_lapic (
	acpi_table_entry_header *header, const unsigned long end)
{
    struct acpi_table_lapic	*processor = NULL;

	processor = (struct acpi_table_lapic*) header;

	if (BAD_MADT_ENTRY(processor, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	/* no utility in registering a disabled processor */
	if (processor->flags.enabled == 0)
		return 0;

	x86_acpiid_to_apicid[processor->acpi_id] = processor->id;

	mp_register_lapic (
		processor->id,					   /* APIC ID */
		processor->flags.enabled);			  /* Enabled? */

	return 0;
}

static int __init
acpi_parse_lapic_addr_ovr (
	acpi_table_entry_header *header, const unsigned long end)
{
	struct acpi_table_lapic_addr_ovr *lapic_addr_ovr = NULL;

	lapic_addr_ovr = (struct acpi_table_lapic_addr_ovr*) header;

	if (BAD_MADT_ENTRY(lapic_addr_ovr, end))
		return -EINVAL;

	acpi_lapic_addr = lapic_addr_ovr->address;

	return 0;
}

static int __init
acpi_parse_lapic_nmi (
	acpi_table_entry_header *header, const unsigned long end)
{
	struct acpi_table_lapic_nmi *lapic_nmi = NULL;

	lapic_nmi = (struct acpi_table_lapic_nmi*) header;

	if (BAD_MADT_ENTRY(lapic_nmi, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	if (lapic_nmi->lint != 1)
		printk(KERN_WARNING PREFIX "NMI not connected to LINT 1!\n");

	return 0;
}
#endif /*CONFIG_X86_LOCAL_APIC*/

#if defined(CONFIG_X86_IO_APIC) && defined(CONFIG_ACPI_INTERPRETER)

static int __init
acpi_parse_ioapic (
	acpi_table_entry_header *header, const unsigned long end)
{
	struct acpi_table_ioapic *ioapic = NULL;

	ioapic = (struct acpi_table_ioapic*) header;

	if (BAD_MADT_ENTRY(ioapic, end))
		return -EINVAL;
 
	acpi_table_print_madt_entry(header);

	mp_register_ioapic (
		ioapic->id,
		ioapic->address,
		ioapic->global_irq_base);
 
	return 0;
}

/*
 * Parse Interrupt Source Override for the ACPI SCI
 */
static void
acpi_sci_ioapic_setup(u32 gsi, u16 polarity, u16 trigger) {
    if (trigger == 0)	/* compatible SCI trigger is level */
		trigger = 3;

	if (polarity == 0)	/* compatible SCI polarity is low */
		polarity = 3;

	/* Command-line over-ride via acpi_sci= */
	if (acpi_sci_flags.trigger)
		trigger = acpi_sci_flags.trigger;

	if (acpi_sci_flags.polarity)
		polarity = acpi_sci_flags.polarity;

	/*
 	 * mp_config_acpi_legacy_irqs() already setup IRQs < 16
	 * If GSI is < 16, this will update its flags,
	 * else it will create a new mp_irqs[] entry.
	 */
	mp_override_legacy_irq(gsi, polarity, trigger, gsi);

	/*
	 * stash over-ride to indicate we've been here
	 * and for later update of acpi_fadt
	 */
	acpi_sci_override_gsi = gsi;
	return;
}

static int __init
acpi_parse_int_src_ovr (
	acpi_table_entry_header *header, const unsigned long end)
{
    struct acpi_table_int_src_ovr *intsrc = NULL;

	intsrc = (struct acpi_table_int_src_ovr*) header;

	if (BAD_MADT_ENTRY(intsrc, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	if (intsrc->bus_irq == acpi_fadt.sci_int) {
		acpi_sci_ioapic_setup(intsrc->global_irq,
			intsrc->flags.polarity, intsrc->flags.trigger);
		return 0;
	}

	if (acpi_skip_timer_override &&
		intsrc->bus_irq == 0 && intsrc->global_irq == 2) {
			printk(PREFIX "BIOS IRQ0 pin2 override ignored.\n");
			return 0;
	}

	mp_override_legacy_irq (
		intsrc->bus_irq,
		intsrc->flags.polarity,
		intsrc->flags.trigger,
		intsrc->global_irq);

	return 0;
}

static int __init
acpi_parse_nmi_src (
	acpi_table_entry_header *header, const unsigned long end)
{
	struct acpi_table_nmi_src *nmi_src = NULL;

	nmi_src = (struct acpi_table_nmi_src*) header;

	if (BAD_MADT_ENTRY(nmi_src, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	/* TBD: Support nimsrc entries? */

	return 0;
}

#endif /* CONFIG_X86_IO_APIC */

#ifdef	CONFIG_ACPI_BUS
#endif /* CONFIG_ACPI_BUS */

static unsigned long __init
acpi_scan_rsdp (
	unsigned long		start,
	unsigned long		length) {
    
    unsigned long offset = 0;
    unsigned long sig_len = sizeof("RSD PTR ") - 1;

    for (offset = 0; offset < length; offset += 16) {
        if (strncmp((char *) (start + offset), "RSD PTR ", sig_len))
            continue;
        return start + offset;
    }
    return 0;
}


static int __init acpi_parse_sbf(unsigned long phys_addr, unsigned long size)
{
    struct acpi_table_sbf *sb;

	if (!phys_addr || !size)
	return -EINVAL;

	sb = (struct acpi_table_sbf *) __acpi_map_table(phys_addr, size);
	if (!sb) {
		printk(KERN_WARNING PREFIX "Unable to map SBF\n");
		return -ENODEV;
	}

	sbf_port = sb->sbf_cmos; /* Save CMOS port */
    return 0;
}

#ifdef CONFIG_HPET_TIMER
static int __init acpi_parse_hpet(unsigned long phys, unsigned long size) {
    struct acpi_table_hpet *hpet_tbl;

	if (!phys || !size)
		return -EINVAL;

	hpet_tbl = (struct acpi_table_hpet *) __acpi_map_table(phys, size);
	if (!hpet_tbl) {
		printk(KERN_WARNING PREFIX "Unable to map HPET\n");
		return -ENODEV;
	}

    if (hpet_tbl->addr.space_id != ACPI_SPACE_MEM) {
		printk(KERN_WARNING PREFIX "HPET timers must be located in "
		       "memory.\n");
		return -1;
	}

#ifdef	CONFIG_X86_64
#error "CONFIG_X86_64"
#else /* X86 */
    {
        extern unsigned long hpet_address;

		hpet_address = hpet_tbl->addr.addrl;
		printk(KERN_INFO PREFIX "HPET id: %#x base: %#lx\n",
			hpet_tbl->id, hpet_address);
    }
#endif
    return 0;
}
#else
#define	acpi_parse_hpet	NULL
#endif

static int __init acpi_parse_fadt(unsigned long phys, unsigned long size) {
    struct fadt_descriptor_rev2 *fadt = NULL;

	fadt = (struct fadt_descriptor_rev2*) __acpi_map_table(phys,size);
	if(!fadt) {
		printk(KERN_WARNING PREFIX "Unable to map FADT\n");
		return 0;
	}
#ifdef	CONFIG_ACPI_INTERPRETER
	/* initialize sci_int early for INT_SRC_OVR MADT parsing */
	acpi_fadt.sci_int = fadt->sci_int;
#endif

#ifdef CONFIG_X86_PM_TIMER
#error "CONFIG_X86_PM_TIMER"
#endif
    return 0;
}



unsigned long __init acpi_find_rsdp (void) {
    unsigned long rsdp_phys = 0;

    if (efi_enabled) {
        mypanic("efi enabled");
    }
    rsdp_phys = acpi_scan_rsdp(0, 0x400);
    if (!rsdp_phys)
        rsdp_phys = acpi_scan_rsdp(0xE0000, 0xFFFFF);

    return rsdp_phys;
}

#ifdef	CONFIG_X86_LOCAL_APIC
/*
 * Parse LAPIC entries in MADT
 * returns 0 on success, < 0 on error
 */
static int __init
acpi_parse_madt_lapic_entries(void)
{
	int count;

	/* 
	 * Note that the LAPIC address is obtained from the MADT (32-bit value)
	 * and (optionally) overriden by a LAPIC_ADDR_OVR entry (64-bit value).
	 */

	count = acpi_table_parse_madt(ACPI_MADT_LAPIC_ADDR_OVR, acpi_parse_lapic_addr_ovr, 0);
	if (count < 0) {
		printk(KERN_ERR PREFIX "Error parsing LAPIC address override entry\n");
		return count;
	}

    mp_register_lapic_address(acpi_lapic_addr);

    count = acpi_table_parse_madt(ACPI_MADT_LAPIC, acpi_parse_lapic,
				       MAX_APICS);
	if (!count) { 
		printk(KERN_ERR PREFIX "No LAPIC entries present\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return -ENODEV;
	} else if (count < 0) {
		printk(KERN_ERR PREFIX "Error parsing LAPIC entry\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return count;
	}

    count = acpi_table_parse_madt(ACPI_MADT_LAPIC_NMI, acpi_parse_lapic_nmi, 0);
	if (count < 0) {
		printk(KERN_ERR PREFIX "Error parsing LAPIC NMI entry\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return count;
	}

    return 0;
}
#endif /* CONFIG_X86_LOCAL_APIC */

#if defined(CONFIG_X86_IO_APIC) && defined(CONFIG_ACPI_INTERPRETER)
/*
 * Parse IOAPIC related entries in MADT
 * returns 0 on success, < 0 on error
 */
static int __init
acpi_parse_madt_ioapic_entries(void)
{
	int count;

	if (acpi_disabled || acpi_noirq) {
		return -ENODEV;
	}

	/*
 	 * if "noapic" boot option, don't look for IO-APICs
	 */
	if (skip_ioapic_setup) {
		printk(KERN_INFO PREFIX "Skipping IOAPIC probe "
			"due to 'noapic' option.\n");
		return -ENODEV;
	}

	count = acpi_table_parse_madt(ACPI_MADT_IOAPIC, acpi_parse_ioapic, MAX_IO_APICS);
	if (!count) {
		printk(KERN_ERR PREFIX "No IOAPIC entries present\n");
		return -ENODEV;
	} else if (count < 0) {
		printk(KERN_ERR PREFIX "Error parsing IOAPIC entry\n");
		return count;
	}

	count = acpi_table_parse_madt(ACPI_MADT_INT_SRC_OVR, acpi_parse_int_src_ovr, NR_IRQ_VECTORS);
	if (count < 0) {
		printk(KERN_ERR PREFIX "Error parsing interrupt source overrides entry\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return count;
	}

	/*
	 * If BIOS did not supply an INT_SRC_OVR for the SCI
	 * pretend we got one so we can set the SCI flags.
	 */
	if (!acpi_sci_override_gsi)
		acpi_sci_ioapic_setup(acpi_fadt.sci_int, 0, 0);

	/* Fill in identity legacy mapings where no override */
	mp_config_acpi_legacy_irqs();

	count = acpi_table_parse_madt(ACPI_MADT_NMI_SRC, acpi_parse_nmi_src, NR_IRQ_VECTORS);
	if (count < 0) {
		printk(KERN_ERR PREFIX "Error parsing NMI SRC entry\n");
		/* TBD: Cleanup to allow fallback to MPS */
		return count;
	}
    return 0;
}
#endif

static void __init acpi_process_madt(void) {
#ifdef CONFIG_X86_LOCAL_APIC
    int count, error;

	count = acpi_table_parse(ACPI_APIC, acpi_parse_madt);
	if (count >= 1) {
        /*
		 * Parse MADT LAPIC entries
		 */
		error = acpi_parse_madt_lapic_entries();
		if (!error) {
			acpi_lapic = 1;

			/*
			 * Parse MADT IO-APIC entries
			 */
			error = acpi_parse_madt_ioapic_entries();
			if (!error) {
				acpi_irq_model = ACPI_IRQ_MODEL_IOAPIC;
				acpi_irq_balance_set(NULL);
				acpi_ioapic = 1;

				smp_found_config = 1;
				clustered_apic_check();
			}
		}
		if (error == -EINVAL) {
			/*
			 * Dell Precision Workstation 410, 610 come here.
			 */
			printk(KERN_ERR PREFIX "Invalid BIOS MADT, disabling ACPI\n");
			disable_acpi();
		}
    }
#endif
    return;
}

int __init acpi_boot_table_init(void) {
	int error;

    if (acpi_disabled && !acpi_ht)
        return 1;
    
    error = acpi_table_init();
    if (error) {
        disable_acpi();
        return error;
    }

// #ifdef __i386__
    check_acpi_pci();
// #endif

    acpi_table_parse(ACPI_BOOT, acpi_parse_sbf);

    /*
	 * blacklist may disable ACPI entirely
	 */
	error = acpi_blacklisted();
    if (error) {
        mypanic("acpi_blacklisted error");
    }

    return 0;
}

int __init acpi_boot_init(void)
{
	/*
	 * If acpi_disabled, bail out
	 * One exception: acpi=ht continues far enough to enumerate LAPICs
	 */
	if (acpi_disabled && !acpi_ht)
		 return 1;

	// qemu 没有BOOT
    acpi_table_parse(ACPI_BOOT, acpi_parse_sbf);

	/*
	 * set sci_int and PM timer address
	 */
	acpi_table_parse(ACPI_FADT, acpi_parse_fadt);

	/*
	 * Process the Multiple APIC Description Table (MADT), if present
	 */
	acpi_process_madt();

	acpi_table_parse(ACPI_HPET, acpi_parse_hpet);
	acpi_table_parse(ACPI_MCFG, acpi_parse_mcfg);

    return 0;
}