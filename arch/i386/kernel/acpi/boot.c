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
int acpi_skip_timer_override __initdata;

static int __init acpi_parse_sbf(unsigned long phys_addr, unsigned long size)
{
    return 0;
}

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
    return 0;
}