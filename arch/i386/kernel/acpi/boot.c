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

int __init acpi_boot_table_init(void) {
	int error;

    if (acpi_disabled && !acpi_ht)
        return 1;
    
    error = acpi_table_init();
    if (error) {
        disable_acpi();
        return error;
    }
    // .............. @todo
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