#include <linux/config.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/irq.h>
#include <linux/errno.h>
#include <linux/acpi.h>
#include <linux/bootmem.h>

#define ACPI_MAX_TABLES		256

/* System Description Table (RSDT/XSDT) */
struct acpi_table_sdt {
	unsigned long		pa;
	enum acpi_table_id	id;
	unsigned long		size;
} __attribute__ ((packed));

static unsigned long		sdt_pa;		/* Physical Address */
static unsigned long		sdt_count;	/* Table count */

static struct acpi_table_sdt	sdt_entry[ACPI_MAX_TABLES];

static int
acpi_table_compute_checksum (
	void			*table_pointer,
	unsigned long		length) {

    u8			*p = (u8 *) table_pointer;
	unsigned long		remains = length;
	unsigned long		sum = 0;

    if (!p || !length)
		return -EINVAL;
    
    while (remains--)
        sum += *p++;
    
    return sum & 0xFF;
}

int __init acpi_table_parse ( enum acpi_table_id id, acpi_table_handler	handler) {
    return 0;
}

static int __init acpi_table_get_sdt(struct acpi_table_rsdp	*rsdp) {
    struct acpi_table_header *header = NULL;
    unsigned int i, id = 0;

    if (!rsdp)
        return -EINVAL;
    
    if ((rsdp->revision >= 2) && (((struct acpi20_table_rsdp *)rsdp)->xsdt_address)) {
        struct acpi_table_xsdt *mapped_xsdt = NULL;

        sdt_pa = ((struct acpi20_table_rsdp *)rsdp)->xsdt_address;
    }
    return 0;
}

int __init acpi_table_init (void) {
    struct acpi_table_rsdp *rsdp = NULL;
    unsigned long rsdp_phys = 0;
    int result = 0;

    rsdp_phys = acpi_find_rsdp();
    if (!rsdp_phys) {
		printk(KERN_ERR PREFIX "Unable to locate RSDP\n");
		return -ENODEV;
	}

    rsdp = (struct acpi_table_rsdp *) __va(rsdp_phys);
    if (!rsdp) {
		printk(KERN_WARNING PREFIX "Unable to map RSDP\n");
		return -ENODEV;
	}

    printk(KERN_DEBUG PREFIX "RSDP (v%3.3d %6.6s                                ) @ 0x%p\n",
		rsdp->revision, rsdp->oem_id, (void *) rsdp_phys);

    if (rsdp->revision < 2)
		result = acpi_table_compute_checksum(rsdp, sizeof(struct acpi_table_rsdp));
	else
		result = acpi_table_compute_checksum(rsdp, ((struct acpi20_table_rsdp *)rsdp)->length);

    if (result) {
		printk(KERN_WARNING "  >>> ERROR: Invalid checksum\n");
		return -ENODEV;
	}

    if (acpi_table_get_sdt(rsdp))
        return -ENODEV;

    return 0;
}