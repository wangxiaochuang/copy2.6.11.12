#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/acpi.h>
#include <acpi/acpi_bus.h>
#include <linux/dmi.h>

enum acpi_blacklist_predicates
{
        all_versions,
        less_than_or_equal,
        equal,
        greater_than_or_equal,
};

struct acpi_blacklist_item
{
        char            oem_id[7];
        char            oem_table_id[9];
        u32             oem_revision;
        acpi_table_type table;
        enum acpi_blacklist_predicates oem_revision_predicate;
        char            *reason;
        u32             is_critical_error;
};

/*
 * POLICY: If *anything* doesn't work, put it on the blacklist.
 *	   If they are critical errors, mark it critical, and abort driver load.
 */
static struct acpi_blacklist_item acpi_blacklist[] __initdata =
{
	/* Compaq Presario 1700 */
	{"PTLTD ", "  DSDT  ", 0x06040000, ACPI_DSDT, less_than_or_equal, "Multiple problems", 1},
	/* Sony FX120, FX140, FX150? */
	{"SONY  ", "U0      ", 0x20010313, ACPI_DSDT, less_than_or_equal, "ACPI driver problem", 1},
	/* Compaq Presario 800, Insyde BIOS */
	{"INT440", "SYSFexxx", 0x00001001, ACPI_DSDT, less_than_or_equal, "Does not use _REG to protect EC OpRegions", 1},
	/* IBM 600E - _ADR should return 7, but it returns 1 */
	{"IBM   ", "TP600E  ", 0x00000105, ACPI_DSDT, less_than_or_equal, "Incorrect _ADR", 1},
	{"ASUS\0\0", "P2B-S   ", 0, ACPI_DSDT, all_versions, "Bogus PCI routing", 1},

	{""}
};

#if	CONFIG_ACPI_BLACKLIST_YEAR
#error "CONFIG_ACPI_BLACKLIST_YEAR"
#else
static inline int blacklist_by_year(void) { return 0; }
#endif

int __init acpi_blacklisted(void) {
    int i = 0;
	int blacklisted = 0;
	struct acpi_table_header *table_header;

    while (acpi_blacklist[i].oem_id[0] != '\0') {
        if (acpi_get_table_header_early(acpi_blacklist[i].table, &table_header)) {
            i++;
            continue;
        }
        if (strncmp(acpi_blacklist[i].oem_id, table_header->oem_id, 6)) {
			i++;
			continue;
		}
        if (strncmp(acpi_blacklist[i].oem_table_id, table_header->oem_table_id, 8)) {
			i++;
			continue;
		}
        if ((acpi_blacklist[i].oem_revision_predicate == all_versions)
		    || (acpi_blacklist[i].oem_revision_predicate == less_than_or_equal
		        && table_header->oem_revision <= acpi_blacklist[i].oem_revision)
		    || (acpi_blacklist[i].oem_revision_predicate == greater_than_or_equal
		        && table_header->oem_revision >= acpi_blacklist[i].oem_revision)
		    || (acpi_blacklist[i].oem_revision_predicate == equal
		        && table_header->oem_revision == acpi_blacklist[i].oem_revision)) {

			printk(KERN_ERR PREFIX "Vendor \"%6.6s\" System \"%8.8s\" "
				"Revision 0x%x has a known ACPI BIOS problem.\n",
				acpi_blacklist[i].oem_id,
				acpi_blacklist[i].oem_table_id,
				acpi_blacklist[i].oem_revision);

			printk(KERN_ERR PREFIX "Reason: %s. This is a %s error\n",
				acpi_blacklist[i].reason,
				(acpi_blacklist[i].is_critical_error ? "non-recoverable" : "recoverable"));

			blacklisted = acpi_blacklist[i].is_critical_error;
			break;
		} else {
            i++;
        }
    }

    blacklisted += blacklist_by_year();

	return blacklisted;
}