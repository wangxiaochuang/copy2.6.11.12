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

static char *acpi_table_signatures[ACPI_TABLE_COUNT] = {
	[ACPI_TABLE_UNKNOWN]	= "????",
	[ACPI_APIC]		= "APIC",
	[ACPI_BOOT]		= "BOOT",
	[ACPI_DBGP]		= "DBGP",
	[ACPI_DSDT]		= "DSDT",
	[ACPI_ECDT]		= "ECDT",
	[ACPI_ETDT]		= "ETDT",
	[ACPI_FADT]		= "FACP",
	[ACPI_FACS]		= "FACS",
	[ACPI_OEMX]		= "OEM",
	[ACPI_PSDT]		= "PSDT",
	[ACPI_SBST]		= "SBST",
	[ACPI_SLIT]		= "SLIT",
	[ACPI_SPCR]		= "SPCR",
	[ACPI_SRAT]		= "SRAT",
	[ACPI_SSDT]		= "SSDT",
	[ACPI_SPMI]		= "SPMI",
	[ACPI_HPET]		= "HPET",
	[ACPI_MCFG]		= "MCFG",
};

/* System Description Table (RSDT/XSDT) */
struct acpi_table_sdt {
	unsigned long		pa;
	enum acpi_table_id	id;
	unsigned long		size;
} __attribute__ ((packed));

static unsigned long		sdt_pa;		/* Physical Address */
static unsigned long		sdt_count;	/* Table count */

static struct acpi_table_sdt	sdt_entry[ACPI_MAX_TABLES];

void
acpi_table_print (
	struct acpi_table_header *header,
	unsigned long		phys_addr)
{
	char			*name = NULL;

	if (!header)
		return;

	/* Some table signatures aren't good table names */

	if (!strncmp((char *) &header->signature,
		acpi_table_signatures[ACPI_APIC],
		sizeof(header->signature))) {
		name = "MADT";
	}
	else if (!strncmp((char *) &header->signature,
		acpi_table_signatures[ACPI_FADT],
		sizeof(header->signature))) {
		name = "FADT";
	}
	else
		name = header->signature;

	printk(KERN_DEBUG PREFIX "%.4s (v%3.3d %6.6s %8.8s 0x%08x %.4s 0x%08x) @ 0x%p\n",
		name, header->revision, header->oem_id,
		header->oem_table_id, header->oem_revision,
		header->asl_compiler_id, header->asl_compiler_revision,
		(void *) phys_addr);
}

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

/*
 * acpi_get_table_header_early()
 * for acpi_blacklisted(), acpi_table_get_sdt()
 */
int __init
acpi_get_table_header_early (
	enum acpi_table_id	id,
	struct acpi_table_header **header)
{
	unsigned int i;
	enum acpi_table_id temp_id;

    /* DSDT is different from the rest */
	if (id == ACPI_DSDT)
		temp_id = ACPI_FADT;
	else
		temp_id = id;
    
    for (i = 0; i < sdt_count; i++) {
		if (sdt_entry[i].id != temp_id)
			continue;
        *header = (void *)
            __acpi_map_table(sdt_entry[i].pa, sdt_entry[i].size);
        if (!*header) {
			printk(KERN_WARNING PREFIX "Unable to map %s\n",
			       acpi_table_signatures[temp_id]);
			return -ENODEV;
		}
		break;
    }

    if (!*header) {
		printk(KERN_WARNING PREFIX "%s not present\n",
		       acpi_table_signatures[id]);
		return -ENODEV;
	}

    /* Map the DSDT header via the pointer in the FADT */
    if (id == ACPI_DSDT) {
        struct fadt_descriptor_rev2 *fadt = (struct fadt_descriptor_rev2 *) *header;

        if (fadt->revision == 3 && fadt->Xdsdt) {
			*header = (void *) __acpi_map_table(fadt->Xdsdt,
					sizeof(struct acpi_table_header));
		} else if (fadt->V1_dsdt) {
			*header = (void *) __acpi_map_table(fadt->V1_dsdt,
					sizeof(struct acpi_table_header));
		} else
			*header = NULL;

		if (!*header) {
			printk(KERN_WARNING PREFIX "Unable to map DSDT\n");
			return -ENODEV;
		}
    }
    return 0;
}

int __init acpi_table_parse ( enum acpi_table_id id, acpi_table_handler	handler) {
	int			count = 0;
	unsigned int		i = 0;

	if (!handler)
		return -EINVAL;

	for (i = 0; i < sdt_count; i++) {
		if (sdt_entry[i].id != id)
			continue;
		count++;
		// 表里出现两次就出错
		if (count == 1)
			handler(sdt_entry[i].pa, sdt_entry[i].size);
		else
			printk(KERN_WARNING PREFIX "%d duplicate %s table ignored.\n",
				count, acpi_table_signatures[id]);
	}

	return count;
}

static int __init acpi_table_get_sdt(struct acpi_table_rsdp	*rsdp) {
    struct acpi_table_header *header = NULL;
    unsigned int i, id = 0;

    if (!rsdp)
        return -EINVAL;
    
    // 先检查XSDT
    if ((rsdp->revision >= 2) && (((struct acpi20_table_rsdp *)rsdp)->xsdt_address)) {
        struct acpi_table_xsdt *mapped_xsdt = NULL;

        sdt_pa = ((struct acpi20_table_rsdp *)rsdp)->xsdt_address;

        /* map in just the header */
		header = (struct acpi_table_header *)
			__acpi_map_table(sdt_pa, sizeof(struct acpi_table_header));
        if (!header) {
			printk(KERN_WARNING PREFIX "Unable to map XSDT header\n");
			return -ENODEV;
		}

        /* remap in the entire table before processing */
		mapped_xsdt = (struct acpi_table_xsdt *)
			__acpi_map_table(sdt_pa, header->length);
        if (!mapped_xsdt) {
			printk(KERN_WARNING PREFIX "Unable to map XSDT\n");
			return -ENODEV;
		}
		header = &mapped_xsdt->header;

        if (strncmp(header->signature, "XSDT", 4)) {
			printk(KERN_WARNING PREFIX "XSDT signature incorrect\n");
			return -ENODEV;
		}

        if (acpi_table_compute_checksum(header, header->length)) {
			printk(KERN_WARNING PREFIX "Invalid XSDT checksum\n");
			return -ENODEV;
		}

        // 每一个entry是8个字节，每一个entry里面有不同功能的表地址，比如apic的配置
        sdt_count = (header->length - sizeof(struct acpi_table_header)) >> 3;
		if (sdt_count > ACPI_MAX_TABLES) {
			printk(KERN_WARNING PREFIX "Truncated %lu XSDT entries\n",
				(sdt_count - ACPI_MAX_TABLES));
			sdt_count = ACPI_MAX_TABLES;
		}

        // 这里仅仅是把表项的所有物理地址设置到了sdt_entry表里，后续继续设置
        for (i = 0; i < sdt_count; i++)
			sdt_entry[i].pa = (unsigned long) mapped_xsdt->entry[i];
    } else if (rsdp->rsdt_address) {
        // 找不到XSDT就找RSDT
		struct acpi_table_rsdt	*mapped_rsdt = NULL;

		sdt_pa = rsdp->rsdt_address;

		/* map in just the header */
		header = (struct acpi_table_header *)
			__acpi_map_table(sdt_pa, sizeof(struct acpi_table_header));
		if (!header) {
			printk(KERN_WARNING PREFIX "Unable to map RSDT header\n");
			return -ENODEV;
		}

		/* remap in the entire table before processing */
		mapped_rsdt = (struct acpi_table_rsdt *)
			__acpi_map_table(sdt_pa, header->length);
		if (!mapped_rsdt) {
			printk(KERN_WARNING PREFIX "Unable to map RSDT\n");
			return -ENODEV;
		}
		header = &mapped_rsdt->header;

		if (strncmp(header->signature, "RSDT", 4)) {
			printk(KERN_WARNING PREFIX "RSDT signature incorrect\n");
			return -ENODEV;
		}

		if (acpi_table_compute_checksum(header, header->length)) {
			printk(KERN_WARNING PREFIX "Invalid RSDT checksum\n");
			return -ENODEV;
		}

		sdt_count = (header->length - sizeof(struct acpi_table_header)) >> 2;
		if (sdt_count > ACPI_MAX_TABLES) {
			printk(KERN_WARNING PREFIX "Truncated %lu RSDT entries\n",
				(sdt_count - ACPI_MAX_TABLES));
			sdt_count = ACPI_MAX_TABLES;
		}

		for (i = 0; i < sdt_count; i++)
			sdt_entry[i].pa = (unsigned long) mapped_rsdt->entry[i];
    } else {
        printk(KERN_WARNING PREFIX "No System Description Table (RSDT/XSDT) specified in RSDP\n");
		return -ENODEV;
    }
    acpi_table_print(header, sdt_pa);
	// ACPI_FADT ACPI_APIC ACPI_HPET
    for (i = 0; i < sdt_count; i++) {
        /* map in just the header */
		header = (struct acpi_table_header *)
			__acpi_map_table(sdt_entry[i].pa,
				sizeof(struct acpi_table_header));
		if (!header)
			continue;
        
        /* remap in the entire table before processing */
		header = (struct acpi_table_header *)
			__acpi_map_table(sdt_entry[i].pa,
				header->length);
		if (!header)
			continue;
        
        acpi_table_print(header, sdt_entry[i].pa);

        if (acpi_table_compute_checksum(header, header->length)) {
			printk(KERN_WARNING "  >>> ERROR: Invalid checksum\n");
			continue;
		}

        sdt_entry[i].size = header->length;

        for (id = 0; id < ACPI_TABLE_COUNT; id++) {
            if (!strncmp((char *) &header->signature,
				acpi_table_signatures[id],
				sizeof(header->signature))) {
				sdt_entry[i].id = id;
			}
        }
    }

    /* 
	 * The DSDT is *not* in the RSDT (why not? no idea.) but we want
	 * to print its info, because this is what people usually blacklist
	 * against. Unfortunately, we don't know the phys_addr, so just
	 * print 0. Maybe no one will notice.
	 */
	if(!acpi_get_table_header_early(ACPI_DSDT, &header))
		acpi_table_print(header, 0);

    return 0;
}

/*
 * 找到RSDP、SDT/XSDT，最后初始化sdt_entry[]

RSDP（acpi表以RSDP(Root System Descriptor Pointer Table)为入口）
    - RSDT（为了兼容ACPI1.0而存在）
    - XSDT（用于取代RSDT的功能）
        - EACP
            - EACS
            - DSDT
                - SSDT
            - Gpx_BLK
        - Entry
 */
int __init acpi_table_init (void) {
    struct acpi_table_rsdp *rsdp = NULL;
    unsigned long rsdp_phys = 0;
    int result = 0;

    // 通过acpi来查找根描述符表的物理地址
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

    // 根据rsdp找到sdt表
    if (acpi_table_get_sdt(rsdp))
        return -ENODEV;

    return 0;
}