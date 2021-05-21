#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/ioport.h>
#include <linux/acpi.h>
#include <linux/apm_bios.h>
#include <linux/initrd.h>
#include <linux/bootmem.h>
#include <linux/seq_file.h>
#include <linux/console.h>
#include <linux/mca.h>
#include <linux/root_dev.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/efi.h>
#include <linux/init.h>
#include <linux/edd.h>
#include <video/edid.h>
#include <asm/e820.h>
#include <asm/mpspec.h>
#include <asm/setup.h>
#include <asm/arch_hooks.h>
#include <asm/sections.h>
#include <asm/io_apic.h>
#include <asm/ist.h>
#include <asm/io.h>
#include "setup_arch_pre.h"
#include <bios_ebda.h>

unsigned long init_pg_tables_end __initdata = ~0UL;

extern void mcheck_init(struct cpuinfo_x86 *c);

int disable_pse __initdata = 0;

#ifdef CONFIG_EFI
int efi_enabled = 0;
EXPORT_SYMBOL(efi_enabled);
#endif

/* cpu data as detected by the assembly code in head.S */
struct cpuinfo_x86 new_cpu_data __initdata = { 0, 0, 0, 0, -1, 1, 0, 0, -1 };
/* common cpu data for all cpus */
struct cpuinfo_x86 boot_cpu_data = { 0, 0, 0, 0, -1, 1, 0, 0, -1 };

unsigned long mmu_cr4_features;
EXPORT_SYMBOL_GPL(mmu_cr4_features);

#ifdef	CONFIG_ACPI_INTERPRETER
	int acpi_disabled = 0;
#else
#error "CONFIG_ACPI_INTERPRETER"
#endif
EXPORT_SYMBOL(acpi_disabled);

#ifdef	CONFIG_ACPI_BOOT
int __initdata acpi_force = 0;
extern acpi_interrupt_flags	acpi_sci_flags;
#endif

/* for MCA, but anyone else can use it if they want */
unsigned int machine_id;
unsigned int machine_submodel_id;
unsigned int BIOS_revision;
unsigned int mca_pentium_flag;

/* For PCI or other memory-mapped resources */
unsigned long pci_mem_start = 0x10000000;

/* Boot loader ID as an integer, for the benefit of proc_dointvec */
int bootloader_type;

/* user-defined highmem size */
static unsigned int highmem_pages = -1;

/*
 * Setup options
 */
struct drive_info_struct { char dummy[32]; } drive_info;
struct screen_info screen_info;
struct apm_info apm_info;
struct sys_desc_table_struct {
	unsigned short length;
	unsigned char table[0];
};
struct edid_info edid_info;
struct ist_info ist_info;
struct e820map e820;

unsigned char aux_device_present;

extern void early_cpu_init(void);
extern void dmi_scan_machine(void);
extern int root_mountflags;

unsigned long saved_videomode;

static char command_line[COMMAND_LINE_SIZE];

unsigned char __initdata boot_params[PARAM_SIZE];

static struct resource data_resource = {
	.name	= "Kernel data",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

static struct resource code_resource = {
	.name	= "Kernel code",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

static struct resource system_rom_resource = {
	.name	= "System ROM",
	.start	= 0xf0000,
	.end	= 0xfffff,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
};

static struct resource extension_rom_resource = {
	.name	= "Extension ROM",
	.start	= 0xe0000,
	.end	= 0xeffff,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
};

static struct resource adapter_rom_resources[] = { {
	.name 	= "Adapter ROM",
	.start	= 0xc8000,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
}, {
	.name 	= "Adapter ROM",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
}, {
	.name 	= "Adapter ROM",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
}, {
	.name 	= "Adapter ROM",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
}, {
	.name 	= "Adapter ROM",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
}, {
	.name 	= "Adapter ROM",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
} };

#define ADAPTER_ROM_RESOURCES \
	(sizeof adapter_rom_resources / sizeof adapter_rom_resources[0])

static struct resource video_rom_resource = {
	.name 	= "Video ROM",
	.start	= 0xc0000,
	.end	= 0xc7fff,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
};

static struct resource video_ram_resource = {
	.name	= "Video RAM area",
	.start	= 0xa0000,
	.end	= 0xbffff,
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

static struct resource standard_io_resources[] = { {
	.name	= "dma1",
	.start	= 0x0000,
	.end	= 0x001f,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name	= "pic1",
	.start	= 0x0020,
	.end	= 0x0021,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name   = "timer0",
	.start	= 0x0040,
	.end    = 0x0043,
	.flags  = IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name   = "timer1",
	.start  = 0x0050,
	.end    = 0x0053,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name	= "keyboard",
	.start	= 0x0060,
	.end	= 0x006f,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name	= "dma page reg",
	.start	= 0x0080,
	.end	= 0x008f,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name	= "pic2",
	.start	= 0x00a0,
	.end	= 0x00a1,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name	= "dma2",
	.start	= 0x00c0,
	.end	= 0x00df,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name	= "fpu",
	.start	= 0x00f0,
	.end	= 0x00ff,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
} };

#define STANDARD_IO_RESOURCES \
	(sizeof standard_io_resources / sizeof standard_io_resources[0])

#define romsignature(x) (*(unsigned short *)(x) == 0xaa55)

static int __init romchecksum(unsigned char *rom, unsigned long length) {
	unsigned char *p, sum = 0;

	for (p = rom; p < rom + length; p++)
		sum += *p;
	return sum == 0;
}

static void __init probe_roms(void) {
	unsigned long start, length, upper;
	unsigned char *rom;
	int	      i;

	/* video rom */
	upper = adapter_rom_resources[0].start;	// 0xc8000
	for (start = video_rom_resource.start; start < upper; start += 2048) {
		rom = isa_bus_to_virt(start);
		if (!romsignature(rom))
			continue;

		video_rom_resource.start = start;
		length = rom[2] * 512;
		if (length && romchecksum(rom, length))
			video_rom_resource.end = start + length - 1;

		request_resource(&iomem_resource, &video_rom_resource);
		break;
	}

	start = (video_rom_resource.end + 1 + 2047) & ~2047UL;
	if (start < upper)
		start = upper;

	/* system rom */
	request_resource(&iomem_resource, &system_rom_resource);
	upper = system_rom_resource.start;

	/* check for extension rom (ignore length byte!) */
	rom = isa_bus_to_virt(extension_rom_resource.start);	
	if (romsignature(rom)) {
		length = extension_rom_resource.end - extension_rom_resource.start + 1;
		if (romchecksum(rom, length)) {
			request_resource(&iomem_resource, &extension_rom_resource);
			upper = extension_rom_resource.start;
		}
	}

	/* check for adapter roms on 2k boundaries */
	for (i = 0; i < ADAPTER_ROM_RESOURCES && start < upper; start += 2048) {
		rom = isa_bus_to_virt(start);
		if (!romsignature(rom))
			continue;
		length = rom[2] * 512;
		/* but accept any length that fits if checksum okay */
		if (!length || start + length > upper || !romchecksum(rom, length))
			continue;

		adapter_rom_resources[i].start = start;
		adapter_rom_resources[i].end = start + length - 1;
		request_resource(&iomem_resource, &adapter_rom_resources[i]);

		start = adapter_rom_resources[i++].end & ~2047UL;
	}
}

static void __init limit_regions(unsigned long long size) {
	unsigned long long current_addr = 0;
	int i;
	if (efi_enabled) {
		mypanic("efi_enabled");
	}
	for (i = 0; i < e820.nr_map; i++) {
		if (e820.map[i].type == E820_RAM) {
			current_addr = e820.map[i].addr + e820.map[i].size;
			e820.map[i].size -= current_addr-size;
			e820.nr_map = i + 1;
			return;
		}
	}
}

static void __init add_memory_region(unsigned long long start,
                                  unsigned long long size, int type)
{
	int x;
	if (!efi_enabled) {
		x = e820.nr_map;
		if (x == E820MAX) {
		    printk(KERN_ERR "Ooops! Too many entries in the memory map!\n");
		    return;
		}
		e820.map[x].addr = start;
		e820.map[x].size = size;
		e820.map[x].type = type;
		e820.nr_map++;
	}
}

static void __init print_memory_map(char *who) {
	int i;

	for (i = 0; i < e820.nr_map; i++) {
		printk(" %s: %016Lx - %016Lx ", who,
			e820.map[i].addr,
			e820.map[i].addr + e820.map[i].size);
		switch (e820.map[i].type) {
		case E820_RAM:	printk("(usable)\n");
				break;
		case E820_RESERVED:
				printk("(reserved)\n");
				break;
		case E820_ACPI:
				printk("(ACPI data)\n");
				break;
		case E820_NVS:
				printk("(ACPI NVS)\n");
				break;
		default:	printk("type %lu\n", e820.map[i].type);
				break;
		}
	}
}

struct change_member {
	struct e820entry *pbios; /* pointer to original bios entry */
	unsigned long long addr; /* address for this change point */
};
struct change_member change_point_list[2*E820MAX] __initdata;
struct change_member *change_point[2*E820MAX] __initdata;
struct e820entry *overlap_list[E820MAX] __initdata;
struct e820entry new_bios[E820MAX] __initdata;

static int __init sanitize_e820_map(struct e820entry * biosmap, char * pnr_map) {
	struct change_member *change_tmp;
	unsigned long current_type, last_type;
	unsigned long long last_addr;
	int chgidx, still_changing;
	int overlap_entries;
	int new_bios_entry;
	int old_nr, new_nr, chg_nr;
	int i;

	if (*pnr_map < 2)
		return -1;
	old_nr = *pnr_map;

	for (i = 0; i < old_nr; i++)
		if (biosmap[i].addr + biosmap[i].size < biosmap[i].addr)
			return -1;
	for (i = 0; i < 2 * old_nr; i++)
		change_point[i] = &change_point_list[i];

	chgidx = 0;
	for (i = 0; i < old_nr; i++) {
		if (biosmap[i].size != 0) {
			change_point[chgidx]->addr = biosmap[i].addr;
			change_point[chgidx++]->pbios = &biosmap[i];
			change_point[chgidx]->addr = biosmap[i].addr + biosmap[i].size;
			change_point[chgidx++]->pbios = &biosmap[i];
		}
	}
	chg_nr = chgidx;

	still_changing = 1;
	while (still_changing) {
		still_changing = 0;
		for (i = 1; i < chg_nr; i++) {
			if ((change_point[i]->addr < change_point[i-1]->addr) ||
				((change_point[i]->addr == change_point[i-1]->addr) &&
				 (change_point[i]->addr == change_point[i]->pbios->addr) &&
				 (change_point[i-1]->addr != change_point[i-1]->pbios->addr))
			   ) {
                change_tmp = change_point[i];
				change_point[i] = change_point[i-1];
				change_point[i-1] = change_tmp;
				still_changing = 1;
			}
		}
	}
	/* create a new bios memory map, removing overlaps */
	overlap_entries=0;	 /* number of entries in the overlap table */
	new_bios_entry=0;	 /* index for creating new bios map entries */
	last_type = 0;		 /* start with undefined memory type */
	last_addr = 0;		 /* start with 0 as last starting address */

	for (chgidx = 0; chgidx < chg_nr; chgidx++) {
		if (change_point[chgidx]->addr == change_point[chgidx]->pbios->addr) {
			overlap_list[overlap_entries++] = change_point[chgidx]->pbios;
		} else {
			for (i = 0; i < overlap_entries; i++) {
				if (overlap_list[i] == change_point[chgidx]->pbios)
					overlap_list[i] = overlap_list[overlap_entries-1];
			}
			overlap_entries--;
		}
		current_type = 0;
		for (i = 0; i < overlap_entries; i++)
			if (overlap_list[i]->type > current_type)
				current_type = overlap_list[i]->type;
		if (current_type != last_type)	{
			if (last_type != 0)	 {
				new_bios[new_bios_entry].size =
					change_point[chgidx]->addr - last_addr;
				/* move forward only if the new size was non-zero */
				if (new_bios[new_bios_entry].size != 0)
					if (++new_bios_entry >= E820MAX)
						break; 	/* no more space left for new bios entries */
			}
			if (current_type != 0)	{
				new_bios[new_bios_entry].addr = change_point[chgidx]->addr;
				new_bios[new_bios_entry].type = current_type;
				last_addr=change_point[chgidx]->addr;
			}
			last_type = current_type;
		}
	}
	new_nr = new_bios_entry;
	memcpy(biosmap, new_bios, new_nr * sizeof(struct e820entry));
	*pnr_map = new_nr;
	return 0;
}

static int __init copy_e820_map(struct e820entry * biosmap, int nr_map) {
	if (nr_map < 2)
		return -1;
	do {
		unsigned long long start = biosmap->addr;
		unsigned long long size = biosmap->size;
		unsigned long long end = start + size;
		unsigned long type = biosmap->type;

		if (start > end)
			return -1;
		if (type == E820_RAM) {
			if (start < 0x100000ULL && end > 0xA0000ULL) {
				if (start < 0xA0000ULL)
					add_memory_region(start, 0xA0000ULL - start, type);
				if (end <= 0x100000ULL)
					continue;
				start = 0x100000ULL;
				size = end - start;
			}
		}
		add_memory_region(start, size, type);
	} while (biosmap++, --nr_map);
	return 0;
}

#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)
#error "CONFIG_EDD | CONFIG_EDD_MODULE"
#else
static inline void copy_edd(void)
{
}
#endif

#define LOWMEMSIZE()	(0x9f000)

static void __init parse_cmdline_early (char ** cmdline_p) {
    char c = ' ', *to = command_line, *from = saved_command_line;
    int len = 0;
	int userdef = 0;

	/* Save unparsed command line copy for /proc/cmdline */
	saved_command_line[COMMAND_LINE_SIZE-1] = '\0';

    for (;;) {
        if (c != ' ')
            goto next_char;
		/*
		 * "mem=nopentium" disables the 4MB page tables.
		 * "mem=XXX[kKmM]" defines a memory region from HIGH_MEM
		 * to <mem>, overriding the bios size.
		 * "memmap=XXX[KkmM]@XXX[KkmM]" defines a memory region from
		 * <start> to <start>+<mem>, overriding the bios size.
		 *
		 * HPA tells me bootloaders need to parse mem=, so no new
		 * option should be mem=  [also see Documentation/i386/boot.txt]
		 */
		if (!memcmp(from, "mem=", 4)) {
			if (to != command_line)
				to--;
			if (!memcmp(from+4, "nopentium", 9)) {
				from += 9+4;
				clear_bit(X86_FEATURE_PSE, boot_cpu_data.x86_capability);
				disable_pse= 1;
			} else {
				unsigned long long mem_size;
				mem_size = memparse(from+4, &from);
				limit_regions(mem_size);
				userdef = 1;
			}
		} else if (!memcmp(from, "memmap=", 7)) {
			if (to != command_line)
				to--;
			if (!memcmp(from+7, "exactmap", 8)) {
				from += 8+7;
				e820.nr_map = 0;
				userdef = 1;
			} else {
				unsigned long long start_at, mem_size;

				mem_size = memparse(from+7, &from);
				if (*from == '@') {
					start_at = memparse(from+1, &from);
					add_memory_region(start_at, mem_size, E820_RAM);
				} else if (*from == '#') {
					start_at = memparse(from+1, &from);
					add_memory_region(start_at, mem_size, E820_ACPI);
				} else if (*from == '$') {
					start_at = memparse(from+1, &from);
					add_memory_region(start_at, mem_size, E820_RESERVED);
				} else {
					limit_regions(mem_size);
					userdef = 1;
				}
			}
		} else if (!memcmp(from, "noexec=", 7))
			noexec_setup(from+7);

#ifdef  CONFIG_X86_SMP
		/*
		 * If the BIOS enumerates physical processors before logical,
		 * maxcpus=N at enumeration-time can be used to disable HT.
		 */
		else if (!memcmp(from, "maxcpus=", 8)) {
			extern unsigned int maxcpus;

			maxcpus = simple_strtoul(from + 8, NULL, 0);
		}
#endif

#ifdef CONFIG_ACPI_BOOT
		/* "acpi=off" disables both ACPI table parsing and interpreter */
		else if (!memcmp(from, "acpi=off", 8)) {
			disable_acpi();
		}

		/* acpi=force to over-ride black-list */
		else if (!memcmp(from, "acpi=force", 10)) {
			acpi_force = 1;
			acpi_ht = 1;
			acpi_disabled = 0;
		}

		/* acpi=strict disables out-of-spec workarounds */
		else if (!memcmp(from, "acpi=strict", 11)) {
			acpi_strict = 1;
		}

		/* Limit ACPI just to boot-time to enable HT */
		else if (!memcmp(from, "acpi=ht", 7)) {
			if (!acpi_force)
				disable_acpi();
			acpi_ht = 1;
		}
		
		/* "pci=noacpi" disable ACPI IRQ routing and PCI scan */
		else if (!memcmp(from, "pci=noacpi", 10)) {
			acpi_disable_pci();
		}
		/* "acpi=noirq" disables ACPI interrupt routing */
		else if (!memcmp(from, "acpi=noirq", 10)) {
			acpi_noirq_set();
		}

		else if (!memcmp(from, "acpi_sci=edge", 13))
			acpi_sci_flags.trigger =  1;

		else if (!memcmp(from, "acpi_sci=level", 14))
			acpi_sci_flags.trigger = 3;

		else if (!memcmp(from, "acpi_sci=high", 13))
			acpi_sci_flags.polarity = 1;

		else if (!memcmp(from, "acpi_sci=low", 12))
			acpi_sci_flags.polarity = 3;

#ifdef CONFIG_X86_IO_APIC
		else if (!memcmp(from, "acpi_skip_timer_override", 24))
			acpi_skip_timer_override = 1;
#endif

#ifdef CONFIG_X86_LOCAL_APIC
		/* disable IO-APIC */
		else if (!memcmp(from, "noapic", 6))
			disable_ioapic_setup();
#endif /* CONFIG_X86_LOCAL_APIC */
#endif /* CONFIG_ACPI_BOOT */

		/*
		 * highmem=size forces highmem to be exactly 'size' bytes.
		 * This works even on boxes that have no highmem otherwise.
		 * This also works to reduce highmem size on bigger boxes.
		 */
		else if (!memcmp(from, "highmem=", 8))
			highmem_pages = memparse(from+8, &from) >> PAGE_SHIFT;

		/*
		 * vmalloc=size forces the vmalloc area to be exactly 'size'
		 * bytes. This can be used to increase (or decrease) the
		 * vmalloc area - the default is 128m.
		 */
		else if (!memcmp(from, "vmalloc=", 8))
			__VMALLOC_RESERVE = memparse(from+8, &from);

    next_char:
        c = *(from++);
        if (!c)
            break;
        if (COMMAND_LINE_SIZE <= ++len)
            break;
        *(to++) = c;
    }
    *to = '\0';
    *cmdline_p = command_line;
	if (userdef) {
		printk(KERN_INFO "user-defined physical RAM map:\n");
		// print_memory_map("user");
	}
}

/*
 * Find the highest page frame number we have available
 */
void __init find_max_pfn(void) {
    int i;

    max_pfn = 0;
    if (efi_enabled) {
        mypanic("efi not enabled");
    }
    for (i = 0; i < e820.nr_map; i++) {
		unsigned long start, end;
		/* RAM? */
		if (e820.map[i].type != E820_RAM)
			continue;
		start = PFN_UP(e820.map[i].addr);
		end = PFN_DOWN(e820.map[i].addr + e820.map[i].size);
		if (start >= end)
			continue;
		if (end > max_pfn)
			max_pfn = end;
    }
}

/*
 * Determine low and high memory ranges:
 */
unsigned long __init find_max_low_pfn(void) {
	unsigned long max_low_pfn;

	max_low_pfn = max_pfn;
	if (max_low_pfn > MAXMEM_PFN) {
		if (highmem_pages == -1)
			highmem_pages = max_pfn - MAXMEM_PFN;
		if (highmem_pages + MAXMEM_PFN < max_pfn)
			max_pfn = MAXMEM_PFN + highmem_pages;
		if (highmem_pages + MAXMEM_PFN > max_pfn) {
			printk("only %luMB highmem pages available, ignoring highmem size of %uMB.\n", pages_to_mb(max_pfn - MAXMEM_PFN), pages_to_mb(highmem_pages));
			highmem_pages = 0;
		}
		max_low_pfn = MAXMEM_PFN;
#ifndef CONFIG_HIGHMEM
#error "!CONFIG_HIGHMEM"
#else /* !CONFIG_HIGHMEM */
#ifndef CONFIG_X86_PAE
		if (max_pfn > MAX_NONPAE_PFN) {
			max_pfn = MAX_NONPAE_PFN;
			printk(KERN_WARNING "Warning only 4GB will be used.\n");
			printk(KERN_WARNING "Use a PAE enabled kernel.\n");
		}
#endif /* !CONFIG_X86_PAE */
#endif /* !CONFIG_HIGHMEM */
	} else {
		if (highmem_pages == -1)
			highmem_pages = 0;
#ifdef CONFIG_HIGHMEM
		if (highmem_pages >= max_pfn) {
			printk(KERN_ERR "highmem size specified (%uMB) is bigger than pages available (%luMB)!.\n", pages_to_mb(highmem_pages), pages_to_mb(max_pfn));
			highmem_pages = 0;
		}
		if (highmem_pages) {
			if (max_low_pfn - highmem_pages < 64 * 1024 * 1024 / PAGE_SIZE) {
				mypanic("highmem size %uMB results in smaller than 64MB lowmem, ignoring it.\n", pages_to_mb(highmem_pages));
				highmem_pages = 0;
			}
			max_low_pfn -= highmem_pages;
		}
#else
	#error "CONFIG_HIGHMEM"
#endif
	}
	return max_low_pfn;
}

static void __init register_bootmem_low_pages(unsigned long max_low_pfn) {
	int i;

	if (efi_enabled) {
		mypanic("efi_enabled");
		return;
	}
	for (i = 0; i < e820.nr_map; i++) {
		unsigned long curr_pfn, last_pfn, size;
		if (e820.map[i].type != E820_RAM)
			continue;
		curr_pfn = PFN_UP(e820.map[i].addr);
		if (curr_pfn >= max_low_pfn)
			continue;
		last_pfn = PFN_DOWN(e820.map[i].addr + e820.map[i].size);
		if (last_pfn > max_low_pfn)
			last_pfn = max_low_pfn;
		if (last_pfn <= curr_pfn)
			continue;
		size = last_pfn - curr_pfn;
		// 将类型为RAM的内存置为可用状态，0表示free
		free_bootmem(PFN_PHYS(curr_pfn), PFN_PHYS(size));
	}
}

static void __init reserve_ebda_region(void) {
	unsigned int addr;
	addr = get_bios_ebda();
	if (addr)
		reserve_bootmem(addr, PAGE_SIZE);	
}

static unsigned long __init setup_memory(void) {
    unsigned long bootmap_size, start_pfn, max_low_pfn;

    start_pfn = PFN_UP(init_pg_tables_end);

	// 找到最大的物理页
    find_max_pfn();
	// 低端内存的最大的物理页
	max_low_pfn = find_max_low_pfn();

#ifdef CONFIG_HIGHMEM
	highstart_pfn = highend_pfn = max_pfn;
	if (max_pfn > max_low_pfn) {
		highstart_pfn = max_low_pfn;
	}
	printk(KERN_NOTICE "%ldMB HIGHMEM available.\n",
		pages_to_mb(highend_pfn - highstart_pfn));
#endif
	printk(KERN_NOTICE "%ldMB LOWMEM available.\n",
			pages_to_mb(max_low_pfn));
	/*
	 * Initialize the boot-time allocator (with low memory only):
	 */
	bootmap_size = init_bootmem(start_pfn, max_low_pfn);

	register_bootmem_low_pages(max_low_pfn);

	// start_pfn后面的bootmap_size大小存放了map表
	reserve_bootmem(HIGH_MEMORY, (PFN_PHYS(start_pfn) +
			bootmap_size + PAGE_SIZE - 1) - (HIGH_MEMORY));

    // reserve page 0 - it's a special BIOS page
	reserve_bootmem(0, PAGE_SIZE);

	// reserve EBDA region
	reserve_ebda_region();

	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
		boot_cpu_data.x86 == 6)
		reserve_bootmem(0xa0000 - 4096, 4096);

#ifdef CONFIG_SMP
	reserve_bootmem(PAGE_SIZE, PAGE_SIZE);
#endif
#ifdef CONFIG_ACPI_SLEEP	
#error "CONFIG_ACPI_SLEEP"
#endif
#ifdef CONFIG_X86_FIND_SMP_CONFIG
	/*
	 * smp_scan_config(0x0,0x400)
	 * smp_scan_config(639*0x400,0x400)
	 * smp_scan_config(0xF0000,0x10000)
	 * smp_scan_config(get_bios_ebda(), 0x400)
	 * 这几个地方来扫描ACPI的物理地址，如果存在就设置mpf_found为配置的首地址
	 */
	find_smp_config();
#endif
#ifdef CONFIG_BLK_DEV_INITRD
#error "CONFIG_BLK_DEV_INITRD"
#endif
	return max_low_pfn;
}

static void __init legacy_init_iomem_resources(struct resource *code_resource, struct resource *data_resource) {
	int i;

	probe_roms();
	for (i = 0; i < e820.nr_map; i++) {
		struct resource *res;
		if (e820.map[i].addr + e820.map[i].size > 0x100000000ULL)
			continue;
		res = alloc_bootmem_low(sizeof(struct resource));
		switch (e820.map[i].type) {
			case E820_RAM:	res->name = "System RAM"; break;
			case E820_ACPI:	res->name = "ACPI Tables"; break;
			case E820_NVS:	res->name = "ACPI Non-volatile Storage"; break;
			default:	res->name = "reserved";
		}
		res->start = e820.map[i].addr;
		res->end = res->start + e820.map[i].size - 1;
		res->flags = IORESOURCE_MEM | IORESOURCE_BUSY;
		request_resource(&iomem_resource, res);
		if (e820.map[i].type == E820_RAM) {
			/*
			 *  We don't know which RAM region contains kernel data,
			 *  so we try it repeatedly and let the resource manager
			 *  test it.
			 */
			request_resource(res, code_resource);
			request_resource(res, data_resource);
		}
	}
}

/*
 * Request address space for all standard resources
 */
static void __init register_memory(void) {
	unsigned long gapstart, gapsize;
	unsigned long long last;
	int	      i;

	if (efi_enabled)
		mypanic("efi_enabled");
	else
		legacy_init_iomem_resources(&code_resource, &data_resource);

	request_resource(&iomem_resource, &video_ram_resource);

	for (i = 0; i < STANDARD_IO_RESOURCES; i++)
		request_resource(&ioport_resource, &standard_io_resources[i]);

	/*
	 * Search for the bigest gap in the low 32 bits of the e820
	 * memory space.
	 */
	last = 0x100000000ull;
	gapstart = 0x10000000;
	gapsize = 0x400000;
	i = e820.nr_map;
	while (--i >= 0) {
		unsigned long long start = e820.map[i].addr;
		unsigned long long end = start + e820.map[i].size;

		if (last > end) {
			unsigned long gap = last - end;

			if (gap > gapsize) {
				gapsize = gap;
				gapstart = end;
			}
		}
		if (start < last)
			last = start;
	}

	pci_mem_start = (gapstart + 0xfffff) & ~0xfffff;
	printk("Allocating PCI resources starting at %08lx (gap: %08lx:%08lx)\n",
		pci_mem_start, gapstart, gapsize);
}

static int no_replacement __initdata = 0;

void __init alternative_instructions(void) {
	extern struct alt_instr __alt_instructions[], __alt_instructions_end[];
	if (no_replacement) 
		return;
	panic("in alternative_instructions function");
}
static int __init noreplacement_setup(char *s)
{ 
     no_replacement = 1; 
     return 0; 
} 

__setup("noreplacement", noreplacement_setup);

static char * __init machine_specific_memory_setup(void);

#ifdef CONFIG_MCA
static void set_mca_bus(int x)
{
	MCA_bus = x;
}
#else
static void set_mca_bus(int x) { }
#endif

void __init setup_arch(char **cmdline_p) {
    unsigned long max_low_pfn;

    memcpy(&boot_cpu_data, &new_cpu_data, sizeof(new_cpu_data));
    pre_setup_arch_hook();
    early_cpu_init();
#ifdef CONFIG_EFI
	if ((LOADER_TYPE == 0x50) && EFI_SYSTAB)
		efi_enabled = 1;
#endif

    ROOT_DEV = old_decode_dev(ORIG_ROOT_DEV);
    drive_info = DRIVE_INFO;
 	screen_info = SCREEN_INFO;
	edid_info = EDID_INFO;
	apm_info.bios = APM_BIOS_INFO;
	ist_info = IST_INFO;
    saved_videomode = VIDEO_MODE;
    if (SYS_DESC_TABLE.length != 0) {
        set_mca_bus(SYS_DESC_TABLE.table[3] & 0x2);
        machine_id = SYS_DESC_TABLE.table[0];
		machine_submodel_id = SYS_DESC_TABLE.table[1];
		BIOS_revision = SYS_DESC_TABLE.table[2];
    }
	aux_device_present = AUX_DEVICE_INFO;
	bootloader_type = LOADER_TYPE;

#ifdef CONFIG_BLK_DEV_RAM
#error "CONFIG_BLK_DEV_RAM"
#endif
    ARCH_SETUP
    if (efi_enabled)
        mypanic("xxxxxxxxx");
    else {
		printk(KERN_INFO "BIOS-provided physical RAM map:\n");
		print_memory_map(machine_specific_memory_setup());
    }
    copy_edd();
    if (!MOUNT_ROOT_RDONLY)
        root_mountflags &= ~MS_RDONLY;
    init_mm.start_code = (unsigned long) _text;
    init_mm.end_code = (unsigned long) _etext;
    init_mm.end_data = (unsigned long) _edata;
	// init_pg_tables_end 是pg0后面的地址，这里转换为内核虚拟地址
    init_mm.brk = init_pg_tables_end + PAGE_OFFSET;
    // myprint("start: %08x, end: %08x, end: %08x, brk: %08x", init_mm.start_code, init_mm.end_code, init_mm.end_data, init_mm.brk);

    code_resource.start = virt_to_phys(_text);
	code_resource.end = virt_to_phys(_etext)-1;
	data_resource.start = virt_to_phys(_etext);
	data_resource.end = virt_to_phys(_edata)-1;

    parse_cmdline_early(cmdline_p);

    max_low_pfn = setup_memory();

	/*
	 * NOTE: before this point _nobody_ is allowed to allocate
	 * any memory using the bootmem allocator.  Although the
	 * alloctor is now initialised only the first 8Mb of the kernel
	 * virtual address space has been mapped.  All allocations before
	 * paging_init() has completed must use the alloc_bootmem_low_pages()
	 * variant (which allocates DMA'able memory) and care must be taken
	 * not to exceed the 8Mb limit.
	 */
#ifdef CONFIG_SMP
	smp_alloc_memory(); /* AP processor realmode stacks in low memory*/
#endif
	paging_init();

#ifdef CONFIG_EARLY_PRINTK
	{
		char *s = strstr(*cmdline_p, "earlyprintk=");
		if (s) {
			/*
			extern void setup_early_printk(char *);

			setup_early_printk(s);
			printk("early console enabled\n");
			*/
		}
	}
#endif

	dmi_scan_machine();
#ifdef CONFIG_X86_GENERICARCH
#error "CONFIG_X86_GENERICARCH"
#endif	
	if (efi_enabled)
		mypanic("efi_enabled");

	/*
	 * Parse the ACPI tables for possible boot-time SMP configuration.
	 * ACPI_FADT ACPI_APIC ACPI_HPET
	 */
	acpi_boot_table_init();
	acpi_boot_init();

#ifdef CONFIG_X86_LOCAL_APIC
	if (smp_found_config)
		get_smp_config();
#endif

	register_memory();

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	if (!efi_enabled || (efi_mem_type(0xa0000) != EFI_CONVENTIONAL_MEMORY))
		conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE)
	conswitchp = &dummy_con;
#endif
#endif
}

static char * __init machine_specific_memory_setup(void)
{
	char *who;


	who = "BIOS-e820";
	/*
	 * Try to copy the BIOS-supplied E820-map.
	 *
	 * Otherwise fake a memory map; one section from 0k->640k,
	 * the next section from 1mb->appropriate_mem_k
	 */
	sanitize_e820_map(E820_MAP, &E820_MAP_NR);
	if (copy_e820_map(E820_MAP, E820_MAP_NR) < 0) {
		mypanic("copy_e820_map < 0");
	}

	return who;
}