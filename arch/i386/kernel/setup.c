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

/* for MCA, but anyone else can use it if they want */
unsigned int machine_id;
unsigned int machine_submodel_id;
unsigned int BIOS_revision;
unsigned int mca_pentium_flag;

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
		mypanic("max_low_pfn > MAXMEM_PFN");
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
	 * Find and reserve possible boot-time SMP configuration:
	 */
	find_smp_config();
#endif
#ifdef CONFIG_BLK_DEV_INITRD
#error "CONFIG_BLK_DEV_INITRD"
#endif
	return max_low_pfn;
}

void __init alternative_instructions(void) {
	
}

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
			*/
			printk("early console enabled\n");
		}
	}
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