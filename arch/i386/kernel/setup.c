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

unsigned int mca_pentium_flag;

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

unsigned char __initdata boot_params[PARAM_SIZE];

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
}