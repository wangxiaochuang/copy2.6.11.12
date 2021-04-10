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

static int __init mpf_checksum(unsigned char *mp, int len) {
	int sum = 0;

	while (len--)
		sum += *mp++;

	return sum & 0xFF;
}

static struct intel_mp_floating *mpf_found;

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