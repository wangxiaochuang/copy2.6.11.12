#include <linux/config.h>
#include <linux/init.h>

#include <linux/mm.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/bootmem.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/mc146818rtc.h>
#include <linux/kernel_stat.h>
#include <linux/sysdev.h>

#include <asm/atomic.h>
#include <asm/smp.h>
#include <asm/mtrr.h>
#include <asm/mpspec.h>
#include <asm/desc.h>
#include <asm/arch_hooks.h>
#include <asm/hpet.h>

#include <mach_apic.h>

#include "io_ports.h"

/*
 * Debug level
 */
int apic_verbosity;

int get_physical_broadcast(void)
{
	unsigned int lvr, version;
	lvr = apic_read(APIC_LVR);
	version = GET_APIC_VERSION(lvr);
	if (!APIC_INTEGRATED(version) || version >= 0x14)
		return 0xff;
	else
		return 0xf;
}

static int __init detect_init_APIC (void) {
    return 0;
}
void __init init_apic_mappings(void) {
    unsigned long apic_phys;

    if (!smp_found_config && detect_init_APIC()) {
        apic_phys = (unsigned long) alloc_bootmem_pages(PAGE_SIZE);
        apic_phys = __pa(apic_phys);
    } else 
        apic_phys = mp_lapic_addr;
    
    set_fixmap_nocache(FIX_APIC_BASE, apic_phys);
    printk(KERN_DEBUG "mapped APIC to %08lx (%08lx)\n", APIC_BASE,
	       apic_phys);
    
    if (boot_cpu_physical_apicid == -1U)
        boot_cpu_physical_apicid = GET_APIC_ID(apic_read(APIC_ID));
    
#ifdef CONFIG_X86_IO_APIC
    {
        unsigned long ioapic_phys, idx = FIX_IO_APIC_BASE_0;
        int i;

        for (i = 0; i < nr_ioapics; i++) {
            if (smp_found_config) {

            } else {
                ioapic_phys = (unsigned long)
                        alloc_bootmem_pages(PAGE_SIZE);
                ioapic_phys = __pa(ioapic_phys);
            }
            set_fixmap_nocache(idx, ioapic_phys);
            printk(KERN_DEBUG "mapped IOAPIC to %08lx (%08lx)\n",
			       __fix_to_virt(idx), ioapic_phys);
			idx++;
        }
    }
#endif
}