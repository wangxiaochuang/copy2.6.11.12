#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/param.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/smp.h>

#include <asm/timer.h>
#include <asm/fixmap.h>
#include <asm/apic.h>

#include <linux/timex.h>
#include <linux/config.h>

#include <asm/hpet.h>
#include <linux/hpet.h>

unsigned long hpet_address;	/* hpet memory map physical address */

static int boot_hpet_disable; 	/* boottime override for HPET timer */

/*
 * Check whether HPET was found by ACPI boot parse. If yes setup HPET
 * counter 0 for kernel base timer.
 */
int __init hpet_enable(void)
{
    return 0;
}

int is_hpet_capable(void)
{
	if (!boot_hpet_disable && hpet_address)
		return 1;
	return 0;
}