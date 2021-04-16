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