#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/config.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/smp.h>

#include <asm/processor.h> 
#include <asm/system.h>
#include <asm/msr.h>
#include <asm/apic.h>

#include "mce.h"

void __init intel_p4_mcheck_init(struct cpuinfo_x86 *c)
{
}