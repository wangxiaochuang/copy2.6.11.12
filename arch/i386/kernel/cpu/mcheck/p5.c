#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/smp.h>

#include <asm/processor.h> 
#include <asm/system.h>
#include <asm/msr.h>

#include "mce.h"

/* Set up machine check reporting for processors with Intel style MCE */
void __init intel_p5_mcheck_init(struct cpuinfo_x86 *c)
{
}