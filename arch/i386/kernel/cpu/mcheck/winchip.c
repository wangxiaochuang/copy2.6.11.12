#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/irq.h>
#include <linux/interrupt.h>

#include <asm/processor.h> 
#include <asm/system.h>
#include <asm/msr.h>

#include "mce.h"

/* Set up machine check reporting on the Winchip C6 series */
void __init winchip_mcheck_init(struct cpuinfo_x86 *c)
{
}