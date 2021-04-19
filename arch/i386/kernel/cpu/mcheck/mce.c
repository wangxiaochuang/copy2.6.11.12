#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/thread_info.h>

#include <asm/processor.h> 
#include <asm/system.h>

#include "mce.h"

/* Handle unconfigured int18 (should never happen) */
static fastcall void unexpected_machine_check(struct pt_regs * regs, long error_code)
{	
	printk(KERN_ERR "CPU#%d: Unexpected int18 (Machine Check).\n", smp_processor_id());
}

/* Call the installed machine check handler for this CPU setup. */
void fastcall (*machine_check_vector)(struct pt_regs *, long error_code) = unexpected_machine_check;