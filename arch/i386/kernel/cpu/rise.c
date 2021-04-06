#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <asm/processor.h>

#include "cpu.h"

static void __init init_rise(struct cpuinfo_x86 *c) {

}

static struct cpu_dev rise_cpu_dev __initdata = {
	.c_vendor	= "Rise",
	.c_ident	= { "RiseRiseRise" },
	.c_models = {
		{ .vendor = X86_VENDOR_RISE, .family = 5, .model_names = 
		  { 
			  [0] = "iDragon", 
			  [2] = "iDragon", 
			  [8] = "iDragon II", 
			  [9] = "iDragon II"
		  }
		},
	},
	.c_init		= init_rise,
};

int __init rise_init_cpu(void)
{
	cpu_devs[X86_VENDOR_RISE] = &rise_cpu_dev;
	return 0;
}