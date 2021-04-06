#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <asm/processor.h>

#include "cpu.h"

static void __init init_nexgen(struct cpuinfo_x86 * c) {
}

static void __init nexgen_identify(struct cpuinfo_x86 * c) {

}

static struct cpu_dev nexgen_cpu_dev __initdata = {
	.c_vendor	= "Nexgen",
	.c_ident	= { "NexGenDriven" },
	.c_models = {
			{ .vendor = X86_VENDOR_NEXGEN,
			  .family = 5,
			  .model_names = { [1] = "Nx586" }
			},
	},
	.c_init		= init_nexgen,
	.c_identify	= nexgen_identify,
};

int __init nexgen_init_cpu(void) {
	cpu_devs[X86_VENDOR_NEXGEN] = &nexgen_cpu_dev;
	return 0;
}