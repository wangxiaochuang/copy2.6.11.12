#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <asm/processor.h>

#include "cpu.h"

static void __init init_amd(struct cpuinfo_x86 *c) {

}

static unsigned int amd_size_cache(struct cpuinfo_x86 * c, unsigned int size) {
    return 0;
}

static struct cpu_dev amd_cpu_dev __initdata = {
	.c_vendor	= "AMD",
	.c_ident 	= { "AuthenticAMD" },
	.c_models = {
		{ .vendor = X86_VENDOR_AMD, .family = 4, .model_names =
		  {
			  [3] = "486 DX/2",
			  [7] = "486 DX/2-WB",
			  [8] = "486 DX/4", 
			  [9] = "486 DX/4-WB", 
			  [14] = "Am5x86-WT",
			  [15] = "Am5x86-WB" 
		  }
		},
	},
	.c_init		= init_amd,
	.c_identify	= generic_identify,
	.c_size_cache	= amd_size_cache,
};

int __init amd_init_cpu(void) {
	cpu_devs[X86_VENDOR_AMD] = &amd_cpu_dev;
	return 0;
}