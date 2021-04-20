#include <linux/config.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <linux/string.h>
#include <linux/bitops.h>
#include <linux/smp.h>
#include <linux/thread_info.h>

#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/uaccess.h>

#include "cpu.h"

#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <mach_apic.h>
#endif

#ifdef CONFIG_X86_INTEL_USERCOPY
/*
 * Alignment at which movsl is preferred for bulk memory copies.
 */
struct movsl_mask movsl_mask;
#endif

void __init early_intel_workaround(struct cpuinfo_x86 *c) {
	if (c->x86_vendor != X86_VENDOR_INTEL)
		return;
	if (c->x86 == 15 && c->x86_cache_alignment == 64)
		c->x86_cache_alignment = 128;
}

static void __init init_intel(struct cpuinfo_x86 *c) {

}

static unsigned int intel_size_cache(struct cpuinfo_x86 * c, unsigned int size) {
    return 0;    
}

static struct cpu_dev intel_cpu_dev __initdata = {
	.c_vendor	= "Intel",
	.c_ident 	= { "GenuineIntel" },
	.c_models = {
		{ .vendor = X86_VENDOR_INTEL, .family = 4, .model_names = 
		  { 
			  [0] = "486 DX-25/33", 
			  [1] = "486 DX-50", 
			  [2] = "486 SX", 
			  [3] = "486 DX/2", 
			  [4] = "486 SL", 
			  [5] = "486 SX/2", 
			  [7] = "486 DX/2-WB", 
			  [8] = "486 DX/4", 
			  [9] = "486 DX/4-WB"
		  }
		},
		{ .vendor = X86_VENDOR_INTEL, .family = 5, .model_names =
		  { 
			  [0] = "Pentium 60/66 A-step", 
			  [1] = "Pentium 60/66", 
			  [2] = "Pentium 75 - 200",
			  [3] = "OverDrive PODP5V83", 
			  [4] = "Pentium MMX",
			  [7] = "Mobile Pentium 75 - 200", 
			  [8] = "Mobile Pentium MMX"
		  }
		},
		{ .vendor = X86_VENDOR_INTEL, .family = 6, .model_names =
		  { 
			  [0] = "Pentium Pro A-step",
			  [1] = "Pentium Pro", 
			  [3] = "Pentium II (Klamath)", 
			  [4] = "Pentium II (Deschutes)", 
			  [5] = "Pentium II (Deschutes)", 
			  [6] = "Mobile Pentium II",
			  [7] = "Pentium III (Katmai)", 
			  [8] = "Pentium III (Coppermine)", 
			  [10] = "Pentium III (Cascades)",
			  [11] = "Pentium III (Tualatin)",
		  }
		},
		{ .vendor = X86_VENDOR_INTEL, .family = 15, .model_names =
		  {
			  [0] = "Pentium 4 (Unknown)",
			  [1] = "Pentium 4 (Willamette)",
			  [2] = "Pentium 4 (Northwood)",
			  [4] = "Pentium 4 (Foster)",
			  [5] = "Pentium 4 (Foster)",
		  }
		},
	},
	.c_init		= init_intel,
	.c_identify	= generic_identify,
	.c_size_cache	= intel_size_cache,
};

__init int intel_cpu_init(void) {
	cpu_devs[X86_VENDOR_INTEL] = &intel_cpu_dev;
	return 0;
}
