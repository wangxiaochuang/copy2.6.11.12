#include <linux/config.h>
#include <linux/mm.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/bootmem.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/mc146818rtc.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/nmi.h>
#include <linux/sysdev.h>
#include <linux/sysctl.h>

#include <asm/smp.h>
#include <asm/mtrr.h>
#include <asm/mpspec.h>
#include <asm/nmi.h>

#include "mach_traps.h"

unsigned int nmi_watchdog = NMI_NONE;
static unsigned int nmi_hz = HZ;
static unsigned int nmi_perfctr_msr;

static unsigned int lapic_nmi_owner;
#define LAPIC_NMI_WATCHDOG	(1<<0)

int nmi_active;

#define P6_EVNTSEL0_ENABLE	(1 << 22)
#define P6_EVNTSEL_INT		(1 << 20)
#define P6_EVNTSEL_OS		(1 << 17)
#define P6_EVNTSEL_USR		(1 << 16)
#define P6_EVENT_CPU_CLOCKS_NOT_HALTED	0x79
#define P6_NMI_EVENT		P6_EVENT_CPU_CLOCKS_NOT_HALTED

static void clear_msr_range(unsigned int base, unsigned int n)
{
	unsigned int i;

	for(i = 0; i < n; ++i)
		wrmsr(base+i, 0, 0);
}

static void setup_p6_watchdog(void)
{
	unsigned int evntsel;

	nmi_perfctr_msr = MSR_P6_PERFCTR0;

	clear_msr_range(MSR_P6_EVNTSEL0, 2);
	clear_msr_range(MSR_P6_PERFCTR0, 2);

	evntsel = P6_EVNTSEL_INT
		| P6_EVNTSEL_OS
		| P6_EVNTSEL_USR
		| P6_NMI_EVENT;

	wrmsr(MSR_P6_EVNTSEL0, evntsel, 0);
	Dprintk("setting P6_PERFCTR0 to %08lx\n", -(cpu_khz/nmi_hz*1000));
	wrmsr(MSR_P6_PERFCTR0, -(cpu_khz/nmi_hz*1000), 0);
	apic_write(APIC_LVTPC, APIC_DM_NMI);
	evntsel |= P6_EVNTSEL0_ENABLE;
	wrmsr(MSR_P6_EVNTSEL0, evntsel, 0);
}

void setup_apic_nmi_watchdog (void)
{
	switch (boot_cpu_data.x86_vendor) {
	case X86_VENDOR_AMD:
		if (boot_cpu_data.x86 != 6 && boot_cpu_data.x86 != 15)
			return;
		panic("in setup_apic_nmi_watchdog 1");
		break;
	case X86_VENDOR_INTEL:
		switch (boot_cpu_data.x86) {
		case 6:
			if (boot_cpu_data.x86_model > 0xd)
				return;

			setup_p6_watchdog();
			break;
		case 15:
			if (boot_cpu_data.x86_model > 0x3)
				return;

            panic("in setup_apic_nmi_watchdog 2");
			break;
		default:
			return;
		}
		break;
	default:
		return;
	}
	lapic_nmi_owner = LAPIC_NMI_WATCHDOG;
	nmi_active = 1;
}