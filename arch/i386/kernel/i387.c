#include <linux/config.h>
#include <linux/sched.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/math_emu.h>
#include <asm/sigcontext.h>
#include <asm/user.h>
#include <asm/ptrace.h>
#include <asm/uaccess.h>

#ifdef CONFIG_MATH_EMULATION
#define HAVE_HWFP (boot_cpu_data.hard_math)
#else
#define HAVE_HWFP 1
#endif

unsigned long mxcsr_feature_mask = 0xffffffff;

void mxcsr_feature_mask_init(void)
{
	unsigned long mask = 0;
	clts();
	if (cpu_has_fxsr) {
		memset(&current->thread.i387.fxsave, 0, sizeof(struct i387_fxsave_struct));
		asm volatile("fxsave %0" : : "m" (current->thread.i387.fxsave)); 
		mask = current->thread.i387.fxsave.mxcsr_mask;
		if (mask == 0) mask = 0x0000ffbf;
	} 
	mxcsr_feature_mask &= mask;
	stts();
}