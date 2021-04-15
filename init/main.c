#define __KERNEL_SYSCALLS__

#include <linux/config.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/devfs_fs_kernel.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/utsname.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/initrd.h>
#include <linux/hdreg.h>
#include <linux/bootmem.h>
#include <linux/tty.h>
#include <linux/gfp.h>
#include <linux/percpu.h>
#include <linux/kmod.h>
#include <linux/kernel_stat.h>
#include <linux/security.h>
#include <linux/workqueue.h>
#include <linux/profile.h>
#include <linux/rcupdate.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/efi.h>
#include <linux/unistd.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>

#include <asm/io.h>
#include <asm/bugs.h>
#include <asm/setup.h>

enum system_states system_state;
EXPORT_SYMBOL(system_state);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS 32
#define MAX_INIT_ENVS 32

/* Untouched command line (eg. for /proc) saved by arch-specific code. */
char saved_command_line[COMMAND_LINE_SIZE];

static char * argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
char * envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

extern struct obs_kernel_param __setup_start[], __setup_end[];

static int __init obsolete_checksetup(char *line)
{
	struct obs_kernel_param *p;

	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (!strncmp(line, p->str, n)) {
			if (p->early) {
				/* Already done in parse_early_param?  (Needs
				 * exact match on param part) */
				if (line[n] == '\0' || line[n] == '=')
					return 1;
			} else if (!p->setup_func) {
				printk(KERN_WARNING "Parameter %s is obsolete,"
				       " ignored\n", p->str);
				return 1;
			} else if (p->setup_func(line + n))
				return 1;
		}
		p++;
	} while (p < __setup_end);
	return 0;
}

/*
 * Unknown boot options get handed to init, unless they look like
 * failed parameters
 */
static int __init unknown_bootoption(char *param, char *val)
{
	/* Change NUL term back to "=", to make "param" the whole string. */
	if (val) {
		/* param=val or param="val"? */
		if (val == param+strlen(param)+1)
			val[-1] = '=';
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
			val--;
		} else
			BUG();
	}

	/* Handle obsolete-style parameters */
	if (obsolete_checksetup(param))
		return 0;

	/*
	 * Preemptive maintenance for "why didn't my mispelled command
	 * line work?"
	 */
	if (strchr(param, '.') && (!val || strchr(param, '.') < val)) {
		printk(KERN_ERR "Unknown boot option `%s': ignoring\n", param);
		return 0;
	}

	if (panic_later)
		return 0;

	if (val) {
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "Too many boot env vars at `%s'";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], val - param))
				break;
		}
		envp_init[i] = param;
	} else {
		/* Command line option */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "Too many boot init vars at `%s'";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

extern void setup_arch(char **);

#ifdef __GENERIC_PER_CPU
unsigned long __per_cpu_offset[NR_CPUS];

EXPORT_SYMBOL(__per_cpu_offset);

static void __init setup_per_cpu_areas(void) {
    unsigned long size, i;
    char *ptr;
    /* Created by linker magic */
	extern char __per_cpu_start[], __per_cpu_end[];

    size = ALIGN(__per_cpu_end - __per_cpu_start, SMP_CACHE_BYTES);
#ifdef CONFIG_MODULES
    if (size < PERCPU_ENOUGH_ROOM)
        size = PERCPU_ENOUGH_ROOM;
#endif

    ptr = alloc_bootmem(size * NR_CPUS);

    for (i = 0; i < NR_CPUS; i++, ptr += size) {
        __per_cpu_offset[i] = ptr - __per_cpu_start;
        memcpy(ptr, __per_cpu_start, __per_cpu_end - __per_cpu_start);
    }
}

#endif

/* Check for early params. */
static int __init do_early_param(char *param, char *val) {
	struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if (p->early && strcmp(param, p->str) == 0) {
			if (p->setup_func(val) != 0)
				printk(KERN_WARNING
				       "Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void) {
	static __initdata int done = 0;
	static __initdata char tmp_cmdline[COMMAND_LINE_SIZE];

    if (done)
        return;
    strlcpy(tmp_cmdline, saved_command_line, COMMAND_LINE_SIZE);
    parse_args("early options", tmp_cmdline, NULL, 0, do_early_param);
	done = 1;
}

asmlinkage void __init start_kernel(void) {
    char *command_line;
	strcpy(saved_command_line, "mem=nopentium");
    extern struct kernel_param __start___param[], __stop___param[];
    lock_kernel();
    page_address_init();
    printk("%s", linux_banner);
    setup_arch(&command_line);
    setup_per_cpu_areas();

    smp_prepare_boot_cpu();

    sched_init();

    preempt_disable();
	build_all_zonelists();
    page_alloc_init();
	printk("Kernel command line: %s\n", saved_command_line);
    parse_early_param();
    parse_args("Booting kernel", command_line, __start___param,
		   __stop___param - __start___param,
		   &unknown_bootoption);
    sort_main_extable();
    trap_init();
    for(;;);
}
