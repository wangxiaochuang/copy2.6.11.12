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

/*
 * This is one of the first .c files built. Error out early
 * if we have compiler trouble..
 */
#if __GNUC__ == 2 && __GNUC_MINOR__ == 96
#ifdef CONFIG_FRAME_POINTER
#error This compiler cannot compile correctly with frame pointers enabled
#endif
#endif

#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/smp.h>
#endif

/*
 * Versions of gcc older than that listed below may actually compile
 * and link okay, but the end product can have subtle run time bugs.
 * To avoid associated bogus bug reports, we flatly refuse to compile
 * with a gcc that is known to be too old from the very beginning.
 */
#if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 95)
#error Sorry, your GCC is too old. It builds incorrect kernels.
#endif

static int init(void *);

extern void init_IRQ(void);
extern void sock_init(void);
extern void fork_init(unsigned long);
extern void mca_init(void);
extern void sbus_init(void);
extern void sysctl_init(void);
extern void signals_init(void);
extern void buffer_init(void);
extern void pidhash_init(void);
extern void pidmap_init(void);
extern void prio_tree_init(void);
extern void radix_tree_init(void);
extern void free_initmem(void);
extern void populate_rootfs(void);
extern void driver_init(void);
extern void prepare_namespace(void);
#ifdef	CONFIG_ACPI
extern void acpi_early_init(void);
#else
static inline void acpi_early_init(void) { }
#endif

#ifdef CONFIG_TC
extern void tc_init(void);
#endif

enum system_states system_state;
EXPORT_SYMBOL(system_state);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS 32
#define MAX_INIT_ENVS 32

extern void time_init(void);
/* Default late time init is NULL. archs can override this later. */
void (*late_time_init)(void);
extern void softirq_init(void);

/* Untouched command line (eg. for /proc) saved by arch-specific code. */
char saved_command_line[COMMAND_LINE_SIZE];

static char *execute_command;

static unsigned int max_cpus = NR_CPUS;

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
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);

EXPORT_SYMBOL(loops_per_jiffy);

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

/* Called by boot processor to activate the rest. */
static void __init smp_init(void)
{
	unsigned int i;

	for_each_present_cpu(i) {
		if (num_online_cpus() >= max_cpus)
			break;
		if (!cpu_online(i))
			cpu_up(i);
	}
	/* Any cleanup work */
	printk("Brought up %ld CPUs\n", (long)num_online_cpus());
	smp_cpus_done(max_cpus);
}

static void noinline rest_init(void)
	__releases(kernel_lock)
{
	kernel_thread(init, NULL, CLONE_FS | CLONE_SIGHAND);
	numa_default_policy();
	unlock_kernel();
	preempt_enable_no_resched();
	cpu_idle();
} 

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

extern struct kernel_param __start___param[], __stop___param[];

asmlinkage void __init start_kernel(void) {
    char *command_line;
	strcpy(saved_command_line, "hd=16644,16,63 mem=nopentium selinux=1 raid=noautodetect root=/dev/hda1 no_replacement initcall_debug");
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
	rcu_init();
	init_IRQ();
	pidhash_init();
	init_timers();
	softirq_init();
	time_init();	// ??????????????????

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();
	if (panic_later)
		panic(panic_later, panic_param);
	profile_init();
	local_irq_enable();
#ifdef CONFIG_BLK_DEV_INITRD
#error "CONFIG_BLK_DEV_INITRD"
#endif
	vfs_caches_init_early();
	mem_init();
	kmem_cache_init();
	numa_policy_init();
	if (late_time_init)
		late_time_init();
	calibrate_delay();
	pidmap_init();
	pgtable_cache_init();
	prio_tree_init();
	anon_vma_init();
#ifdef CONFIG_X86
	if (efi_enabled)
		panic("efi enabled");
#endif
	fork_init(num_physpages);
	proc_caches_init();
	buffer_init();
	unnamed_dev_init();
	security_init();
	vfs_caches_init(num_physpages);
	radix_tree_init();
	signals_init();
	page_writeback_init();
#ifdef CONFIG_PROC_FS
	proc_root_init();
#endif
	// check_bugs();
	// acpi_early_init();
	rest_init();
}



static int __initdata initcall_debug;

static int __init initcall_debug_setup(char *str)
{
	initcall_debug = 1;
	return 1;
}
__setup("initcall_debug", initcall_debug_setup);

struct task_struct *child_reaper = &init_task;

extern initcall_t __initcall_start[], __initcall_end[];

static void __init do_initcalls(void)
{
	initcall_t *call;
	int count = preempt_count();

	for (call = __initcall_start; call < __initcall_end; call++) {
		char *msg;

		if (initcall_debug) {
			printk(KERN_DEBUG "Calling initcall 0x%p", *call);
			print_fn_descriptor_symbol(": %s()", (unsigned long) *call);
			printk("\n");
		}

		(*call)();

		msg = NULL;

		msg = NULL;
		if (preempt_count() != count) {
			msg = "preemption imbalance";
			preempt_count() = count;
		}
		if (irqs_disabled()) {
			msg = "disabled interrupts";
			local_irq_enable();
		}
		if (msg) {
			printk("error in initcall at 0x%p: "
				"returned with %s\n", *call, msg);
		}
	}

	/* Make sure there is no pending stuff from the initcall sequence */
	flush_scheduled_work();
}

static void __init do_basic_setup(void)
{
	init_workqueues();
	usermodehelper_init();
	key_init();
	driver_init();

#ifdef CONFIG_SYSCTL
	sysctl_init();
#endif

	/* Networking initialization needs a process context */ 
	sock_init();

	do_initcalls();
}

static void do_pre_smp_initcalls(void)
{
	extern int spawn_ksoftirqd(void);
#ifdef CONFIG_SMP
	extern int migration_init(void);

	migration_init();
#endif
	spawn_ksoftirqd();
}

static void run_init_process(char *init_filename)
{
}

static inline void fixup_cpu_present_map(void)
{
#ifdef CONFIG_SMP
	int i;

	if (cpus_empty(cpu_present_map)) {
		for_each_cpu(i) {
			cpu_set(i, cpu_present_map);
		}
	}
#endif
}

static int init(void * unused)
{
	lock_kernel();

	child_reaper = current;

	smp_prepare_cpus(max_cpus);

	do_pre_smp_initcalls();

	fixup_cpu_present_map();
	smp_init();
	sched_init_smp();

	/*
	 * Do this before initcalls, because some drivers want to access
	 * firmware files.
	 */
	populate_rootfs();

	do_basic_setup();

	if (sys_access((const char __user *) "/init", 0) == 0)
		execute_command = "/init";
	else
		prepare_namespace();	

	free_initmem();
	unlock_kernel();
	system_state = SYSTEM_RUNNING;
	numa_default_policy();

	if (sys_open((const char __user *) "/dev/console", O_RDWR, 0) < 0)
		printk("Warning: unable to open an initial console.\n");

	for(;;)
		printk("int init\n");
	return 0;
}
