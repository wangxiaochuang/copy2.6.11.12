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

/* Untouched command line (eg. for /proc) saved by arch-specific code. */
char saved_command_line[COMMAND_LINE_SIZE];

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

asmlinkage void __init start_kernel(void) {
    char *command_line;
    extern struct kernel_param __start___param[], __stop__param[];
    lock_kernel();
    page_address_init();
    printk("%s", linux_banner);
    setup_arch(&command_line);
    setup_per_cpu_areas();

    smp_prepare_boot_cpu();

    sched_init();
    for(;;);
}
