#include <linux/config.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/elf.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/rcupdate.h>
#include <linux/cpu.h>
#include <linux/moduleparam.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/vermagic.h>
#include <linux/notifier.h>
#include <linux/stop_machine.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <asm/semaphore.h>
#include <asm/cacheflush.h>

#if 0
#define DEBUGP printk
#else
#define DEBUGP(fmt , a...)
#endif

/* Protects module list */
static DEFINE_SPINLOCK(modlist_lock);

/* List of modules, protected by module_mutex AND modlist_lock */
static DECLARE_MUTEX(module_mutex);
static LIST_HEAD(modules);

unsigned int module_refcount(struct module *mod)
{
	unsigned int i, total = 0;

	for (i = 0; i < NR_CPUS; i++)
		total += local_read(&mod->ref[i].count);
	return total;
}
EXPORT_SYMBOL(module_refcount);

/* Given an address, look for it in the module exception tables. */
const struct exception_table_entry *search_module_extables(unsigned long addr)
{
	unsigned long flags;
	const struct exception_table_entry *e = NULL;
	struct module *mod;

	spin_lock_irqsave(&modlist_lock, flags);
	list_for_each_entry(mod, &modules, list) {
		if (mod->num_exentries == 0)
			continue;
				
		e = search_extable(mod->extable,
				   mod->extable + mod->num_exentries - 1,
				   addr);
		if (e)
			break;
	}
	spin_unlock_irqrestore(&modlist_lock, flags);

	/* Now, if we found one, we are running inside it now, hence
           we cannot unload the module, hence no refcnt needed. */
	return e;
}