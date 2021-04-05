#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>

#include <asm/sections.h>

const char *kallsyms_lookup(unsigned long addr,
			    unsigned long *symbolsize,
			    unsigned long *offset,
			    char **modname, char *namebuf) 
{
	return NULL;
}

/* Replace "%s" in format with address, or returns -errno. */
void __print_symbol(const char *fmt, unsigned long address)
{
	char *modname;
	const char *name;
	unsigned long offset, size;
	char namebuf[KSYM_NAME_LEN+1];
	char buffer[sizeof("%s+%#lx/%#lx [%s]") + KSYM_NAME_LEN +
		    2*(BITS_PER_LONG*3/10) + MODULE_NAME_LEN + 1];

	name = kallsyms_lookup(address, &size, &offset, &modname, namebuf);

	if (!name)
		sprintf(buffer, "0x%lx", address);
	else {
		if (modname)
			sprintf(buffer, "%s+%#lx/%#lx [%s]", name, offset,
				size, modname);
		else
			sprintf(buffer, "%s+%#lx/%#lx", name, offset, size);
	}
	printk(fmt, buffer);
}