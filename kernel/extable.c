#include <linux/module.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include <asm/sections.h>

extern struct exception_table_entry __start___ex_table[];
extern struct exception_table_entry __stop___ex_table[];

/* Sort the kernel's built-in exception table */
void __init sort_main_extable(void) {
	sort_extable(__start___ex_table, __stop___ex_table);
}

/* Given an address, look for it in the exception tables. */
const struct exception_table_entry *search_exception_tables(unsigned long addr)
{
	const struct exception_table_entry *e;

	e = search_extable(__start___ex_table, __stop___ex_table-1, addr);
	if (!e)
		e = search_module_extables(addr);
	return e;
}