#include <asm/uaccess.h>

#include <linux/init.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/tty.h>
#include <linux/seq_file.h>
#include <linux/bitops.h>

static int tty_ldiscs_read_proc(char *page, char **start, off_t off,
				int count, int *eof, void *data);

/*
 * The /proc/tty directory inodes...
 */
static struct proc_dir_entry *proc_tty_ldisc, *proc_tty_driver;

static int show_tty_driver(struct seq_file *m, void *v)
{
	panic("in show_tty_driver");
    return 0;
}

static void *t_start(struct seq_file *m, loff_t *pos)
{
	struct list_head *p;
	loff_t l = *pos;
	list_for_each(p, &tty_drivers)
		if (!l--)
			return list_entry(p, struct tty_driver, tty_drivers);
	return NULL;
}

static void *t_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct list_head *p = ((struct tty_driver *)v)->tty_drivers.next;
	(*pos)++;
	return p==&tty_drivers ? NULL :
			list_entry(p, struct tty_driver, tty_drivers);
}

static void t_stop(struct seq_file *m, void *v)
{
}

static struct seq_operations tty_drivers_op = {
	.start	= t_start,
	.next	= t_next,
	.stop	= t_stop,
	.show	= show_tty_driver
};

static int tty_drivers_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &tty_drivers_op);
}

static struct file_operations proc_tty_drivers_operations = {
	.open		= tty_drivers_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int tty_ldiscs_read_proc(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	panic("in tty_ldiscs_read_proc");
    return 0;
}

void proc_tty_register_driver(struct tty_driver *driver)
{
	struct proc_dir_entry *ent;
		
	if ((!driver->read_proc && !driver->write_proc) ||
	    !driver->driver_name ||
	    driver->proc_entry)
		return;
	
	ent = create_proc_entry(driver->driver_name, 0, proc_tty_driver);
	if (!ent)
		return;
	ent->read_proc = driver->read_proc;
	ent->write_proc = driver->write_proc;
	ent->owner = driver->owner;
	ent->data = driver;

	driver->proc_entry = ent;
}

void proc_tty_unregister_driver(struct tty_driver *driver)
{
	struct proc_dir_entry *ent;

	ent = driver->proc_entry;
	if (!ent)
		return;
		
	remove_proc_entry(driver->driver_name, proc_tty_driver);
	
	driver->proc_entry = NULL;
}

void __init proc_tty_init(void)
{
    struct proc_dir_entry *entry;
	if (!proc_mkdir("tty", NULL))
		return;
	proc_tty_ldisc = proc_mkdir("tty/ldisc", NULL);

    proc_tty_driver = proc_mkdir_mode("tty/driver", S_IRUSR | S_IXUSR, NULL);

    create_proc_read_entry("tty/ldiscs", 0, NULL, tty_ldiscs_read_proc, NULL);
	entry = create_proc_entry("tty/drivers", 0, NULL);
	if (entry)
		entry->proc_fops = &proc_tty_drivers_operations;
}