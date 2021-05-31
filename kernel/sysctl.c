#include <linux/config.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/ctype.h>
#include <linux/utsname.h>
#include <linux/capability.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sysrq.h>
#include <linux/highuid.h>
#include <linux/writeback.h>
#include <linux/hugetlb.h>
#include <linux/security.h>
#include <linux/initrd.h>
#include <linux/times.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/syscalls.h>

#include <asm/uaccess.h>
#include <asm/processor.h>

#ifdef CONFIG_ROOT_NFS
#include <linux/nfs_fs.h>
#endif

#if defined(CONFIG_SYSCTL)


static ctl_table root_table[];
static struct ctl_table_header root_table_header =
	{ root_table, LIST_HEAD_INIT(root_table_header.ctl_entry) };

static ctl_table kern_table[];
static ctl_table vm_table[];
#ifdef CONFIG_NET
extern ctl_table net_table[];
#endif
static ctl_table proc_table[];
static ctl_table fs_table[];
static ctl_table debug_table[];
static ctl_table dev_table[];
extern ctl_table random_table[];
#ifdef CONFIG_UNIX98_PTYS
extern ctl_table pty_table[];
#endif

#ifdef CONFIG_PROC_FS

static ssize_t proc_readsys(struct file *, char __user *, size_t, loff_t *);
static ssize_t proc_writesys(struct file *, const char __user *, size_t, loff_t *);
static int proc_opensys(struct inode *, struct file *);

struct file_operations proc_sys_file_operations = {
	.open		= proc_opensys,
	.read		= proc_readsys,
	.write		= proc_writesys,
};

extern struct proc_dir_entry *proc_sys_root;

static void register_proc_table(ctl_table *, struct proc_dir_entry *);
static void unregister_proc_table(ctl_table *, struct proc_dir_entry *);
#endif


/* The default sysctl tables: */

static ctl_table root_table[] = {
	{
		.ctl_name	= CTL_KERN,
		.procname	= "kernel",
		.mode		= 0555,
		.child		= kern_table,
	},
	{
		.ctl_name	= CTL_VM,
		.procname	= "vm",
		.mode		= 0555,
		.child		= vm_table,
	},
#ifdef CONFIG_NET
	{
		.ctl_name	= CTL_NET,
		.procname	= "net",
		.mode		= 0555,
		.child		= net_table,
	},
#endif
	{
		.ctl_name	= CTL_PROC,
		.procname	= "proc",
		.mode		= 0555,
		.child		= proc_table,
	},
	{
		.ctl_name	= CTL_FS,
		.procname	= "fs",
		.mode		= 0555,
		.child		= fs_table,
	},
	{
		.ctl_name	= CTL_DEBUG,
		.procname	= "debug",
		.mode		= 0555,
		.child		= debug_table,
	},
	{
		.ctl_name	= CTL_DEV,
		.procname	= "dev",
		.mode		= 0555,
		.child		= dev_table,
	},
	{ .ctl_name = 0 }
};

static ctl_table kern_table[] = {
	{ .ctl_name = 0 }
};

static ctl_table vm_table[] = {
	{ .ctl_name = 0 }
};

static ctl_table proc_table[] = {
	{ .ctl_name = 0 }
};

static ctl_table fs_table[] = {
	{ .ctl_name = 0 }
};

static ctl_table debug_table[] = {
	{ .ctl_name = 0 }
};

static ctl_table dev_table[] = {
	{ .ctl_name = 0 }
};  

static int test_perm(int mode, int op)
{
	if (!current->euid)
		mode >>= 6;
	else if (in_egroup_p(0))
		mode >>= 3;
	if ((mode & op & 0007) == op)
		return 0;
	return -EACCES;
}

static inline int ctl_perm(ctl_table *table, int op)
{
	int error;
	error = security_sysctl(table, op);
	if (error)
		return error;
	return test_perm(table->mode, op);
}

static ssize_t do_rw_proc(int write, struct file * file, char __user * buf,
			  size_t count, loff_t *ppos)
{
	int op;
	struct proc_dir_entry *de;
	struct ctl_table *table;
	size_t res;
	ssize_t error;
	
	de = PDE(file->f_dentry->d_inode);
	if (!de || !de->data)
		return -ENOTDIR;
	table = (struct ctl_table *) de->data;
	if (!table || !table->proc_handler)
		return -ENOTDIR;
	op = (write ? 002 : 004);
	if (ctl_perm(table, op))
		return -EPERM;
	
	res = count;

	error = (*table->proc_handler) (table, write, file, buf, &res, ppos);
	if (error)
		return error;
	return res;
}



static int proc_opensys(struct inode *inode, struct file *file)
{
	if (file->f_mode & FMODE_WRITE) {
		if (!(inode->i_mode & S_IWUSR))
			return -EPERM;
	}

	return 0;
}

static ssize_t proc_readsys(struct file * file, char __user * buf,
			    size_t count, loff_t *ppos)
{
	return do_rw_proc(0, file, buf, count, ppos);
}

static ssize_t proc_writesys(struct file * file, const char __user * buf,
			     size_t count, loff_t *ppos)
{
	return do_rw_proc(1, file, (char __user *) buf, count, ppos);
}

extern void init_irq_proc (void);

void __init sysctl_init(void)
{
#ifdef CONFIG_PROC_FS
	register_proc_table(root_table, proc_sys_root);
	init_irq_proc();
#endif
}

#ifdef CONFIG_PROC_FS

/* Scan the sysctl entries in table and add them all into /proc */
static void register_proc_table(ctl_table * table, struct proc_dir_entry *root)
{
    struct proc_dir_entry *de;
	int len;
	mode_t mode;

	for (; table->ctl_name; table++) {
		if (!table->procname)
			continue;
		if (!table->proc_handler && !table->child) {
			printk(KERN_WARNING "SYSCTL: Can't register %s\n",
				table->procname);
			continue;
		}

		len = strlen(table->procname);
		mode = table->mode;

		de = NULL;
		if (table->proc_handler) {
			mode |= S_IFREG;
		} else {
			mode |= S_IFDIR;
			for (de = root->subdir; de; de = de->next) {
				if (proc_match(len, table->procname, de))
					break;
			}
		}
		if (!de) {
			de = create_proc_entry(table->procname, mode, root);
			if (!de)
				continue;
			de->data = (void *) table;
			if (table->proc_handler)
				de->proc_fops = &proc_sys_file_operations;
		}
		table->de = de;
		if (de->mode & S_IFDIR)
			register_proc_table(table->child, de);
	}
}

#endif


#else /* CONFIG_SYSCTL */
#endif /* CONFIG_SYSCTL */