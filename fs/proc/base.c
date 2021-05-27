#include <asm/uaccess.h>

#include <linux/config.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/namei.h>
#include <linux/namespace.h>
#include <linux/mm.h>
#include <linux/smp_lock.h>
#include <linux/kallsyms.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/ptrace.h>
#include "internal.h"

struct dentry *proc_pid_unhash(struct task_struct *p)
{
	struct dentry *proc_dentry;

    proc_dentry = p->proc_dentry;
    if (proc_dentry != NULL) {
        spin_lock(&dcache_lock);
        if (!d_unhashed(proc_dentry)) {
            dget_locked(proc_dentry);
            __d_drop(proc_dentry);
        } else
            proc_dentry = NULL;
        spin_unlock(&dcache_lock);
    }
    return proc_dentry;
}

void proc_pid_flush(struct dentry *proc_dentry)
{
    might_sleep();
    if (proc_dentry != NULL) {
        shrink_dcache_parent(proc_dentry);
        dput(proc_dentry);
    }
}
