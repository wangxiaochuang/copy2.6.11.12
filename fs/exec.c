#include <linux/config.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/a.out.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/key.h>
#include <linux/personality.h>
#include <linux/binfmts.h>
#include <linux/swap.h>
#include <linux/utsname.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/ptrace.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/rmap.h>
#include <linux/acct.h>

#include <asm/uaccess.h>
#include <asm/mmu_context.h>

#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif



struct file *open_exec(const char *name)
{
    struct nameidata nd;
	int err;
	struct file *file;

	nd.intent.open.flags = FMODE_READ;
	err = path_lookup(name, LOOKUP_FOLLOW|LOOKUP_OPEN, &nd);
	file = ERR_PTR(err);

    if (!err) {
        struct inode *inode = nd.dentry->d_inode;
		file = ERR_PTR(-EACCES);
        if (!(nd.mnt->mnt_flags & MNT_NOEXEC) &&
		    S_ISREG(inode->i_mode)) {
            int err = permission(inode, MAY_EXEC, &nd);
			if (!err && !(inode->i_mode & 0111))
				err = -EACCES;
            file = ERR_PTR(err);
			if (!err) {
                file = dentry_open(nd.dentry, nd.mnt, O_RDONLY);
                if (!IS_ERR(file)) {
					err = deny_write_access(file);
					if (err) {
						fput(file);
						file = ERR_PTR(err);
					}
				}
out:
                return file;
            }
        }
        path_release(&nd);
    }
    goto out;
}


int do_execve(char * filename,
	char __user *__user *argv,
	char __user *__user *envp,
	struct pt_regs * regs)
{
    struct linux_binprm *bprm;
    struct file *file;
    int retval;
    int i;

    retval = -ENOMEM;
    bprm = kmalloc(sizeof(*bprm), GFP_KERNEL);
	if (!bprm)
		goto out_ret;
	memset(bprm, 0, sizeof(*bprm));

    file = open_exec(filename);
    retval = PTR_ERR(file);
	if (IS_ERR(file))
		goto out_kfree;
    

out_kfree:
	kfree(bprm);

out_ret:
	return retval;
}