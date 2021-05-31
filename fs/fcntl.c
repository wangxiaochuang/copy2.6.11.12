#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dnotify.h>
#include <linux/smp_lock.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/ptrace.h>

#include <asm/poll.h>
#include <asm/siginfo.h>
#include <asm/uaccess.h>

static void f_modown(struct file *filp, unsigned long pid,
                     uid_t uid, uid_t euid, int force)
{
	write_lock_irq(&filp->f_owner.lock);
	if (force || !filp->f_owner.pid) {
		filp->f_owner.pid = pid;
		filp->f_owner.uid = uid;
		filp->f_owner.euid = euid;
	}
	write_unlock_irq(&filp->f_owner.lock);
}

int f_setown(struct file *filp, unsigned long arg, int force)
{
	int err;
	
	err = security_file_set_fowner(filp);
	if (err)
		return err;

	f_modown(filp, arg, current->uid, current->euid, force);
	return 0;
}

void send_sigio(struct fown_struct *fown, int fd, int band)
{
    panic("in send_sigio function");
}