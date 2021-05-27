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

void send_sigio(struct fown_struct *fown, int fd, int band)
{
    panic("in send_sigio function");
}