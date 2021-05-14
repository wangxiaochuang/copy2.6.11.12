#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>
#include <linux/kd.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for sysctl_local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <asm/uaccess.h>
#include <asm/semaphore.h>
#include <asm/ioctls.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>

#include "avc.h"
#include "objsec.h"
#include "netif.h"

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
int selinux_enforcing = 0;

static int __init enforcing_setup(char *str)
{
	selinux_enforcing = simple_strtol(str,NULL,0);
	return 1;
}
__setup("enforcing=", enforcing_setup);
#endif

#ifdef CONFIG_SECURITY_SELINUX_BOOTPARAM
int selinux_enabled = CONFIG_SECURITY_SELINUX_BOOTPARAM_VALUE;

static int __init selinux_enabled_setup(char *str)
{
	selinux_enabled = simple_strtol(str, NULL, 0);
	return 1;
}
__setup("selinux=", selinux_enabled_setup);
#endif

/* Original (dummy) security module. */
static struct security_operations *original_ops = NULL;

/* Minimal support for a secondary security module,
   just to allow the use of the dummy or capability modules.
   The owlsm module can alternatively be used as a secondary
   module as long as CONFIG_OWLSM_FD is not enabled. */
static struct security_operations *secondary_ops = NULL;

static LIST_HEAD(superblock_security_head);
static DEFINE_SPINLOCK(sb_security_lock);

static int task_alloc_security(struct task_struct *task)
{
    struct task_security_struct *tsec;

	tsec = kmalloc(sizeof(struct task_security_struct), GFP_KERNEL);
	if (!tsec)
		return -ENOMEM;
    
    memset(tsec, 0, sizeof(struct task_security_struct));
	tsec->magic = SELINUX_MAGIC;
	tsec->task = task;
	tsec->osid = tsec->sid = tsec->ptrace_sid = SECINITSID_UNLABELED;
	task->security = tsec;

	return 0;
}

static int superblock_alloc_security(struct super_block *sb)
{
	struct superblock_security_struct *sbsec;

	sbsec = kmalloc(sizeof(struct superblock_security_struct), GFP_KERNEL);
	if (!sbsec)
		return -ENOMEM;

	memset(sbsec, 0, sizeof(struct superblock_security_struct));
	init_MUTEX(&sbsec->sem);
	INIT_LIST_HEAD(&sbsec->list);
	INIT_LIST_HEAD(&sbsec->isec_head);
	spin_lock_init(&sbsec->isec_lock);
	sbsec->magic = SELINUX_MAGIC;
	sbsec->sb = sb;
	sbsec->sid = SECINITSID_UNLABELED;
	sbsec->def_sid = SECINITSID_FILE;
	sb->s_security = sbsec;

	return 0;
}

static int selinux_ptrace(struct task_struct *parent, struct task_struct *child)
{
    return 0;
}

static int selinux_capget(struct task_struct *target, kernel_cap_t *effective,
                          kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
    return 0;
}

static int selinux_capset_check(struct task_struct *target, kernel_cap_t *effective,
                                kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
    return 0;
}

static void selinux_capset_set(struct task_struct *target, kernel_cap_t *effective,
                               kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
    
}

static int selinux_capable(struct task_struct *tsk, int cap)
{
    return 0;
}

static int selinux_sysctl(ctl_table *table, int op)
{
    return 0;
}

static int selinux_quotactl(int cmds, int type, int id, struct super_block *sb)
{
    return 0;
}

static int selinux_quota_on(struct dentry *dentry)
{
    return 0;
}

static int selinux_syslog(int type)
{
    return 0;
}

static int selinux_vm_enough_memory(long pages)
{
    return 0;
}

static int selinux_bprm_alloc_security(struct linux_binprm *bprm)
{
    return 0;
}

static int selinux_bprm_set_security(struct linux_binprm *bprm)
{
    return 0;
}

static int selinux_bprm_check_security (struct linux_binprm *bprm)
{
    return 0;
}

static int selinux_bprm_secureexec (struct linux_binprm *bprm)
{
    return 0;
}

static void selinux_bprm_free_security(struct linux_binprm *bprm)
{
}

static void selinux_bprm_apply_creds(struct linux_binprm *bprm, int unsafe)
{
}

static void selinux_bprm_post_apply_creds(struct linux_binprm *bprm)
{
}

static int selinux_sb_alloc_security(struct super_block *sb)
{
    return superblock_alloc_security(sb);
}

static void selinux_sb_free_security(struct super_block *sb)
{
}

static inline int selinux_option(char *option, int len)
{
    return 0;
}

static int selinux_sb_copy_data(struct file_system_type *type, void *orig, void *copy)
{
    return 0;
}

static int selinux_sb_kern_mount(struct super_block *sb, void *data)
{
    return 0;
}

static int selinux_sb_statfs(struct super_block *sb)
{
    return 0;
}

static int selinux_mount(char * dev_name,
                         struct nameidata *nd,
                         char * type,
                         unsigned long flags,
                         void * data)
{
    return 0;
}

static int selinux_umount(struct vfsmount *mnt, int flags)
{
    return 0;
}

static int selinux_inode_alloc_security(struct inode *inode)
{
    return 0;
}

static void selinux_inode_free_security(struct inode *inode)
{
}

static int selinux_inode_create(struct inode *dir, struct dentry *dentry, int mask)
{
    return 0;
}

static void selinux_inode_post_create(struct inode *dir, struct dentry *dentry, int mask)
{
}

static int selinux_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
    return 0;
}

static void selinux_inode_post_link(struct dentry *old_dentry, struct inode *inode, struct dentry *new_dentry)
{
	return;
}

static int selinux_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    return 0;
}

static int selinux_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
    return 0;
}

static void selinux_inode_post_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
}

static int selinux_inode_mkdir(struct inode *dir, struct dentry *dentry, int mask)
{
    return 0;
}

static void selinux_inode_post_mkdir(struct inode *dir, struct dentry *dentry, int mask)
{
    return;
}

static int selinux_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    return 0;
}

static int selinux_inode_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
    return 0;
}

static void selinux_inode_post_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
}

static int selinux_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
                                struct inode *new_inode, struct dentry *new_dentry)
{
    return 0;
}

static void selinux_inode_post_rename(struct inode *old_inode, struct dentry *old_dentry,
                                      struct inode *new_inode, struct dentry *new_dentry)
{
	return;
}

static int selinux_inode_readlink(struct dentry *dentry)
{
    return 0;
}

static int selinux_inode_follow_link(struct dentry *dentry, struct nameidata *nameidata)
{
    return 0;
}

static int selinux_inode_permission(struct inode *inode, int mask,
				    struct nameidata *nd)
{
    return 0;
}

static int selinux_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
    return 0;
}

static int selinux_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
    return 0;
}

static int selinux_inode_setxattr(struct dentry *dentry, char *name, void *value, size_t size, int flags)
{
    return 0;
}

static void selinux_inode_post_setxattr(struct dentry *dentry, char *name,
                                        void *value, size_t size, int flags)
{
}

static int selinux_inode_getxattr (struct dentry *dentry, char *name)
{
    return 0;
}

static int selinux_inode_listxattr (struct dentry *dentry)
{
    return 0;
}

static int selinux_inode_removexattr (struct dentry *dentry, char *name)
{
    return 0;
}

static int selinux_inode_getsecurity(struct inode *inode, const char *name, void *buffer, size_t size)
{
    return 0;
}

static int selinux_inode_setsecurity(struct inode *inode, const char *name,
                                     const void *value, size_t size, int flags)
{
    return 0;
}

static int selinux_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
    return 0;
}

static int selinux_file_permission(struct file *file, int mask)
{
    return 0;
}

static int selinux_file_alloc_security(struct file *file)
{
    return 0;
}

static void selinux_file_free_security(struct file *file)
{
}

static int selinux_file_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
    return 0;
}

static int selinux_file_mmap(struct file *file, unsigned long prot, unsigned long flags)
{
    return 0;
}

static int selinux_file_mprotect(struct vm_area_struct *vma,
				 unsigned long prot)
{
    return 0;
}

static int selinux_file_lock(struct file *file, unsigned int cmd)
{
    return 0;
}

static int selinux_file_fcntl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
    return 0;
}

static int selinux_file_set_fowner(struct file *file)
{
    return 0;
}

static int selinux_file_send_sigiotask(struct task_struct *tsk,
				       struct fown_struct *fown, int signum)
{
    return 0;
}

static int selinux_file_receive(struct file *file)
{
    return 0;
}

static int selinux_task_create(unsigned long clone_flags)
{
    return 0;
}

static int selinux_task_alloc_security(struct task_struct *tsk)
{
    return 0;
}

static void selinux_task_free_security(struct task_struct *tsk)
{
}

static int selinux_task_setuid(uid_t id0, uid_t id1, uid_t id2, int flags)
{
    return 0;
}

static int selinux_task_post_setuid(uid_t id0, uid_t id1, uid_t id2, int flags)
{
    return 0;
}

static int selinux_task_setgid(gid_t id0, gid_t id1, gid_t id2, int flags)
{
	/* See the comment for setuid above. */
	return 0;
}

static int selinux_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return 0;
}

static int selinux_task_getpgid(struct task_struct *p)
{
	return 0;
}

static int selinux_task_getsid(struct task_struct *p)
{
	return 0;
}

static int selinux_task_setgroups(struct group_info *group_info)
{
	/* See the comment for setuid above. */
	return 0;
}

static int selinux_task_setnice(struct task_struct *p, int nice)
{
	return 0;
}

static int selinux_task_setrlimit(unsigned int resource, struct rlimit *new_rlim)
{
	return 0;
}

static int selinux_task_setscheduler(struct task_struct *p, int policy, struct sched_param *lp)
{
	return 0;
}

static int selinux_task_getscheduler(struct task_struct *p)
{
	return 0;
}

static int selinux_task_kill(struct task_struct *p, struct siginfo *info, int sig)
{
	return 0;
}

static int selinux_task_prctl(int option,
			      unsigned long arg2,
			      unsigned long arg3,
			      unsigned long arg4,
			      unsigned long arg5)
{
	/* The current prctl operations do not appear to require
	   any SELinux controls since they merely observe or modify
	   the state of the current process. */
	return 0;
}

static int selinux_task_wait(struct task_struct *p)
{
	return 0;
}

static void selinux_task_reparent_to_init(struct task_struct *p)
{
}

static void selinux_task_to_inode(struct task_struct *p,
				  struct inode *inode)
{
}

#ifdef CONFIG_SECURITY_NETWORK

static int selinux_parse_skb_ipv4(struct sk_buff *skb, struct avc_audit_data *ad)
{
	return 0;
}

static int selinux_parse_skb(struct sk_buff *skb, struct avc_audit_data *ad,
			     char **addrp, int *len, int src)
{
	return 0;
}

static int selinux_socket_create(int family, int type,
				 int protocol, int kern)
{
	return 0;
}

static void selinux_socket_post_create(struct socket *sock, int family,
				       int type, int protocol, int kern)
{
}

static int selinux_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return 0;
}

static int selinux_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return 0;
}

static int selinux_socket_listen(struct socket *sock, int backlog)
{
	return 0;
}

static int selinux_socket_accept(struct socket *sock, struct socket *newsock)
{
	return 0;
}

static int selinux_socket_sendmsg(struct socket *sock, struct msghdr *msg,
 				  int size)
{
	return 0;
}

static int selinux_socket_recvmsg(struct socket *sock, struct msghdr *msg,
				  int size, int flags)
{
	return 0;
}

static int selinux_socket_getsockname(struct socket *sock)
{
	return 0;
}

static int selinux_socket_getpeername(struct socket *sock)
{
	return 0;
}

static int selinux_socket_setsockopt(struct socket *sock,int level,int optname)
{
	return 0;
}

static int selinux_socket_getsockopt(struct socket *sock, int level,
				     int optname)
{
	return 0;
}

static int selinux_socket_shutdown(struct socket *sock, int how)
{
	return 0;
}

static int selinux_socket_unix_stream_connect(struct socket *sock,
					      struct socket *other,
					      struct sock *newsk)
{
	return 0;
}

static int selinux_socket_unix_may_send(struct socket *sock,
					struct socket *other)
{
	return 0;
}

static int selinux_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int selinux_socket_getpeersec(struct socket *sock, char __user *optval,
				     int __user *optlen, unsigned len)
{
	return 0;
}

static int selinux_sk_alloc_security(struct sock *sk, int family, int priority)
{
	return 0;
}

static void selinux_sk_free_security(struct sock *sk)
{
}

static int selinux_nlmsg_perm(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

#ifdef CONFIG_NETFILTER
static unsigned int selinux_ip_postroute_last(unsigned int hooknum,
                                              struct sk_buff **pskb,
                                              const struct net_device *in,
                                              const struct net_device *out,
                                              int (*okfn)(struct sk_buff *),
                                              u16 family)
{
	return 0;
}

static unsigned int selinux_ipv4_postroute_last(unsigned int hooknum,
						struct sk_buff **pskb,
						const struct net_device *in,
						const struct net_device *out,
						int (*okfn)(struct sk_buff *))
{
	return 0;
}

#endif /* CONFIG_NETFILTER */

#else
#endif	/* CONFIG_SECURITY_NETWORK */

static int selinux_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int selinux_netlink_recv(struct sk_buff *skb)
{
	return 0;
}

static int selinux_msg_msg_alloc_security(struct msg_msg *msg)
{
	return 0;
}

static void selinux_msg_msg_free_security(struct msg_msg *msg)
{
}

static int selinux_msg_queue_alloc_security(struct msg_queue *msq)
{
	return 0;
}

static void selinux_msg_queue_free_security(struct msg_queue *msq)
{
}

static int selinux_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
	return 0;
}

static int selinux_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
	return 0;
}

static int selinux_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg, int msqflg)
{
	return 0;
}

static int selinux_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
				    struct task_struct *target,
				    long type, int mode)
{
	return 0;
}

static int selinux_shm_alloc_security(struct shmid_kernel *shp)
{
	return 0;
}

static void selinux_shm_free_security(struct shmid_kernel *shp)
{
}

static int selinux_shm_associate(struct shmid_kernel *shp, int shmflg)
{
	return 0;
}

static int selinux_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	return 0;
}

static int selinux_shm_shmat(struct shmid_kernel *shp,
			     char __user *shmaddr, int shmflg)
{
	return 0;
}

static int selinux_sem_alloc_security(struct sem_array *sma)
{
	return 0;
}

static void selinux_sem_free_security(struct sem_array *sma)
{
}

static int selinux_sem_associate(struct sem_array *sma, int semflg)
{
	return 0;
}

static int selinux_sem_semctl(struct sem_array *sma, int cmd)
{
	return 0;
}

static int selinux_sem_semop(struct sem_array *sma,
			     struct sembuf *sops, unsigned nsops, int alter)
{
	return 0;
}

static int selinux_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	return 0;
}

int selinux_register_security (const char *name, struct security_operations *ops)
{
	return 0;
}

int selinux_unregister_security (const char *name, struct security_operations *ops)
{
	return 0;
}

static void selinux_d_instantiate (struct dentry *dentry, struct inode *inode)
{
}

static int selinux_getprocattr(struct task_struct *p,
			       char *name, void *value, size_t size)
{
	return 0;
}

static int selinux_setprocattr(struct task_struct *p,
			       char *name, void *value, size_t size)
{
	return 0;
}




struct security_operations selinux_ops = {
	.ptrace =			selinux_ptrace,
	.capget =			selinux_capget,
	.capset_check =			selinux_capset_check,
	.capset_set =			selinux_capset_set,
	.sysctl =			selinux_sysctl,
	.capable =			selinux_capable,
	.quotactl =			selinux_quotactl,
	.quota_on =			selinux_quota_on,
	.syslog =			selinux_syslog,
	.vm_enough_memory =		selinux_vm_enough_memory,

	.netlink_send =			selinux_netlink_send,
        .netlink_recv =			selinux_netlink_recv,

	.bprm_alloc_security =		selinux_bprm_alloc_security,
	.bprm_free_security =		selinux_bprm_free_security,
	.bprm_apply_creds =		selinux_bprm_apply_creds,
	.bprm_post_apply_creds =	selinux_bprm_post_apply_creds,
	.bprm_set_security =		selinux_bprm_set_security,
	.bprm_check_security =		selinux_bprm_check_security,
	.bprm_secureexec =		selinux_bprm_secureexec,

	.sb_alloc_security =		selinux_sb_alloc_security,
	.sb_free_security =		selinux_sb_free_security,
	.sb_copy_data =			selinux_sb_copy_data,
	.sb_kern_mount =	        selinux_sb_kern_mount,
	.sb_statfs =			selinux_sb_statfs,
	.sb_mount =			selinux_mount,
	.sb_umount =			selinux_umount,

	.inode_alloc_security =		selinux_inode_alloc_security,
	.inode_free_security =		selinux_inode_free_security,
	.inode_create =			selinux_inode_create,
	.inode_post_create =		selinux_inode_post_create,
	.inode_link =			selinux_inode_link,
	.inode_post_link =		selinux_inode_post_link,
	.inode_unlink =			selinux_inode_unlink,
	.inode_symlink =		selinux_inode_symlink,
	.inode_post_symlink =		selinux_inode_post_symlink,
	.inode_mkdir =			selinux_inode_mkdir,
	.inode_post_mkdir =		selinux_inode_post_mkdir,
	.inode_rmdir =			selinux_inode_rmdir,
	.inode_mknod =			selinux_inode_mknod,
	.inode_post_mknod =		selinux_inode_post_mknod,
	.inode_rename =			selinux_inode_rename,
	.inode_post_rename =		selinux_inode_post_rename,
	.inode_readlink =		selinux_inode_readlink,
	.inode_follow_link =		selinux_inode_follow_link,
	.inode_permission =		selinux_inode_permission,
	.inode_setattr =		selinux_inode_setattr,
	.inode_getattr =		selinux_inode_getattr,
	.inode_setxattr =		selinux_inode_setxattr,
	.inode_post_setxattr =		selinux_inode_post_setxattr,
	.inode_getxattr =		selinux_inode_getxattr,
	.inode_listxattr =		selinux_inode_listxattr,
	.inode_removexattr =		selinux_inode_removexattr,
	.inode_getsecurity =            selinux_inode_getsecurity,
	.inode_setsecurity =            selinux_inode_setsecurity,
	.inode_listsecurity =           selinux_inode_listsecurity,

	.file_permission =		selinux_file_permission,
	.file_alloc_security =		selinux_file_alloc_security,
	.file_free_security =		selinux_file_free_security,
	.file_ioctl =			selinux_file_ioctl,
	.file_mmap =			selinux_file_mmap,
	.file_mprotect =		selinux_file_mprotect,
	.file_lock =			selinux_file_lock,
	.file_fcntl =			selinux_file_fcntl,
	.file_set_fowner =		selinux_file_set_fowner,
	.file_send_sigiotask =		selinux_file_send_sigiotask,
	.file_receive =			selinux_file_receive,

	.task_create =			selinux_task_create,
	.task_alloc_security =		selinux_task_alloc_security,
	.task_free_security =		selinux_task_free_security,
	.task_setuid =			selinux_task_setuid,
	.task_post_setuid =		selinux_task_post_setuid,
	.task_setgid =			selinux_task_setgid,
	.task_setpgid =			selinux_task_setpgid,
	.task_getpgid =			selinux_task_getpgid,
	.task_getsid =		        selinux_task_getsid,
	.task_setgroups =		selinux_task_setgroups,
	.task_setnice =			selinux_task_setnice,
	.task_setrlimit =		selinux_task_setrlimit,
	.task_setscheduler =		selinux_task_setscheduler,
	.task_getscheduler =		selinux_task_getscheduler,
	.task_kill =			selinux_task_kill,
	.task_wait =			selinux_task_wait,
	.task_prctl =			selinux_task_prctl,
	.task_reparent_to_init =	selinux_task_reparent_to_init,
	.task_to_inode =                selinux_task_to_inode,

	.ipc_permission =		selinux_ipc_permission,

	.msg_msg_alloc_security =	selinux_msg_msg_alloc_security,
	.msg_msg_free_security =	selinux_msg_msg_free_security,

	.msg_queue_alloc_security =	selinux_msg_queue_alloc_security,
	.msg_queue_free_security =	selinux_msg_queue_free_security,
	.msg_queue_associate =		selinux_msg_queue_associate,
	.msg_queue_msgctl =		selinux_msg_queue_msgctl,
	.msg_queue_msgsnd =		selinux_msg_queue_msgsnd,
	.msg_queue_msgrcv =		selinux_msg_queue_msgrcv,

	.shm_alloc_security =		selinux_shm_alloc_security,
	.shm_free_security =		selinux_shm_free_security,
	.shm_associate =		selinux_shm_associate,
	.shm_shmctl =			selinux_shm_shmctl,
	.shm_shmat =			selinux_shm_shmat,

	.sem_alloc_security = 		selinux_sem_alloc_security,
	.sem_free_security =  		selinux_sem_free_security,
	.sem_associate =		selinux_sem_associate,
	.sem_semctl =			selinux_sem_semctl,
	.sem_semop =			selinux_sem_semop,

	.register_security =		selinux_register_security,
	.unregister_security =		selinux_unregister_security,

	.d_instantiate =                selinux_d_instantiate,

	.getprocattr =                  selinux_getprocattr,
	.setprocattr =                  selinux_setprocattr,

#ifdef CONFIG_SECURITY_NETWORK
        .unix_stream_connect =		selinux_socket_unix_stream_connect,
	.unix_may_send =		selinux_socket_unix_may_send,

	.socket_create =		selinux_socket_create,
	.socket_post_create =		selinux_socket_post_create,
	.socket_bind =			selinux_socket_bind,
	.socket_connect =		selinux_socket_connect,
	.socket_listen =		selinux_socket_listen,
	.socket_accept =		selinux_socket_accept,
	.socket_sendmsg =		selinux_socket_sendmsg,
	.socket_recvmsg =		selinux_socket_recvmsg,
	.socket_getsockname =		selinux_socket_getsockname,
	.socket_getpeername =		selinux_socket_getpeername,
	.socket_getsockopt =		selinux_socket_getsockopt,
	.socket_setsockopt =		selinux_socket_setsockopt,
	.socket_shutdown =		selinux_socket_shutdown,
	.socket_sock_rcv_skb =		selinux_socket_sock_rcv_skb,
	.socket_getpeersec =		selinux_socket_getpeersec,
	.sk_alloc_security =		selinux_sk_alloc_security,
	.sk_free_security =		selinux_sk_free_security,
#endif
};

__init int selinux_init(void)
{
    struct task_security_struct *tsec;
    if (!selinux_enabled) {
		printk(KERN_INFO "SELinux:  Disabled at boot.\n");
		return 0;
	}

    printk(KERN_INFO "SELinux:  Initializing.\n");

    /* Set the security state for the initial task. */
	if (task_alloc_security(current))
		panic("SELinux:  Failed to initialize initial task.\n");
    tsec = current->security;
	tsec->osid = tsec->sid = SECINITSID_KERNEL;

    avc_init();

    original_ops = secondary_ops = security_ops;
	if (!secondary_ops)
		panic ("SELinux: No initial security operations\n");
	if (register_security (&selinux_ops))
		panic("SELinux: Unable to register with kernel.\n");

	if (selinux_enforcing) {
		printk(KERN_INFO "SELinux:  Starting in enforcing mode\n");
	} else {
		printk(KERN_INFO "SELinux:  Starting in permissive mode\n");
	}
	return 0;
}

security_initcall(selinux_init);