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

#define XATTR_SELINUX_SUFFIX "selinux"
#define XATTR_NAME_SELINUX XATTR_SECURITY_PREFIX XATTR_SELINUX_SUFFIX

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

static void task_free_security(struct task_struct *task)
{
	struct task_security_struct *tsec = task->security;

	if (!tsec || tsec->magic != SELINUX_MAGIC)
		return;

	task->security = NULL;
	kfree(tsec);
}

static int inode_alloc_security(struct inode *inode)
{
	struct task_security_struct *tsec = current->security;
	struct inode_security_struct *isec;

	isec = kmalloc(sizeof(struct inode_security_struct), GFP_KERNEL);
	if (!isec)
		return -ENOMEM;

	memset(isec, 0, sizeof(struct inode_security_struct));
	init_MUTEX(&isec->sem);
	INIT_LIST_HEAD(&isec->list);
	isec->magic = SELINUX_MAGIC;
	isec->inode = inode;
	isec->sid = SECINITSID_UNLABELED;
	isec->sclass = SECCLASS_FILE;
	if (tsec && tsec->magic == SELINUX_MAGIC)
		isec->task_sid = tsec->sid;
	else
		isec->task_sid = SECINITSID_UNLABELED;
	inode->i_security = isec;

	return 0;
}

static void inode_free_security(struct inode *inode)
{
	struct inode_security_struct *isec = inode->i_security;
	struct superblock_security_struct *sbsec = inode->i_sb->s_security;

	if (!isec || isec->magic != SELINUX_MAGIC)
		return;

	spin_lock(&sbsec->isec_lock);
	if (!list_empty(&isec->list))
		list_del_init(&isec->list);
	spin_unlock(&sbsec->isec_lock);

	inode->i_security = NULL;
	kfree(isec);
}

static int file_alloc_security(struct file *file)
{
	struct task_security_struct *tsec = current->security;
	struct file_security_struct *fsec;

	fsec = kmalloc(sizeof(struct file_security_struct), GFP_ATOMIC);
	if (!fsec)
		return -ENOMEM;

	memset(fsec, 0, sizeof(struct file_security_struct));
	fsec->magic = SELINUX_MAGIC;
	fsec->file = file;
	if (tsec && tsec->magic == SELINUX_MAGIC) {
		fsec->sid = tsec->sid;
		fsec->fown_sid = tsec->sid;
	} else {
		fsec->sid = SECINITSID_UNLABELED;
		fsec->fown_sid = SECINITSID_UNLABELED;
	}
	file->f_security = fsec;

	return 0;
}

static void file_free_security(struct file *file)
{
	struct file_security_struct *fsec = file->f_security;

	if (!fsec || fsec->magic != SELINUX_MAGIC)
		return;

	file->f_security = NULL;
	kfree(fsec);
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

static void superblock_free_security(struct super_block *sb)
{
	struct superblock_security_struct *sbsec = sb->s_security;

	if (!sbsec || sbsec->magic != SELINUX_MAGIC)
		return;

	spin_lock(&sb_security_lock);
	if (!list_empty(&sbsec->list))
		list_del_init(&sbsec->list);
	spin_unlock(&sb_security_lock);

	sb->s_security = NULL;
	kfree(sbsec);
}

extern int ss_initialized;

static int superblock_doinit(struct super_block *sb, void *data)
{
	struct superblock_security_struct *sbsec = sb->s_security;
	struct dentry *root = sb->s_root;
	struct inode *inode = root->d_inode;
	int rc = 0;

	down(&sbsec->sem);
	if (sbsec->initialized)
		goto out;

	if (!ss_initialized) {
		/* Defer initialization until selinux_complete_init,
		   after the initial policy is loaded and the security
		   server is ready to handle calls. */
		spin_lock(&sb_security_lock);
		if (list_empty(&sbsec->list))
			list_add(&sbsec->list, &superblock_security_head);
		spin_unlock(&sb_security_lock);
		goto out;
	}
out:
	up(&sbsec->sem);
	return rc;
}

static inline u16 inode_mode_to_security_class(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFSOCK:
		return SECCLASS_SOCK_FILE;
	case S_IFLNK:
		return SECCLASS_LNK_FILE;
	case S_IFREG:
		return SECCLASS_FILE;
	case S_IFBLK:
		return SECCLASS_BLK_FILE;
	case S_IFDIR:
		return SECCLASS_DIR;
	case S_IFCHR:
		return SECCLASS_CHR_FILE;
	case S_IFIFO:
		return SECCLASS_FIFO_FILE;

	}

	return SECCLASS_FILE;
}

static inline u16 socket_type_to_security_class(int family, int type, int protocol)
{
	switch (family) {
	case PF_UNIX:
		switch (type) {
		case SOCK_STREAM:
		case SOCK_SEQPACKET:
			return SECCLASS_UNIX_STREAM_SOCKET;
		case SOCK_DGRAM:
			return SECCLASS_UNIX_DGRAM_SOCKET;
		}
		break;
	case PF_INET:
	case PF_INET6:
		switch (type) {
		case SOCK_STREAM:
			return SECCLASS_TCP_SOCKET;
		case SOCK_DGRAM:
			return SECCLASS_UDP_SOCKET;
		case SOCK_RAW:
			return SECCLASS_RAWIP_SOCKET;
		}
		break;
	case PF_NETLINK:
		switch (protocol) {
		case NETLINK_ROUTE:
			return SECCLASS_NETLINK_ROUTE_SOCKET;
		case NETLINK_FIREWALL:
			return SECCLASS_NETLINK_FIREWALL_SOCKET;
		case NETLINK_TCPDIAG:
			return SECCLASS_NETLINK_TCPDIAG_SOCKET;
		case NETLINK_NFLOG:
			return SECCLASS_NETLINK_NFLOG_SOCKET;
		case NETLINK_XFRM:
			return SECCLASS_NETLINK_XFRM_SOCKET;
		case NETLINK_SELINUX:
			return SECCLASS_NETLINK_SELINUX_SOCKET;
		case NETLINK_AUDIT:
			return SECCLASS_NETLINK_AUDIT_SOCKET;
		case NETLINK_IP6_FW:
			return SECCLASS_NETLINK_IP6FW_SOCKET;
		case NETLINK_DNRTMSG:
			return SECCLASS_NETLINK_DNRT_SOCKET;
		default:
			return SECCLASS_NETLINK_SOCKET;
		}
	case PF_PACKET:
		return SECCLASS_PACKET_SOCKET;
	case PF_KEY:
		return SECCLASS_KEY_SOCKET;
	}

	return SECCLASS_SOCKET;
}

#ifdef CONFIG_PROC_FS
static int selinux_proc_get_sid(struct proc_dir_entry *de,
				u16 tclass,
				u32 *sid)
{
	int buflen, rc;
	char *buffer, *path, *end;

	buffer = (char*)__get_free_page(GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	buflen = PAGE_SIZE;
	end = buffer+buflen;
	*--end = '\0';
	buflen--;
	path = end-1;
	*path = '/';
	while (de && de != de->parent) {
		buflen -= de->namelen + 1;
		if (buflen < 0)
			break;
		end -= de->namelen;
		memcpy(end, de->name, de->namelen);
		*--end = '/';
		path = end;
		de = de->parent;
	}
	rc = security_genfs_sid("proc", path, tclass, sid);
	free_page((unsigned long)buffer);
	return rc;
}
#else
static int selinux_proc_get_sid(struct proc_dir_entry *de,
				u16 tclass,
				u32 *sid)
{
	return -EINVAL;
}
#endif

static int inode_doinit_with_dentry(struct inode *inode, struct dentry *opt_dentry)
{
	struct superblock_security_struct *sbsec = NULL;
	struct inode_security_struct *isec = inode->i_security;
	u32 sid;
	struct dentry *dentry;
#define INITCONTEXTLEN 255
	char *context = NULL;
	unsigned len = 0;
	int rc = 0;
	int hold_sem = 0;

	if (isec->initialized)
		goto out;

	down(&isec->sem);
	hold_sem = 1;
	if (isec->initialized)
		goto out;

	sbsec = inode->i_sb->s_security;
	if (!sbsec->initialized) {
		/* Defer initialization until selinux_complete_init,
		   after the initial policy is loaded and the security
		   server is ready to handle calls. */
		spin_lock(&sbsec->isec_lock);
		if (list_empty(&isec->list))
			list_add(&isec->list, &sbsec->isec_head);
		spin_unlock(&sbsec->isec_lock);
		goto out;
	}

	switch (sbsec->behavior) {
	case SECURITY_FS_USE_XATTR:
		if (!inode->i_op->getxattr) {
			isec->sid = sbsec->def_sid;
			break;
		}

		/* Need a dentry, since the xattr API requires one.
		   Life would be simpler if we could just pass the inode. */
		if (opt_dentry) {
			/* Called from d_instantiate or d_splice_alias. */
			dentry = dget(opt_dentry);
		} else {
			/* Called from selinux_complete_init, try to find a dentry. */
			dentry = d_find_alias(inode);
		}
		if (!dentry) {
			printk(KERN_WARNING "%s:  no dentry for dev=%s "
			       "ino=%ld\n", __FUNCTION__, inode->i_sb->s_id,
			       inode->i_ino);
			goto out;
		}

		len = INITCONTEXTLEN;
		context = kmalloc(len, GFP_KERNEL);
		if (!context) {
			rc = -ENOMEM;
			dput(dentry);
			goto out;
		}
		rc = inode->i_op->getxattr(dentry, XATTR_NAME_SELINUX,
					   context, len);
		if (rc == -ERANGE) {
			/* Need a larger buffer.  Query for the right size. */
			rc = inode->i_op->getxattr(dentry, XATTR_NAME_SELINUX,
						   NULL, 0);
			if (rc < 0) {
				dput(dentry);
				goto out;
			}
			kfree(context);
			len = rc;
			context = kmalloc(len, GFP_KERNEL);
			if (!context) {
				rc = -ENOMEM;
				dput(dentry);
				goto out;
			}
			rc = inode->i_op->getxattr(dentry,
						   XATTR_NAME_SELINUX,
						   context, len);
		}
		dput(dentry);
		if (rc < 0) {
			if (rc != -ENODATA) {
				printk(KERN_WARNING "%s:  getxattr returned "
				       "%d for dev=%s ino=%ld\n", __FUNCTION__,
				       -rc, inode->i_sb->s_id, inode->i_ino);
				kfree(context);
				goto out;
			}
			/* Map ENODATA to the default file SID */
			sid = sbsec->def_sid;
			rc = 0;
		} else {
			rc = security_context_to_sid(context, rc, &sid);
			if (rc) {
				printk(KERN_WARNING "%s:  context_to_sid(%s) "
				       "returned %d for dev=%s ino=%ld\n",
				       __FUNCTION__, context, -rc,
				       inode->i_sb->s_id, inode->i_ino);
				kfree(context);
				goto out;
			}
		}
		kfree(context);
		isec->sid = sid;
		break;
	case SECURITY_FS_USE_TASK:
		isec->sid = isec->task_sid;
		break;
	case SECURITY_FS_USE_TRANS:
		/* Default to the fs SID. */
		isec->sid = sbsec->sid;

		/* Try to obtain a transition SID. */
		isec->sclass = inode_mode_to_security_class(inode->i_mode);
		rc = security_transition_sid(isec->task_sid,
					     sbsec->sid,
					     isec->sclass,
					     &sid);
		if (rc)
			goto out;
		isec->sid = sid;
		break;
	default:
		/* Default to the fs SID. */
		isec->sid = sbsec->sid;

		if (sbsec->proc) {
			struct proc_inode *proci = PROC_I(inode);
			if (proci->pde) {
				isec->sclass = inode_mode_to_security_class(inode->i_mode);
				rc = selinux_proc_get_sid(proci->pde,
							  isec->sclass,
							  &sid);
				if (rc)
					goto out;
				isec->sid = sid;
			}
		}
		break;
	}

	isec->initialized = 1;

out:
	if (inode->i_sock) {
		struct socket *sock = SOCKET_I(inode);
		if (sock->sk) {
			isec->sclass = socket_type_to_security_class(sock->sk->sk_family,
			                                             sock->sk->sk_type,
			                                             sock->sk->sk_protocol);
		} else {
			isec->sclass = SECCLASS_SOCKET;
		}
	} else {
		isec->sclass = inode_mode_to_security_class(inode->i_mode);
	}

	if (hold_sem)
		up(&isec->sem);
	return rc;
}

/* Convert a Linux signal to an access vector. */
static inline u32 signal_to_av(int sig)
{
	u32 perm = 0;

	switch (sig) {
	case SIGCHLD:
		/* Commonly granted from child to parent. */
		perm = PROCESS__SIGCHLD;
		break;
	case SIGKILL:
		/* Cannot be caught or ignored */
		perm = PROCESS__SIGKILL;
		break;
	case SIGSTOP:
		/* Cannot be caught or ignored */
		perm = PROCESS__SIGSTOP;
		break;
	default:
		/* All other signals. */
		perm = PROCESS__SIGNAL;
		break;
	}

	return perm;
}

/* Check permission betweeen a pair of tasks, e.g. signal checks,
   fork check, ptrace check, etc. */
int task_has_perm(struct task_struct *tsk1,
		  struct task_struct *tsk2,
		  u32 perms)
{
	struct task_security_struct *tsec1, *tsec2;

	tsec1 = tsk1->security;
	tsec2 = tsk2->security;
	return avc_has_perm(tsec1->sid, tsec2->sid,
			    SECCLASS_PROCESS, perms, NULL);
}

/* Check whether a task is allowed to use a capability. */
int task_has_capability(struct task_struct *tsk,
			int cap)
{
	struct task_security_struct *tsec;
	struct avc_audit_data ad;

	tsec = tsk->security;

	AVC_AUDIT_DATA_INIT(&ad,CAP);
	ad.tsk = tsk;
	ad.u.cap = cap;

	return avc_has_perm(tsec->sid, tsec->sid,
			    SECCLASS_CAPABILITY, CAP_TO_MASK(cap), &ad);
}

/* Check whether a task is allowed to use a system operation. */
int task_has_system(struct task_struct *tsk,
		    u32 perms)
{
	struct task_security_struct *tsec;

	tsec = tsk->security;

	return avc_has_perm(tsec->sid, SECINITSID_KERNEL,
			    SECCLASS_SYSTEM, perms, NULL);
}

int inode_has_perm(struct task_struct *tsk,
		   struct inode *inode,
		   u32 perms,
		   struct avc_audit_data *adp)
{
	struct task_security_struct *tsec;
	struct inode_security_struct *isec;
	struct avc_audit_data ad;

	tsec = tsk->security;
	isec = inode->i_security;

	if (!adp) {
		adp = &ad;
		AVC_AUDIT_DATA_INIT(&ad, FS);
		ad.u.fs.inode = inode;
	}

	return avc_has_perm(tsec->sid, isec->sid, isec->sclass, perms, adp);
}

static inline int dentry_has_perm(struct task_struct *tsk,
				  struct vfsmount *mnt,
				  struct dentry *dentry,
				  u32 av)
{
	struct inode *inode = dentry->d_inode;
	struct avc_audit_data ad;
	AVC_AUDIT_DATA_INIT(&ad,FS);
	ad.u.fs.mnt = mnt;
	ad.u.fs.dentry = dentry;
	return inode_has_perm(tsk, inode, av, &ad);
}

static inline int file_has_perm(struct task_struct *tsk,
				struct file *file,
				u32 av)
{
	struct task_security_struct *tsec = tsk->security;
	struct file_security_struct *fsec = file->f_security;
	struct vfsmount *mnt = file->f_vfsmnt;
	struct dentry *dentry = file->f_dentry;
	struct inode *inode = dentry->d_inode;
	struct avc_audit_data ad;
	int rc;

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.mnt = mnt;
	ad.u.fs.dentry = dentry;

	if (tsec->sid != fsec->sid) {
		rc = avc_has_perm(tsec->sid, fsec->sid,
				  SECCLASS_FD,
				  FD__USE,
				  &ad);
		if (rc)
			return rc;
	}

	/* av is zero if only checking access to the descriptor. */
	if (av)
		return inode_has_perm(tsk, inode, av, &ad);

	return 0;
}

/* Check whether a task can create a file. */
static int may_create(struct inode *dir,
		      struct dentry *dentry,
		      u16 tclass)
{
	struct task_security_struct *tsec;
	struct inode_security_struct *dsec;
	struct superblock_security_struct *sbsec;
	u32 newsid;
	struct avc_audit_data ad;
	int rc;

	tsec = current->security;
	dsec = dir->i_security;
	sbsec = dir->i_sb->s_security;

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.dentry = dentry;

	rc = avc_has_perm(tsec->sid, dsec->sid, SECCLASS_DIR,
			  DIR__ADD_NAME | DIR__SEARCH,
			  &ad);
	if (rc)
		return rc;

	if (tsec->create_sid && sbsec->behavior != SECURITY_FS_USE_MNTPOINT) {
		newsid = tsec->create_sid;
	} else {
		rc = security_transition_sid(tsec->sid, dsec->sid, tclass,
					     &newsid);
		if (rc)
			return rc;
	}

	rc = avc_has_perm(tsec->sid, newsid, tclass, FILE__CREATE, &ad);
	if (rc)
		return rc;

	return avc_has_perm(newsid, sbsec->sid,
			    SECCLASS_FILESYSTEM,
			    FILESYSTEM__ASSOCIATE, &ad);
}

#define MAY_LINK   0
#define MAY_UNLINK 1
#define MAY_RMDIR  2

/* Check whether a task can link, unlink, or rmdir a file/directory. */
static int may_link(struct inode *dir,
		    struct dentry *dentry,
		    int kind)

{
	struct task_security_struct *tsec;
	struct inode_security_struct *dsec, *isec;
	struct avc_audit_data ad;
	u32 av;
	int rc;

	tsec = current->security;
	dsec = dir->i_security;
	isec = dentry->d_inode->i_security;

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.dentry = dentry;

	av = DIR__SEARCH;
	av |= (kind ? DIR__REMOVE_NAME : DIR__ADD_NAME);
	rc = avc_has_perm(tsec->sid, dsec->sid, SECCLASS_DIR, av, &ad);
	if (rc)
		return rc;

	switch (kind) {
	case MAY_LINK:
		av = FILE__LINK;
		break;
	case MAY_UNLINK:
		av = FILE__UNLINK;
		break;
	case MAY_RMDIR:
		av = DIR__RMDIR;
		break;
	default:
		printk(KERN_WARNING "may_link:  unrecognized kind %d\n", kind);
		return 0;
	}

	rc = avc_has_perm(tsec->sid, isec->sid, isec->sclass, av, &ad);
	return rc;
}

static inline int may_rename(struct inode *old_dir,
			     struct dentry *old_dentry,
			     struct inode *new_dir,
			     struct dentry *new_dentry)
{
	struct task_security_struct *tsec;
	struct inode_security_struct *old_dsec, *new_dsec, *old_isec, *new_isec;
	struct avc_audit_data ad;
	u32 av;
	int old_is_dir, new_is_dir;
	int rc;

	tsec = current->security;
	old_dsec = old_dir->i_security;
	old_isec = old_dentry->d_inode->i_security;
	old_is_dir = S_ISDIR(old_dentry->d_inode->i_mode);
	new_dsec = new_dir->i_security;

	AVC_AUDIT_DATA_INIT(&ad, FS);

	ad.u.fs.dentry = old_dentry;
	rc = avc_has_perm(tsec->sid, old_dsec->sid, SECCLASS_DIR,
			  DIR__REMOVE_NAME | DIR__SEARCH, &ad);
	if (rc)
		return rc;
	rc = avc_has_perm(tsec->sid, old_isec->sid,
			  old_isec->sclass, FILE__RENAME, &ad);
	if (rc)
		return rc;
	if (old_is_dir && new_dir != old_dir) {
		rc = avc_has_perm(tsec->sid, old_isec->sid,
				  old_isec->sclass, DIR__REPARENT, &ad);
		if (rc)
			return rc;
	}

	ad.u.fs.dentry = new_dentry;
	av = DIR__ADD_NAME | DIR__SEARCH;
	if (new_dentry->d_inode)
		av |= DIR__REMOVE_NAME;
	rc = avc_has_perm(tsec->sid, new_dsec->sid, SECCLASS_DIR, av, &ad);
	if (rc)
		return rc;
	if (new_dentry->d_inode) {
		new_isec = new_dentry->d_inode->i_security;
		new_is_dir = S_ISDIR(new_dentry->d_inode->i_mode);
		rc = avc_has_perm(tsec->sid, new_isec->sid,
				  new_isec->sclass,
				  (new_is_dir ? DIR__RMDIR : FILE__UNLINK), &ad);
		if (rc)
			return rc;
	}

	return 0;
}

int superblock_has_perm(struct task_struct *tsk,
			struct super_block *sb,
			u32 perms,
			struct avc_audit_data *ad)
{
	struct task_security_struct *tsec;
	struct superblock_security_struct *sbsec;

	tsec = tsk->security;
	sbsec = sb->s_security;
	return avc_has_perm(tsec->sid, sbsec->sid, SECCLASS_FILESYSTEM,
			    perms, ad);
}

/* Convert a Linux mode and permission mask to an access vector. */
static inline u32 file_mask_to_av(int mode, int mask)
{
	u32 av = 0;

	if ((mode & S_IFMT) != S_IFDIR) {
		if (mask & MAY_EXEC)
			av |= FILE__EXECUTE;
		if (mask & MAY_READ)
			av |= FILE__READ;

		if (mask & MAY_APPEND)
			av |= FILE__APPEND;
		else if (mask & MAY_WRITE)
			av |= FILE__WRITE;

	} else {
		if (mask & MAY_EXEC)
			av |= DIR__SEARCH;
		if (mask & MAY_WRITE)
			av |= DIR__WRITE;
		if (mask & MAY_READ)
			av |= DIR__READ;
	}

	return av;
}

/* Convert a Linux file to an access vector. */
static inline u32 file_to_av(struct file *file)
{
	u32 av = 0;

	if (file->f_mode & FMODE_READ)
		av |= FILE__READ;
	if (file->f_mode & FMODE_WRITE) {
		if (file->f_flags & O_APPEND)
			av |= FILE__APPEND;
		else
			av |= FILE__WRITE;
	}

	return av;
}

/* Set an inode's SID to a specified value. */
int inode_security_set_sid(struct inode *inode, u32 sid)
{
	struct inode_security_struct *isec = inode->i_security;
	struct superblock_security_struct *sbsec = inode->i_sb->s_security;

	if (!sbsec->initialized) {
		/* Defer initialization to selinux_complete_init. */
		return 0;
	}

	down(&isec->sem);
	isec->sclass = inode_mode_to_security_class(inode->i_mode);
	isec->sid = sid;
	isec->initialized = 1;
	up(&isec->sem);
	return 0;
}

/* Set the security attributes on a newly created file. */
static int post_create(struct inode *dir,
		       struct dentry *dentry)
{

	struct task_security_struct *tsec;
	struct inode *inode;
	struct inode_security_struct *dsec;
	struct superblock_security_struct *sbsec;
	u32 newsid;
	char *context;
	unsigned int len;
	int rc;

	tsec = current->security;
	dsec = dir->i_security;
	sbsec = dir->i_sb->s_security;

	inode = dentry->d_inode;
	if (!inode) {
		/* Some file system types (e.g. NFS) may not instantiate
		   a dentry for all create operations (e.g. symlink),
		   so we have to check to see if the inode is non-NULL. */
		printk(KERN_WARNING "post_create:  no inode, dir (dev=%s, "
		       "ino=%ld)\n", dir->i_sb->s_id, dir->i_ino);
		return 0;
	}

	if (tsec->create_sid && sbsec->behavior != SECURITY_FS_USE_MNTPOINT) {
		newsid = tsec->create_sid;
	} else {
		rc = security_transition_sid(tsec->sid, dsec->sid,
					     inode_mode_to_security_class(inode->i_mode),
					     &newsid);
		if (rc) {
			printk(KERN_WARNING "post_create:  "
			       "security_transition_sid failed, rc=%d (dev=%s "
			       "ino=%ld)\n",
			       -rc, inode->i_sb->s_id, inode->i_ino);
			return rc;
		}
	}

	rc = inode_security_set_sid(inode, newsid);
	if (rc) {
		printk(KERN_WARNING "post_create:  inode_security_set_sid "
		       "failed, rc=%d (dev=%s ino=%ld)\n",
		       -rc, inode->i_sb->s_id, inode->i_ino);
		return rc;
	}

	if (sbsec->behavior == SECURITY_FS_USE_XATTR &&
	    inode->i_op->setxattr) {
		/* Use extended attributes. */
		rc = security_sid_to_context(newsid, &context, &len);
		if (rc) {
			printk(KERN_WARNING "post_create:  sid_to_context "
			       "failed, rc=%d (dev=%s ino=%ld)\n",
			       -rc, inode->i_sb->s_id, inode->i_ino);
			return rc;
		}
		down(&inode->i_sem);
		rc = inode->i_op->setxattr(dentry,
					   XATTR_NAME_SELINUX,
					   context, len, 0);
		up(&inode->i_sem);
		kfree(context);
		if (rc < 0) {
			printk(KERN_WARNING "post_create:  setxattr failed, "
			       "rc=%d (dev=%s ino=%ld)\n",
			       -rc, inode->i_sb->s_id, inode->i_ino);
			return rc;
		}
	}

	return 0;
}

static int selinux_ptrace(struct task_struct *parent, struct task_struct *child)
{
    struct task_security_struct *psec = parent->security;
	struct task_security_struct *csec = child->security;
	int rc;

	rc = secondary_ops->ptrace(parent,child);
	if (rc)
		return rc;

	rc = task_has_perm(parent, child, PROCESS__PTRACE);
	/* Save the SID of the tracing process for later use in apply_creds. */
	if (!rc)
		csec->ptrace_sid = psec->sid;
	return rc;
}

static int selinux_capget(struct task_struct *target, kernel_cap_t *effective,
                          kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
    int error;

	error = task_has_perm(current, target, PROCESS__GETCAP);
	if (error)
		return error;

	return secondary_ops->capget(target, effective, inheritable, permitted);
}

static int selinux_capset_check(struct task_struct *target, kernel_cap_t *effective,
                                kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
    int error;

	error = secondary_ops->capset_check(target, effective, inheritable, permitted);
	if (error)
		return error;

	return task_has_perm(current, target, PROCESS__SETCAP);
}

static void selinux_capset_set(struct task_struct *target, kernel_cap_t *effective,
                               kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
    secondary_ops->capset_set(target, effective, inheritable, permitted);
}

static int selinux_capable(struct task_struct *tsk, int cap)
{
    int rc;

	rc = secondary_ops->capable(tsk, cap);
	if (rc)
		return rc;

	return task_has_capability(tsk,cap);
}

static int selinux_sysctl(ctl_table *table, int op)
{
    int error = 0;
	u32 av;
	struct task_security_struct *tsec;
	u32 tsid;
	int rc;

	rc = secondary_ops->sysctl(table, op);
	if (rc)
		return rc;

	tsec = current->security;

	rc = selinux_proc_get_sid(table->de, (op == 001) ?
	                          SECCLASS_DIR : SECCLASS_FILE, &tsid);
	if (rc) {
		/* Default to the well-defined sysctl SID. */
		tsid = SECINITSID_SYSCTL;
	}

	/* The op values are "defined" in sysctl.c, thereby creating
	 * a bad coupling between this module and sysctl.c */
	if(op == 001) {
		error = avc_has_perm(tsec->sid, tsid,
				     SECCLASS_DIR, DIR__SEARCH, NULL);
	} else {
		av = 0;
		if (op & 004)
			av |= FILE__READ;
		if (op & 002)
			av |= FILE__WRITE;
		if (av)
			error = avc_has_perm(tsec->sid, tsid,
					     SECCLASS_FILE, av, NULL);
        }

	return error;
}

static int selinux_quotactl(int cmds, int type, int id, struct super_block *sb)
{
    int rc = 0;

	if (!sb)
		return 0;

	switch (cmds) {
		case Q_SYNC:
		case Q_QUOTAON:
		case Q_QUOTAOFF:
	        case Q_SETINFO:
		case Q_SETQUOTA:
			rc = superblock_has_perm(current,
						 sb,
						 FILESYSTEM__QUOTAMOD, NULL);
			break;
	        case Q_GETFMT:
	        case Q_GETINFO:
		case Q_GETQUOTA:
			rc = superblock_has_perm(current,
						 sb,
						 FILESYSTEM__QUOTAGET, NULL);
			break;
		default:
			rc = 0;  /* let the kernel handle invalid cmds */
			break;
	}
	return rc;
}

static int selinux_quota_on(struct dentry *dentry)
{
    return dentry_has_perm(current, NULL, dentry, FILE__QUOTAON);
}

static int selinux_syslog(int type)
{
    int rc;

	rc = secondary_ops->syslog(type);
	if (rc)
		return rc;

	switch (type) {
		case 3:         /* Read last kernel messages */
		case 10:        /* Return size of the log buffer */
			rc = task_has_system(current, SYSTEM__SYSLOG_READ);
			break;
		case 6:         /* Disable logging to console */
		case 7:         /* Enable logging to console */
		case 8:		/* Set level of messages printed to console */
			rc = task_has_system(current, SYSTEM__SYSLOG_CONSOLE);
			break;
		case 0:         /* Close log */
		case 1:         /* Open log */
		case 2:         /* Read from log */
		case 4:         /* Read/clear last kernel messages */
		case 5:         /* Clear ring buffer */
		default:
			rc = task_has_system(current, SYSTEM__SYSLOG_MOD);
			break;
	}
	return rc;
}

static int selinux_vm_enough_memory(long pages)
{
    int rc, cap_sys_admin = 0;
	struct task_security_struct *tsec = current->security;

	rc = secondary_ops->capable(current, CAP_SYS_ADMIN);
	if (rc == 0)
		rc = avc_has_perm_noaudit(tsec->sid, tsec->sid,
					SECCLASS_CAPABILITY,
					CAP_TO_MASK(CAP_SYS_ADMIN),
					NULL);

	if (rc == 0)
		cap_sys_admin = 1;

	return __vm_enough_memory(pages, cap_sys_admin);
}

static int selinux_bprm_alloc_security(struct linux_binprm *bprm)
{
    struct bprm_security_struct *bsec;

	bsec = kmalloc(sizeof(struct bprm_security_struct), GFP_KERNEL);
	if (!bsec)
		return -ENOMEM;

	memset(bsec, 0, sizeof *bsec);
	bsec->magic = SELINUX_MAGIC;
	bsec->bprm = bprm;
	bsec->sid = SECINITSID_UNLABELED;
	bsec->set = 0;

	bprm->security = bsec;
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
	superblock_free_security(sb);
}

static inline int match_prefix(char *prefix, int plen, char *option, int olen)
{
	if (plen > olen)
		return 0;

	return !memcmp(prefix, option, plen);
}

static inline int selinux_option(char *option, int len)
{
    return (match_prefix("context=", sizeof("context=")-1, option, len) ||
	        match_prefix("fscontext=", sizeof("fscontext=")-1, option, len) ||
	        match_prefix("defcontext=", sizeof("defcontext=")-1, option, len));
}

static inline void take_option(char **to, char *from, int *first, int len)
{
	if (!*first) {
		**to = ',';
		*to += 1;
	}
	else
		*first = 0;
	memcpy(*to, from, len);
	*to += len;
}

static int selinux_sb_copy_data(struct file_system_type *type, void *orig, void *copy)
{
    int fnosec, fsec, rc = 0;
	char *in_save, *in_curr, *in_end;
	char *sec_curr, *nosec_save, *nosec;

	in_curr = orig;
	sec_curr = copy;

	/* Binary mount data: just copy */
	if (type->fs_flags & FS_BINARY_MOUNTDATA) {
		copy_page(sec_curr, in_curr);
		goto out;
	}

	nosec = (char *)get_zeroed_page(GFP_KERNEL);
	if (!nosec) {
		rc = -ENOMEM;
		goto out;
	}

	nosec_save = nosec;
	fnosec = fsec = 1;
	in_save = in_end = orig;

	do {
		if (*in_end == ',' || *in_end == '\0') {
			int len = in_end - in_curr;

			if (selinux_option(in_curr, len))
				take_option(&sec_curr, in_curr, &fsec, len);
			else
				take_option(&nosec, in_curr, &fnosec, len);

			in_curr = in_end + 1;
		}
	} while (*in_end++);

	copy_page(in_save, nosec_save);
out:
	return rc;
}

static int selinux_sb_kern_mount(struct super_block *sb, void *data)
{
    struct avc_audit_data ad;
	int rc;

	rc = superblock_doinit(sb, data);
	if (rc)
		return rc;
	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.dentry = sb->s_root;
	return superblock_has_perm(current, sb, FILESYSTEM__MOUNT, &ad);
}

static int selinux_sb_statfs(struct super_block *sb)
{
    struct avc_audit_data ad;

	AVC_AUDIT_DATA_INIT(&ad,FS);
	ad.u.fs.dentry = sb->s_root;
	return superblock_has_perm(current, sb, FILESYSTEM__GETATTR, &ad);
}

static int selinux_mount(char * dev_name,
                         struct nameidata *nd,
                         char * type,
                         unsigned long flags,
                         void * data)
{
    int rc;

	rc = secondary_ops->sb_mount(dev_name, nd, type, flags, data);
	if (rc)
		return rc;

	if (flags & MS_REMOUNT)
		return superblock_has_perm(current, nd->mnt->mnt_sb,
		                           FILESYSTEM__REMOUNT, NULL);
	else
		return dentry_has_perm(current, nd->mnt, nd->dentry,
		                       FILE__MOUNTON);
}

static int selinux_umount(struct vfsmount *mnt, int flags)
{
    int rc;

	rc = secondary_ops->sb_umount(mnt, flags);
	if (rc)
		return rc;

	return superblock_has_perm(current,mnt->mnt_sb,
	                           FILESYSTEM__UNMOUNT,NULL);
}

static int selinux_inode_alloc_security(struct inode *inode)
{
    return inode_alloc_security(inode);
}

static void selinux_inode_free_security(struct inode *inode)
{
	inode_free_security(inode);
}

static int selinux_inode_create(struct inode *dir, struct dentry *dentry, int mask)
{
    return may_create(dir, dentry, SECCLASS_FILE);
}

static void selinux_inode_post_create(struct inode *dir, struct dentry *dentry, int mask)
{
	post_create(dir, dentry);
}

static int selinux_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
    int rc;

	rc = secondary_ops->inode_link(old_dentry,dir,new_dentry);
	if (rc)
		return rc;
	return may_link(dir, old_dentry, MAY_LINK);
}

static void selinux_inode_post_link(struct dentry *old_dentry, struct inode *inode, struct dentry *new_dentry)
{
	return;
}

static int selinux_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    int rc;

	rc = secondary_ops->inode_unlink(dir, dentry);
	if (rc)
		return rc;
	return may_link(dir, dentry, MAY_UNLINK);
}

static int selinux_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
    return may_create(dir, dentry, SECCLASS_LNK_FILE);
}

static void selinux_inode_post_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
	post_create(dir, dentry);
}

static int selinux_inode_mkdir(struct inode *dir, struct dentry *dentry, int mask)
{
    return may_create(dir, dentry, SECCLASS_DIR);
}

static void selinux_inode_post_mkdir(struct inode *dir, struct dentry *dentry, int mask)
{
    post_create(dir, dentry);
}

static int selinux_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    return may_link(dir, dentry, MAY_RMDIR);
}

static int selinux_inode_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
    int rc;

	rc = secondary_ops->inode_mknod(dir, dentry, mode, dev);
	if (rc)
		return rc;

	return may_create(dir, dentry, inode_mode_to_security_class(mode));
}

static void selinux_inode_post_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	post_create(dir, dentry);
}

static int selinux_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
                                struct inode *new_inode, struct dentry *new_dentry)
{
    return may_rename(old_inode, old_dentry, new_inode, new_dentry);
}

static void selinux_inode_post_rename(struct inode *old_inode, struct dentry *old_dentry,
                                      struct inode *new_inode, struct dentry *new_dentry)
{
	return;
}

static int selinux_inode_readlink(struct dentry *dentry)
{
    return dentry_has_perm(current, NULL, dentry, FILE__READ);
}

static int selinux_inode_follow_link(struct dentry *dentry, struct nameidata *nameidata)
{
    int rc;

	rc = secondary_ops->inode_follow_link(dentry,nameidata);
	if (rc)
		return rc;
	return dentry_has_perm(current, NULL, dentry, FILE__READ);
}

static int selinux_inode_permission(struct inode *inode, int mask,
				    struct nameidata *nd)
{
    int rc;

	rc = secondary_ops->inode_permission(inode, mask, nd);
	if (rc)
		return rc;

	if (!mask) {
		/* No permission to check.  Existence test. */
		return 0;
	}

	return inode_has_perm(current, inode,
			       file_mask_to_av(inode->i_mode, mask), NULL);
}

static int selinux_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
    int rc;

	rc = secondary_ops->inode_setattr(dentry, iattr);
	if (rc)
		return rc;

	if (iattr->ia_valid & ATTR_FORCE)
		return 0;

	if (iattr->ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID |
			       ATTR_ATIME_SET | ATTR_MTIME_SET))
		return dentry_has_perm(current, NULL, dentry, FILE__SETATTR);

	return dentry_has_perm(current, NULL, dentry, FILE__WRITE);
}

static int selinux_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
    return dentry_has_perm(current, mnt, dentry, FILE__GETATTR);
}

static int selinux_inode_setxattr(struct dentry *dentry, char *name, void *value, size_t size, int flags)
{
    struct task_security_struct *tsec = current->security;
	struct inode *inode = dentry->d_inode;
	struct inode_security_struct *isec = inode->i_security;
	struct superblock_security_struct *sbsec;
	struct avc_audit_data ad;
	u32 newsid;
	int rc = 0;

	if (strcmp(name, XATTR_NAME_SELINUX)) {
		if (!strncmp(name, XATTR_SECURITY_PREFIX,
			     sizeof XATTR_SECURITY_PREFIX - 1) &&
		    !capable(CAP_SYS_ADMIN)) {
			/* A different attribute in the security namespace.
			   Restrict to administrator. */
			return -EPERM;
		}

		/* Not an attribute we recognize, so just check the
		   ordinary setattr permission. */
		return dentry_has_perm(current, NULL, dentry, FILE__SETATTR);
	}

	sbsec = inode->i_sb->s_security;
	if (sbsec->behavior == SECURITY_FS_USE_MNTPOINT)
		return -EOPNOTSUPP;

	if ((current->fsuid != inode->i_uid) && !capable(CAP_FOWNER))
		return -EPERM;

	AVC_AUDIT_DATA_INIT(&ad,FS);
	ad.u.fs.dentry = dentry;

	rc = avc_has_perm(tsec->sid, isec->sid, isec->sclass,
			  FILE__RELABELFROM, &ad);
	if (rc)
		return rc;

	rc = security_context_to_sid(value, size, &newsid);
	if (rc)
		return rc;

	rc = avc_has_perm(tsec->sid, newsid, isec->sclass,
			  FILE__RELABELTO, &ad);
	if (rc)
		return rc;

	return avc_has_perm(newsid,
			    sbsec->sid,
			    SECCLASS_FILESYSTEM,
			    FILESYSTEM__ASSOCIATE,
			    &ad);
}

static void selinux_inode_post_setxattr(struct dentry *dentry, char *name,
                                        void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	struct inode_security_struct *isec = inode->i_security;
	u32 newsid;
	int rc;

	if (strcmp(name, XATTR_NAME_SELINUX)) {
		/* Not an attribute we recognize, so nothing to do. */
		return;
	}

	rc = security_context_to_sid(value, size, &newsid);
	if (rc) {
		printk(KERN_WARNING "%s:  unable to obtain SID for context "
		       "%s, rc=%d\n", __FUNCTION__, (char*)value, -rc);
		return;
	}

	isec->sid = newsid;
	return;
}

static int selinux_inode_getxattr (struct dentry *dentry, char *name)
{
    struct inode *inode = dentry->d_inode;
	struct superblock_security_struct *sbsec = inode->i_sb->s_security;

	if (sbsec->behavior == SECURITY_FS_USE_MNTPOINT)
		return -EOPNOTSUPP;

	return dentry_has_perm(current, NULL, dentry, FILE__GETATTR);
}

static int selinux_inode_listxattr (struct dentry *dentry)
{
    return dentry_has_perm(current, NULL, dentry, FILE__GETATTR);
}

static int selinux_inode_removexattr (struct dentry *dentry, char *name)
{
    if (strcmp(name, XATTR_NAME_SELINUX)) {
		if (!strncmp(name, XATTR_SECURITY_PREFIX,
			     sizeof XATTR_SECURITY_PREFIX - 1) &&
		    !capable(CAP_SYS_ADMIN)) {
			/* A different attribute in the security namespace.
			   Restrict to administrator. */
			return -EPERM;
		}

		/* Not an attribute we recognize, so just check the
		   ordinary setattr permission. Might want a separate
		   permission for removexattr. */
		return dentry_has_perm(current, NULL, dentry, FILE__SETATTR);
	}

	/* No one is allowed to remove a SELinux security label.
	   You can change the label, but all data must be labeled. */
	return -EACCES;
}

static int selinux_inode_getsecurity(struct inode *inode, const char *name, void *buffer, size_t size)
{
    struct inode_security_struct *isec = inode->i_security;
	char *context;
	unsigned len;
	int rc;

	/* Permission check handled by selinux_inode_getxattr hook.*/

	if (strcmp(name, XATTR_SELINUX_SUFFIX))
		return -EOPNOTSUPP;

	rc = security_sid_to_context(isec->sid, &context, &len);
	if (rc)
		return rc;

	if (!buffer || !size) {
		kfree(context);
		return len;
	}
	if (size < len) {
		kfree(context);
		return -ERANGE;
	}
	memcpy(buffer, context, len);
	kfree(context);
	return len;
}

static int selinux_inode_setsecurity(struct inode *inode, const char *name,
                                     const void *value, size_t size, int flags)
{
    struct inode_security_struct *isec = inode->i_security;
	u32 newsid;
	int rc;

	if (strcmp(name, XATTR_SELINUX_SUFFIX))
		return -EOPNOTSUPP;

	if (!value || !size)
		return -EACCES;

	rc = security_context_to_sid((void*)value, size, &newsid);
	if (rc)
		return rc;

	isec->sid = newsid;
	return 0;
}

static int selinux_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
    const int len = sizeof(XATTR_NAME_SELINUX);
	if (buffer && len <= buffer_size)
		memcpy(buffer, XATTR_NAME_SELINUX, len);
	return len;
}

static int selinux_file_permission(struct file *file, int mask)
{
    struct inode *inode = file->f_dentry->d_inode;

	if (!mask) {
		/* No permission to check.  Existence test. */
		return 0;
	}

	/* file_mask_to_av won't add FILE__WRITE if MAY_APPEND is set */
	if ((file->f_flags & O_APPEND) && (mask & MAY_WRITE))
		mask |= MAY_APPEND;

	return file_has_perm(current, file,
			     file_mask_to_av(inode->i_mode, mask));
}

static int selinux_file_alloc_security(struct file *file)
{
    return file_alloc_security(file);
}

static void selinux_file_free_security(struct file *file)
{
	file_free_security(file);
}

static int selinux_file_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
    int error = 0;

	switch (cmd) {
		case FIONREAD:
		/* fall through */
		case FIBMAP:
		/* fall through */
		case FIGETBSZ:
		/* fall through */
		case EXT2_IOC_GETFLAGS:
		/* fall through */
		case EXT2_IOC_GETVERSION:
			error = file_has_perm(current, file, FILE__GETATTR);
			break;

		case EXT2_IOC_SETFLAGS:
		/* fall through */
		case EXT2_IOC_SETVERSION:
			error = file_has_perm(current, file, FILE__SETATTR);
			break;

		/* sys_ioctl() checks */
		case FIONBIO:
		/* fall through */
		case FIOASYNC:
			error = file_has_perm(current, file, 0);
			break;

	        case KDSKBENT:
	        case KDSKBSENT:
			error = task_has_capability(current,CAP_SYS_TTY_CONFIG);
			break;

		/* default case assumes that the command will go
		 * to the file's ioctl() function.
		 */
		default:
			error = file_has_perm(current, file, FILE__IOCTL);

	}
	return error;
}

static int file_map_prot_check(struct file *file, unsigned long prot, int shared)
{
	if ((prot & PROT_EXEC) && (!file || (!shared && (prot & PROT_WRITE)))) {
		/*
		 * We are making executable an anonymous mapping or a
		 * private file mapping that will also be writable.
		 * This has an additional check.
		 */
		int rc = task_has_perm(current, current, PROCESS__EXECMEM);
		if (rc)
			return rc;
	}

	if (file) {
		/* read access is always possible with a mapping */
		u32 av = FILE__READ;

		/* write access only matters if the mapping is shared */
		if (shared && (prot & PROT_WRITE))
			av |= FILE__WRITE;

		if (prot & PROT_EXEC)
			av |= FILE__EXECUTE;

		return file_has_perm(current, file, av);
	}
	return 0;
}

static int selinux_file_mmap(struct file *file, unsigned long prot, unsigned long flags)
{
    int rc;

	rc = secondary_ops->file_mmap(file, prot, flags);
	if (rc)
		return rc;

	return file_map_prot_check(file, prot,
				   (flags & MAP_TYPE) == MAP_SHARED);
}

static int selinux_file_mprotect(struct vm_area_struct *vma,
				 unsigned long prot)
{
    int rc;

	rc = secondary_ops->file_mprotect(vma, prot);
	if (rc)
		return rc;

	if (vma->vm_file != NULL && vma->anon_vma != NULL && (prot & PROT_EXEC)) {
		/*
		 * We are making executable a file mapping that has
		 * had some COW done. Since pages might have been written,
		 * check ability to execute the possibly modified content.
		 * This typically should only occur for text relocations.
		 */
		int rc = file_has_perm(current, vma->vm_file, FILE__EXECMOD);
		if (rc)
			return rc;
	}

	return file_map_prot_check(vma->vm_file, prot, vma->vm_flags&VM_SHARED);
}

static int selinux_file_lock(struct file *file, unsigned int cmd)
{
    return file_has_perm(current, file, FILE__LOCK);
}

static int selinux_file_fcntl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
    int err = 0;

	switch (cmd) {
	        case F_SETFL:
			if (!file->f_dentry || !file->f_dentry->d_inode) {
				err = -EINVAL;
				break;
			}

			if ((file->f_flags & O_APPEND) && !(arg & O_APPEND)) {
				err = file_has_perm(current, file,FILE__WRITE);
				break;
			}
			/* fall through */
	        case F_SETOWN:
	        case F_SETSIG:
	        case F_GETFL:
	        case F_GETOWN:
	        case F_GETSIG:
			/* Just check FD__USE permission */
			err = file_has_perm(current, file, 0);
			break;
		case F_GETLK:
		case F_SETLK:
	        case F_SETLKW:
#if BITS_PER_LONG == 32
	        case F_GETLK64:
		case F_SETLK64:
	        case F_SETLKW64:
#endif
			if (!file->f_dentry || !file->f_dentry->d_inode) {
				err = -EINVAL;
				break;
			}
			err = file_has_perm(current, file, FILE__LOCK);
			break;
	}

	return err;
}

static int selinux_file_set_fowner(struct file *file)
{
    struct task_security_struct *tsec;
	struct file_security_struct *fsec;

	tsec = current->security;
	fsec = file->f_security;
	fsec->fown_sid = tsec->sid;

	return 0;
}

static int selinux_file_send_sigiotask(struct task_struct *tsk,
				       struct fown_struct *fown, int signum)
{
        struct file *file;
	u32 perm;
	struct task_security_struct *tsec;
	struct file_security_struct *fsec;

	/* struct fown_struct is never outside the context of a struct file */
        file = (struct file *)((long)fown - offsetof(struct file,f_owner));

	tsec = tsk->security;
	fsec = file->f_security;

	if (!signum)
		perm = signal_to_av(SIGIO); /* as per send_sigio_to_task */
	else
		perm = signal_to_av(signum);

	return avc_has_perm(fsec->fown_sid, tsec->sid,
			    SECCLASS_PROCESS, perm, NULL);
}

static int selinux_file_receive(struct file *file)
{
    return file_has_perm(current, file, file_to_av(file));
}

static int selinux_task_create(unsigned long clone_flags)
{
    int rc;

	rc = secondary_ops->task_create(clone_flags);
	if (rc)
		return rc;

	return task_has_perm(current, current, PROCESS__FORK);
}

static int selinux_task_alloc_security(struct task_struct *tsk)
{
    struct task_security_struct *tsec1, *tsec2;
	int rc;

	tsec1 = current->security;

	rc = task_alloc_security(tsk);
	if (rc)
		return rc;
	tsec2 = tsk->security;

	tsec2->osid = tsec1->osid;
	tsec2->sid = tsec1->sid;

	/* Retain the exec and create SIDs across fork */
	tsec2->exec_sid = tsec1->exec_sid;
	tsec2->create_sid = tsec1->create_sid;

	/* Retain ptracer SID across fork, if any.
	   This will be reset by the ptrace hook upon any
	   subsequent ptrace_attach operations. */
	tsec2->ptrace_sid = tsec1->ptrace_sid;

	return 0;
}

static void selinux_task_free_security(struct task_struct *tsk)
{
	task_free_security(tsk);
}

static int selinux_task_setuid(uid_t id0, uid_t id1, uid_t id2, int flags)
{
    return 0;
}

static int selinux_task_post_setuid(uid_t id0, uid_t id1, uid_t id2, int flags)
{
    return secondary_ops->task_post_setuid(id0,id1,id2,flags);
}

static int selinux_task_setgid(gid_t id0, gid_t id1, gid_t id2, int flags)
{
	/* See the comment for setuid above. */
	return 0;
}

static int selinux_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return task_has_perm(current, p, PROCESS__SETPGID);
}

static int selinux_task_getpgid(struct task_struct *p)
{
	return task_has_perm(current, p, PROCESS__GETPGID);
}

static int selinux_task_getsid(struct task_struct *p)
{
	return task_has_perm(current, p, PROCESS__GETSESSION);
}

static int selinux_task_setgroups(struct group_info *group_info)
{
	/* See the comment for setuid above. */
	return 0;
}

static int selinux_task_setnice(struct task_struct *p, int nice)
{
	int rc;

	rc = secondary_ops->task_setnice(p, nice);
	if (rc)
		return rc;

	return task_has_perm(current,p, PROCESS__SETSCHED);
}

static int selinux_task_setrlimit(unsigned int resource, struct rlimit *new_rlim)
{
	struct rlimit *old_rlim = current->signal->rlim + resource;
	int rc;

	rc = secondary_ops->task_setrlimit(resource, new_rlim);
	if (rc)
		return rc;

	/* Control the ability to change the hard limit (whether
	   lowering or raising it), so that the hard limit can
	   later be used as a safe reset point for the soft limit
	   upon context transitions. See selinux_bprm_apply_creds. */
	if (old_rlim->rlim_max != new_rlim->rlim_max)
		return task_has_perm(current, current, PROCESS__SETRLIMIT);

	return 0;
}

static int selinux_task_setscheduler(struct task_struct *p, int policy, struct sched_param *lp)
{
	return task_has_perm(current, p, PROCESS__SETSCHED);
}

static int selinux_task_getscheduler(struct task_struct *p)
{
	return task_has_perm(current, p, PROCESS__GETSCHED);
}

static int selinux_task_kill(struct task_struct *p, struct siginfo *info, int sig)
{
	u32 perm;
	int rc;

	rc = secondary_ops->task_kill(p, info, sig);
	if (rc)
		return rc;

	if (info && ((unsigned long)info == 1 ||
	             (unsigned long)info == 2 || SI_FROMKERNEL(info)))
		return 0;

	if (!sig)
		perm = PROCESS__SIGNULL; /* null signal; existence test */
	else
		perm = signal_to_av(sig);

	return task_has_perm(current, p, perm);
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
	u32 perm;

	perm = signal_to_av(p->exit_signal);

	return task_has_perm(p, current, perm);
}

static void selinux_task_reparent_to_init(struct task_struct *p)
{
	struct task_security_struct *tsec;

	secondary_ops->task_reparent_to_init(p);

	tsec = p->security;
	tsec->osid = tsec->sid;
	tsec->sid = SECINITSID_KERNEL;
	return;
}

static void selinux_task_to_inode(struct task_struct *p,
				  struct inode *inode)
{
	struct task_security_struct *tsec = p->security;
	struct inode_security_struct *isec = inode->i_security;

	isec->sid = tsec->sid;
	isec->initialized = 1;
	return;
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
	if (secondary_ops != original_ops) {
		printk(KERN_INFO "%s:  There is already a secondary security "
		       "module registered.\n", __FUNCTION__);
		return -EINVAL;
 	}

	secondary_ops = ops;

	printk(KERN_INFO "%s:  Registering secondary module %s\n",
	       __FUNCTION__,
	       name);

	return 0;
}

int selinux_unregister_security (const char *name, struct security_operations *ops)
{
	if (ops != secondary_ops) {
		printk (KERN_INFO "%s:  trying to unregister a security module "
		        "that is not registered.\n", __FUNCTION__);
		return -EINVAL;
	}

	secondary_ops = original_ops;

	return 0;
}

static void selinux_d_instantiate (struct dentry *dentry, struct inode *inode)
{
	if (inode)
		inode_doinit_with_dentry(inode, dentry);
}

static int selinux_getprocattr(struct task_struct *p,
			       char *name, void *value, size_t size)
{
	struct task_security_struct *tsec;
	u32 sid, len;
	char *context;
	int error;

	if (current != p) {
		error = task_has_perm(current, p, PROCESS__GETATTR);
		if (error)
			return error;
	}

	if (!size)
		return -ERANGE;

	tsec = p->security;

	if (!strcmp(name, "current"))
		sid = tsec->sid;
	else if (!strcmp(name, "prev"))
		sid = tsec->osid;
	else if (!strcmp(name, "exec"))
		sid = tsec->exec_sid;
	else if (!strcmp(name, "fscreate"))
		sid = tsec->create_sid;
	else
		return -EINVAL;

	if (!sid)
		return 0;

	error = security_sid_to_context(sid, &context, &len);
	if (error)
		return error;
	if (len > size) {
		kfree(context);
		return -ERANGE;
	}
	memcpy(value, context, len);
	kfree(context);
	return len;
}

static int selinux_setprocattr(struct task_struct *p,
			       char *name, void *value, size_t size)
{
	struct task_security_struct *tsec;
	u32 sid = 0;
	int error;

	if (current != p) {
		/* SELinux only allows a process to change its own
		   security attributes. */
		return -EACCES;
	}

	/*
	 * Basic control over ability to set these attributes at all.
	 * current == p, but we'll pass them separately in case the
	 * above restriction is ever removed.
	 */
	if (!strcmp(name, "exec"))
		error = task_has_perm(current, p, PROCESS__SETEXEC);
	else if (!strcmp(name, "fscreate"))
		error = task_has_perm(current, p, PROCESS__SETFSCREATE);
	else if (!strcmp(name, "current"))
		error = task_has_perm(current, p, PROCESS__SETCURRENT);
	else
		error = -EINVAL;
	if (error)
		return error;

	/* Obtain a SID for the context, if one was specified. */
	if (size) {
		int error;
		error = security_context_to_sid(value, size, &sid);
		if (error)
			return error;
	}

	/* Permission checking based on the specified context is
	   performed during the actual operation (execve,
	   open/mkdir/...), when we know the full context of the
	   operation.  See selinux_bprm_set_security for the execve
	   checks and may_create for the file creation checks. The
	   operation will then fail if the context is not permitted. */
	tsec = p->security;
	if (!strcmp(name, "exec"))
		tsec->exec_sid = sid;
	else if (!strcmp(name, "fscreate"))
		tsec->create_sid = sid;
	else if (!strcmp(name, "current")) {
		struct av_decision avd;

		if (sid == 0)
			return -EINVAL;

		/* Only allow single threaded processes to change context */
		if (atomic_read(&p->mm->mm_users) != 1) {
			struct task_struct *g, *t;
			struct mm_struct *mm = p->mm;
			read_lock(&tasklist_lock);
			do_each_thread(g, t)
				if (t->mm == mm && t != p) {
					read_unlock(&tasklist_lock);
					return -EPERM;
				}
			while_each_thread(g, t);
			read_unlock(&tasklist_lock);
                }

		/* Check permissions for the transition. */
		error = avc_has_perm(tsec->sid, sid, SECCLASS_PROCESS,
		                     PROCESS__DYNTRANSITION, NULL);
		if (error)
			return error;

		/* Check for ptracing, and update the task SID if ok.
		   Otherwise, leave SID unchanged and fail. */
		task_lock(p);
		if (p->ptrace & PT_PTRACED) {
			error = avc_has_perm_noaudit(tsec->ptrace_sid, sid,
						     SECCLASS_PROCESS,
						     PROCESS__PTRACE, &avd);
			if (!error)
				tsec->sid = sid;
			task_unlock(p);
			avc_audit(tsec->ptrace_sid, sid, SECCLASS_PROCESS,
				  PROCESS__PTRACE, &avd, error, NULL);
			if (error)
				return error;
		} else {
			tsec->sid = sid;
			task_unlock(p);
		}
	}
	else
		return -EINVAL;

	return size;
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