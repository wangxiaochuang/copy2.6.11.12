#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/pagemap.h>
#include <linux/dnotify.h>
#include <linux/smp_lock.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <asm/namei.h>
#include <asm/uaccess.h>

#define ACC_MODE(x) ("\000\004\002\006"[(x)&O_ACCMODE])

static inline int do_getname(const char __user *filename, char *page)
{
	int retval;
	unsigned long len = PATH_MAX;

	if (!segment_eq(get_fs(), KERNEL_DS)) {
		if ((unsigned long) filename >= TASK_SIZE)
			return -EFAULT;
		if (TASK_SIZE - (unsigned long) filename < PATH_MAX)
			len = TASK_SIZE - (unsigned long) filename;
	}

	retval = strncpy_from_user(page, filename, len);
	if (retval > 0) {
		if (retval < len)
			return 0;
		return -ENAMETOOLONG;
	} else if (!retval)
		retval = -ENOENT;
	return retval;
}

char * getname(const char __user * filename)
{
	char *tmp, *result;

	result = ERR_PTR(-ENOMEM);
	tmp = __getname();
	if (tmp) {
		int retval = do_getname(filename, tmp);

		result = tmp;
		if (retval < 0) {
			__putname(tmp);
			result = ERR_PTR(retval);
		}
	}
	if (unlikely(current->audit_context) && !IS_ERR(result) && result)
		audit_getname(result);
	return result;
}

int generic_permission(struct inode *inode, int mask,
		int (*check_acl)(struct inode *inode, int mask))
{
	umode_t			mode = inode->i_mode;

	if (current->fsuid == inode->i_uid)
		mode >>= 6;
	else {
		if (IS_POSIXACL(inode) && (mode & S_IRWXG) && check_acl) {
			int error = check_acl(inode, mask);
			if (error == -EACCES)
				goto check_capabilities;
			else if (error != -EAGAIN)
				return error;
		}

		if (in_group_p(inode->i_gid))
			mode >>= 3;
	}

	/*
	 * If the DACs are ok we don't need any capability check.
	 */
	if (((mode & mask & (MAY_READ|MAY_WRITE|MAY_EXEC)) == mask))
		return 0;

 check_capabilities:
	/*
	 * Read/write DACs are always overridable.
	 * Executable DACs are overridable if at least one exec bit is set.
	 */
	if (!(mask & MAY_EXEC) ||
	    (inode->i_mode & S_IXUGO) || S_ISDIR(inode->i_mode))
		if (capable(CAP_DAC_OVERRIDE))
			return 0;

	/*
	 * Searching includes executable on directories, else just read.
	 */
	if (mask == MAY_READ || (S_ISDIR(inode->i_mode) && !(mask & MAY_WRITE)))
		if (capable(CAP_DAC_READ_SEARCH))
			return 0;

	return -EACCES;
}

int permission(struct inode *inode, int mask, struct nameidata *nd)
{
	int retval, submask;

	if (mask & MAY_WRITE) {
		umode_t mode = inode->i_mode;

		/*
		 * Nobody gets write access to a read-only fs.
		 */
		if (IS_RDONLY(inode) &&
		    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			return -EROFS;

		/*
		 * Nobody gets write access to an immutable file.
		 */
		if (IS_IMMUTABLE(inode))
			return -EACCES;
	}


	/* Ordinary permission routines do not understand MAY_APPEND. */
	submask = mask & ~MAY_APPEND;
	if (inode->i_op && inode->i_op->permission)
		retval = inode->i_op->permission(inode, submask, nd);
	else
		retval = generic_permission(inode, submask, NULL);
	if (retval)
		return retval;

	return security_inode_permission(inode, mask, nd);
}

int get_write_access(struct inode * inode)
{
	spin_lock(&inode->i_lock);
	if (atomic_read(&inode->i_writecount) < 0) {
		spin_unlock(&inode->i_lock);
		return -ETXTBSY;
	}
	atomic_inc(&inode->i_writecount);
	spin_unlock(&inode->i_lock);

	return 0;
}

int deny_write_access(struct file * file)
{
	struct inode *inode = file->f_dentry->d_inode;

	spin_lock(&inode->i_lock);
	if (atomic_read(&inode->i_writecount) > 0) {
		spin_unlock(&inode->i_lock);
		return -ETXTBSY;
	}
	atomic_dec(&inode->i_writecount);
	spin_unlock(&inode->i_lock);

	return 0;
}

void path_release(struct nameidata *nd)
{
	dput(nd->dentry);
	mntput(nd->mnt);
}

/*
 * Internal lookup() using the new generic dcache.
 * SMP-safe
 */
static struct dentry * cached_lookup(struct dentry * parent, struct qstr * name, struct nameidata *nd)
{
	struct dentry * dentry = __d_lookup(parent, name);

	/* lockess __d_lookup may fail due to concurrent d_move() 
	 * in some unrelated directory, so try with d_lookup
	 */
	if (!dentry)
		dentry = d_lookup(parent, name);

	if (dentry && dentry->d_op && dentry->d_op->d_revalidate) {
		if (!dentry->d_op->d_revalidate(dentry, nd) && !d_invalidate(dentry)) {
			dput(dentry);
			dentry = NULL;
		}
	}
	return dentry;
}

static inline int exec_permission_lite(struct inode *inode,
				       struct nameidata *nd)
{
	umode_t	mode = inode->i_mode;

	if (inode->i_op && inode->i_op->permission)
		return -EAGAIN;

	if (current->fsuid == inode->i_uid)
		mode >>= 6;
	else if (in_group_p(inode->i_gid))
		mode >>= 3;

	if (mode & MAY_EXEC)
		goto ok;

	if ((inode->i_mode & S_IXUGO) && capable(CAP_DAC_OVERRIDE))
		goto ok;

	if (S_ISDIR(inode->i_mode) && capable(CAP_DAC_OVERRIDE))
		goto ok;

	if (S_ISDIR(inode->i_mode) && capable(CAP_DAC_READ_SEARCH))
		goto ok;

	return -EACCES;
ok:
	return security_inode_permission(inode, MAY_EXEC, nd);
}

static struct dentry * real_lookup(struct dentry * parent, struct qstr * name, struct nameidata *nd)
{
	struct dentry *result;
	struct inode *dir = parent->d_inode;

	down(&dir->i_sem);

	result = d_lookup(parent, name);
	if (!result) {
		struct dentry *dentry = d_alloc(parent, name);
		result = ERR_PTR(-ENOMEM);
		if (dentry) {
			result = dir->i_op->lookup(dir, dentry, nd);
			if (result)
				dput(dentry);
			else
				result = dentry;
		}
		up(&dir->i_sem);
		return result;
	}

	up(&dir->i_sem);
	if (result->d_op && result->d_op->d_revalidate) {
		if (!result->d_op->d_revalidate(result, nd) && !d_invalidate(result)) {
			dput(result);
			result = ERR_PTR(-ENOENT);
		}
	}
	return result;
}

int follow_up(struct vfsmount **mnt, struct dentry **dentry)
{
	return 0;
}

static int follow_mount(struct vfsmount **mnt, struct dentry **dentry)
{
	int res = 0;
	while (d_mountpoint(*dentry)) {
		struct vfsmount *mounted = lookup_mnt(*mnt, *dentry);
		if (!mounted)
			break;
		mntput(*mnt);
		*mnt = mounted;
		dput(*dentry);
		*dentry = dget(mounted->mnt_root);
		res = 1;
	}
	return res;
}

static inline int __follow_down(struct vfsmount **mnt, struct dentry **dentry)
{
	struct vfsmount *mounted;

	mounted = lookup_mnt(*mnt, *dentry);
	if (mounted) {
		mntput(*mnt);
		*mnt = mounted;
		dput(*dentry);
		*dentry = dget(mounted->mnt_root);
		return 1;
	}
	return 0;
}

int follow_down(struct vfsmount **mnt, struct dentry **dentry)
{
	return __follow_down(mnt,dentry);
}

static inline void follow_dotdot(struct vfsmount **mnt, struct dentry **dentry)
{
	while (1) {
		struct vfsmount *parent;
		struct dentry *old = *dentry;

		read_lock(&current->fs->lock);
		if (*dentry == current->fs->root &&
			*mnt == current->fs->rootmnt) {
				read_unlock(&current->fs->lock);
			break;
		}
		read_unlock(&current->fs->lock);
		spin_lock(&dcache_lock);
		if (*dentry != (*mnt)->mnt_root) {
			*dentry = dget((*dentry)->d_parent);
			spin_unlock(&dcache_lock);
			dput(old);
			break;
		}
		spin_unlock(&dcache_lock);
		spin_lock(&vfsmount_lock);
		parent = (*mnt)->mnt_parent;
		if (parent == *mnt) {
			spin_unlock(&vfsmount_lock);
			break;
		}
		mntget(parent);
		*dentry = dget((*mnt)->mnt_mountpoint);
		spin_unlock(&vfsmount_lock);
		dput(old);
		mntput(*mnt);
		*mnt = parent;
	}
	follow_mount(mnt, dentry);
}

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

/* SMP-safe */
static inline int
walk_init_root(const char *name, struct nameidata *nd)
{
	read_lock(&current->fs->lock);
	if (current->fs->altroot && !(nd->flags & LOOKUP_NOALT)) {
		panic("in walk_init_root function");
	}
	nd->mnt = mntget(current->fs->rootmnt);
	nd->dentry = dget(current->fs->root);
	read_unlock(&current->fs->lock);
	return 1;
}

static inline int __vfs_follow_link(struct nameidata *nd, const char *link)
{
	int res = 0;
	char *name;
	if (IS_ERR(link))
		goto fail;

	if (*link == '/') {
		path_release(nd);
		if (!walk_init_root(link, nd))
			/* weird __emul_prefix() stuff did it */
			goto out;
	}
	res = link_path_walk(link, nd);
out:
	if (nd->depth || res || nd->last_type!=LAST_NORM)
		return res;
	/*
	 * If it is an iterative symlinks resolution in open_namei() we
	 * have to copy the last component. And all that crap because of
	 * bloody create() on broken symlinks. Furrfu...
	 */
	name = __getname();
	if (unlikely(!name)) {
		path_release(nd);
		return -ENOMEM;
	}
	strcpy(name, nd->last.name);
	nd->last.name = name;
	return 0;
fail:
	path_release(nd);
	return PTR_ERR(link);
}

static inline int __do_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	int error;

	touch_atime(nd->mnt, dentry);
	nd_set_link(nd, NULL);
	error = dentry->d_inode->i_op->follow_link(dentry, nd);
	if (!error) {
		char *s = nd_get_link(nd);
		if (s)
			error = __vfs_follow_link(nd, s);
		if (dentry->d_inode->i_op->put_link)
			dentry->d_inode->i_op->put_link(dentry, nd);
	}

	return error;
}

static inline int do_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	int err = -ELOOP;
	if (current->link_count >= MAX_NESTED_LINKS)
		goto loop;
	if (current->total_link_count >= 40)
		goto loop;
	BUG_ON(nd->depth >= MAX_NESTED_LINKS);
	cond_resched();
	err = security_inode_follow_link(dentry, nd);
	if (err)
		goto loop;
	current->link_count++;
	current->total_link_count++;
	nd->depth++;
	err = __do_follow_link(dentry, nd);
	current->link_count--;
	nd->depth--;
	return err;
loop:
	path_release(nd);
	return err;
}

static int do_lookup(struct nameidata *nd, struct qstr *name,
		     struct path *path)
{
	struct vfsmount *mnt = nd->mnt;
	struct dentry *dentry = __d_lookup(nd->dentry, name);

	if (!dentry)	
		goto need_lookup;
	if (dentry->d_op && dentry->d_op->d_revalidate)
		goto need_revalidate;

done:
	path->mnt = mnt;
	path->dentry = dentry;
	return 0;

need_lookup:
	dentry = real_lookup(nd->dentry, name, nd);
	if (IS_ERR(dentry))
		goto fail;
	goto done;

need_revalidate:
	if (dentry->d_op->d_revalidate(dentry, nd))
		goto done;
	if (d_invalidate(dentry))
		goto done;
	dput(dentry);
	goto need_lookup;

fail:
	return PTR_ERR(dentry);
}

int fastcall link_path_walk(const char * name, struct nameidata *nd)
{
	struct path next;
	struct inode *inode;
	int err;
	unsigned int lookup_flags = nd->flags;

	while (*name == '/')
		name++;
	if (!*name)
		goto return_reval;

	inode = nd->dentry->d_inode;
	if (nd->depth)
		lookup_flags = LOOKUP_FOLLOW;

	for (;;) {
		unsigned long hash;
		struct qstr this;
		unsigned int c;

		err = exec_permission_lite(inode, nd);
		if (err == -EAGAIN) {
			err = permission(inode, MAY_EXEC, nd);
		}
		if (err)
			break;

		this.name = name;
		c = *(const unsigned char *) name;

		hash = init_name_hash();
		do {
			name++;
			hash = partial_name_hash(c, hash);
			c = *(const unsigned char *) name;
		} while (c && (c != '/'));
		this.len = name - (const char *) this.name;
		this.hash = end_name_hash(hash);

		if (!c)
			goto last_component;
		while (*++name == '/');
		if (!*name)
			goto last_with_slashes;

		if (this.name[0] == '.') switch (this.len) {
			default:
				break;
			case 2:
				if (this.name[1] != '.')
					break;
				follow_dotdot(&nd->mnt, &nd->dentry);
				inode = nd->dentry->d_inode;
			case 1:
				continue;
		}

		if (nd->dentry->d_op && nd->dentry->d_op->d_hash) {
			err = nd->dentry->d_op->d_hash(nd->dentry, &this);
			if (err < 0)
				break;
		}
		nd->flags |= LOOKUP_CONTINUE;
		err = do_lookup(nd, &this, &next);
		if (err)
			break;
		follow_mount(&next.mnt, &next.dentry);

		err = -ENOENT;
		inode = next.dentry->d_inode;
		if (!inode)
			goto out_dput;
		err = -ENOTDIR; 
		if (!inode->i_op)
			goto out_dput;

		if (inode->i_op->follow_link) {
			mntget(next.mnt);
			err = do_follow_link(next.dentry, nd);
			dput(next.dentry);
			mntput(next.mnt);
			if (err)
				goto return_err;
			err = -ENOENT;
			inode = nd->dentry->d_inode;
			if (!inode)
				break;
			err = -ENOTDIR; 
			if (!inode->i_op)
				break;
		} else {
			dput(nd->dentry);
			nd->mnt = next.mnt;
			nd->dentry = next.dentry;
		}
		err = -ENOTDIR; 
		if (!inode->i_op->lookup)
			break;
		continue;

last_with_slashes:
		lookup_flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
last_component:
		nd->flags &= ~LOOKUP_CONTINUE;
		if (lookup_flags & LOOKUP_PARENT)
			goto lookup_parent;
		if (this.name[0] == '.') switch (this.len) {
			default:
				break;
			case 2:	
				if (this.name[1] != '.')
					break;
				follow_dotdot(&nd->mnt, &nd->dentry);
				inode = nd->dentry->d_inode;
				/* fallthrough */
			case 1:
				goto return_reval;
		}
		if (nd->dentry->d_op && nd->dentry->d_op->d_hash) {
			err = nd->dentry->d_op->d_hash(nd->dentry, &this);
			if (err < 0)
				break;
		}
		err = do_lookup(nd, &this, &next);
		if (err)
			break;
		follow_mount(&next.mnt, &next.dentry);
		inode = next.dentry->d_inode;
		if ((lookup_flags & LOOKUP_FOLLOW)
		    && inode && inode->i_op && inode->i_op->follow_link) {
			mntget(next.mnt);
			err = do_follow_link(next.dentry, nd);
			dput(next.dentry);
			mntput(next.mnt);
			if (err)
				goto return_err;
			inode = nd->dentry->d_inode;
		} else {
			dput(nd->dentry);
			nd->mnt = next.mnt;
			nd->dentry = next.dentry;
		}
		err = -ENOENT;
		if (!inode)
			break;
		if (lookup_flags & LOOKUP_DIRECTORY) {
			err = -ENOTDIR; 
			if (!inode->i_op || !inode->i_op->lookup)
				break;
		}
		goto return_base;
lookup_parent:
		nd->last = this;
		nd->last_type = LAST_NORM;
		if (this.name[0] != '.')
			goto return_base;
		if (this.len == 1)
			nd->last_type = LAST_DOT;
		else if (this.len == 2 && this.name[1] == '.')
			nd->last_type = LAST_DOTDOT;
		else
			goto return_base;
return_reval:
		/*
		 * We bypassed the ordinary revalidation routines.
		 * We may need to check the cached dentry for staleness.
		 */
		if (nd->dentry && nd->dentry->d_sb &&
		    (nd->dentry->d_sb->s_type->fs_flags & FS_REVAL_DOT)) {
			err = -ESTALE;
			/* Note: we do not d_invalidate() */
			if (!nd->dentry->d_op->d_revalidate(nd->dentry, nd))
				break;
		}
return_base:
		return 0;
out_dput:
		dput(next.dentry);
		break;
	}
	path_release(nd);
return_err:
	return err;
}

int fastcall path_walk(const char * name, struct nameidata *nd)
{
	current->total_link_count = 0;
	return link_path_walk(name, nd);
}

void set_fs_altroot(void)
{
	panic("in set_fs_altroot function");
}

int fastcall path_lookup(const char *name, unsigned int flags, struct nameidata *nd)
{
	int retval;

	nd->last_type = LAST_ROOT;
	nd->flags = flags;
	nd->depth = 0;

	read_lock(&current->fs->lock);
	if (*name == '/') {
		if (current->fs->altroot && !(nd->flags & LOOKUP_NOALT)) {
			panic("in current->fs->altroot");
		}
		nd->mnt = mntget(current->fs->rootmnt);
		nd->dentry = dget(current->fs->root);
	} else {
		nd->mnt = mntget(current->fs->pwdmnt);
		nd->dentry = dget(current->fs->pwd);
	}
	read_unlock(&current->fs->lock);
	current->total_link_count = 0;
	retval = link_path_walk(name, nd);
	if (unlikely(current->audit_context
		     && nd && nd->dentry && nd->dentry->d_inode))
		audit_inode(name,
			    nd->dentry->d_inode->i_ino,
			    nd->dentry->d_inode->i_rdev);
	return retval;
}

static struct dentry * __lookup_hash(struct qstr *name, struct dentry * base, struct nameidata *nd)
{
	struct dentry * dentry;
	struct inode *inode;
	int err;

	inode = base->d_inode;
	err = permission(inode, MAY_EXEC, nd);
	dentry = ERR_PTR(err);
	if (err)
		goto out;
	if (base->d_op && base->d_op->d_hash) {
		err = base->d_op->d_hash(base, name);
		dentry = ERR_PTR(err);
		if (err < 0)
			goto out;
	}

	dentry = cached_lookup(base, name, nd);
	if (!dentry) {
		struct dentry *new = d_alloc(base, name);
		dentry = ERR_PTR(-ENOMEM);
		if (!new)
			goto out;
		dentry = inode->i_op->lookup(inode, new, nd);
		if (!dentry)
			dentry = new;
		else
			dput(new);
	}
out:
	return dentry;
}

struct dentry * lookup_hash(struct qstr *name, struct dentry * base)
{
	return __lookup_hash(name, base, NULL);
}



int fastcall __user_walk(const char __user *name, unsigned flags, struct nameidata *nd)
{
	char *tmp = getname(name);
	int err = PTR_ERR(tmp);

	if (!IS_ERR(tmp)) {
		err = path_lookup(tmp, flags, nd);
		putname(tmp);
	}
	return err;
}

/*
 * It's inline, so penalty for filesystems that don't use sticky bit is
 * minimal.
 */
static inline int check_sticky(struct inode *dir, struct inode *inode)
{
	if (!(dir->i_mode & S_ISVTX))
		return 0;
	if (inode->i_uid == current->fsuid)
		return 0;
	if (dir->i_uid == current->fsuid)
		return 0;
	return !capable(CAP_FOWNER);
}

static inline int may_delete(struct inode *dir,struct dentry *victim,int isdir)
{
	return 0;
}

static inline int may_create(struct inode *dir, struct dentry *child,
			     struct nameidata *nd)
{
	if (child->d_inode)
		return -EEXIST;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	return permission(dir,MAY_WRITE | MAY_EXEC, nd);
}


/* 
 * Special case: O_CREAT|O_EXCL implies O_NOFOLLOW for security
 * reasons.
 *
 * O_DIRECTORY translates into forcing a directory lookup.
 */
static inline int lookup_flags(unsigned int f)
{
	unsigned long retval = LOOKUP_FOLLOW;
	if (f & O_NOFOLLOW)
		retval &= ~LOOKUP_FOLLOW;

	if ((f & (O_CREAT|O_EXCL)) == (O_CREAT|O_EXCL))
		retval &= ~LOOKUP_FOLLOW;

	if (f & O_DIRECTORY)
		retval |= LOOKUP_DIRECTORY;

	return retval;
}

struct dentry *lock_rename(struct dentry *p1, struct dentry *p2)
{
	struct dentry *p;

	if (p1 == p2) {
		down(&p1->d_inode->i_sem);
		return NULL;
	}

	down(&p1->d_inode->i_sb->s_vfs_rename_sem);

	for (p = p1; p->d_parent != p; p = p->d_parent) {
		if (p->d_parent == p2) {
			down(&p2->d_inode->i_sem);
			down(&p1->d_inode->i_sem);
			return p;
		}
	}

	for (p = p2; p->d_parent != p; p = p->d_parent) {
		if (p->d_parent == p1) {
			down(&p1->d_inode->i_sem);
			down(&p2->d_inode->i_sem);
			return p;
		}
	}

	down(&p1->d_inode->i_sem);
	down(&p2->d_inode->i_sem);
	return NULL;
}

void unlock_rename(struct dentry *p1, struct dentry *p2)
{
	up(&p1->d_inode->i_sem);
	if (p1 != p2) {
		up(&p2->d_inode->i_sem);
		up(&p1->d_inode->i_sb->s_vfs_rename_sem);
	}
}

int vfs_create(struct inode *dir, struct dentry *dentry, int mode,
		struct nameidata *nd)
{
	int error = may_create(dir, dentry, nd);

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->create)
		return -EACCES;	/* shouldn't it be ENOSYS? */
	mode &= S_IALLUGO;
	mode |= S_IFREG;
	error = security_inode_create(dir, dentry, mode);
	if (error)
		return error;
	DQUOT_INIT(dir);
	error = dir->i_op->create(dir, dentry, mode, nd);
	if (!error) {
		inode_dir_notify(dir, DN_CREATE);
		security_inode_post_create(dir, dentry, mode);
	}
	return error;
}

int may_open(struct nameidata *nd, int acc_mode, int flag)
{
	struct dentry *dentry = nd->dentry;
	struct inode *inode = dentry->d_inode;
	int error;

	if (!inode)
		return -ENOENT;

	if (S_ISLNK(inode->i_mode))
		return -ELOOP;
	
	if (S_ISDIR(inode->i_mode) && (flag & FMODE_WRITE))
		return -EISDIR;

	error = permission(inode, acc_mode, nd);
	if (error)
		return error;

	if (S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
	    	flag &= ~O_TRUNC;
	} else if (S_ISBLK(inode->i_mode) || S_ISCHR(inode->i_mode)) {
		if (nd->mnt->mnt_flags & MNT_NODEV)
			return -EACCES;

		flag &= ~O_TRUNC;
	} else if (IS_RDONLY(inode) && (flag & FMODE_WRITE))
		return -EROFS;

	/*
	 * An append-only file must be opened in append mode for writing.
	 */
	if (IS_APPEND(inode)) {
		if  ((flag & FMODE_WRITE) && !(flag & O_APPEND))
			return -EPERM;
		if (flag & O_TRUNC)
			return -EPERM;
	}

	/* O_NOATIME can only be set by the owner or superuser */
	if (flag & O_NOATIME)
		if (current->fsuid != inode->i_uid && !capable(CAP_FOWNER))
			return -EPERM;

	/*
	 * Ensure there are no outstanding leases on the file.
	 */
	error = break_lease(inode, flag);
	if (error)
		return error;

	if (flag & O_TRUNC) {
		error = get_write_access(inode);
		if (error)
			return error;

		/*
		 * Refuse to truncate files with mandatory locks held on them.
		 */
		error = locks_verify_locked(inode);
		if (!error) {
			DQUOT_INIT(inode);
			
			error = do_truncate(dentry, 0);
		}
		put_write_access(inode);
		if (error)
			return error;
	} else
		if (flag & FMODE_WRITE)
			DQUOT_INIT(inode);

	return 0;
}

/*
 *	open_namei()
 *
 * namei for open - this is in fact almost the whole open-routine.
 *
 * Note that the low bits of "flag" aren't the same as in the open
 * system call - they are 00 - no permissions needed
 *			  01 - read permission needed
 *			  10 - write permission needed
 *			  11 - read/write permissions needed
 * which is a lot more logical, and also allows the "no perm" needed
 * for symlinks (where the permissions are checked later).
 * SMP-safe
 */
int open_namei(const char * pathname, int flag, int mode, struct nameidata *nd)
{
	int acc_mode, error = 0;
	struct dentry *dentry;
	struct dentry *dir;
	int count = 0;

	acc_mode = ACC_MODE(flag);

	if (flag & O_APPEND)
		acc_mode |= MAY_APPEND;

	nd->intent.open.flags = flag;
	nd->intent.open.create_mode = mode;

	if (!(flag & O_CREAT)) {
		error = path_lookup(pathname, lookup_flags(flag)|LOOKUP_OPEN, nd);
		if (error)
			return error;
		goto ok;
	}
	/*
	 * Create - we need to know the parent.
	 */
	error = path_lookup(pathname, LOOKUP_PARENT|LOOKUP_OPEN|LOOKUP_CREATE, nd);
	if (error)
		return error;

	error = -EISDIR;
	if (nd->last_type != LAST_NORM || nd->last.name[nd->last.len])
		goto exit;

	dir = nd->dentry;
	nd->flags &= ~LOOKUP_PARENT;
	down(&dir->d_inode->i_sem);
	dentry = __lookup_hash(&nd->last, nd->dentry, nd);

do_last:
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry)) {
		up(&dir->d_inode->i_sem);
		goto exit;
	}

	if (!dentry->d_inode) {
		if (!IS_POSIXACL(dir->d_inode))
			mode &= ~current->fs->umask;
		error = vfs_create(dir->d_inode, dentry, mode, nd);
		up(&dir->d_inode->i_sem);
		dput(nd->dentry);
		nd->dentry = dentry;
		if (error)
			goto exit;
		acc_mode = 0;
		flag &= ~O_TRUNC;
		goto ok;
	}

	/*
	 * It already exists.
	 */
	up(&dir->d_inode->i_sem);

	error = -EEXIST;
	if (flag & O_EXCL)
		goto exit_dput;

	if (d_mountpoint(dentry)) {
		error = -ELOOP;
		if (flag & O_NOFOLLOW)
			goto exit_dput;
		while (__follow_down(&nd->mnt, &dentry) && d_mountpoint(dentry));
	}
	error = -ENOENT;
	if (!dentry->d_inode)
		goto exit_dput;
	if (dentry->d_inode->i_op && dentry->d_inode->i_op->follow_link)
		goto do_link;

	dput(nd->dentry);
	nd->dentry = dentry;
	error = -EISDIR;
	if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode))
		goto exit;
ok:
	error = may_open(nd, acc_mode, flag);
	if (error)
		goto exit;
	return 0;
exit_dput:
	dput(dentry);
exit:
	path_release(nd);
	return error;

do_link:
	error = -ELOOP;
	if (flag & O_NOFOLLOW)
		goto exit_dput;

	nd->flags |= LOOKUP_PARENT;
	error = security_inode_follow_link(dentry, nd);
	if (error)
		goto exit_dput;
	error = __do_follow_link(dentry, nd);
	dput(dentry);
	if (error)
		return error;
	nd->flags &= ~LOOKUP_PARENT;
	if (nd->last_type == LAST_BIND) {
		dentry = nd->dentry;
		goto ok;
	}
	error = -EISDIR;
	if (nd->last_type != LAST_NORM)
		goto exit;
	if (nd->last.name[nd->last.len]) {
		putname(nd->last.name);
		goto exit;
	}
	error = -ELOOP;
	if (count++==32) {
		putname(nd->last.name);
		goto exit;
	}
	dir = nd->dentry;
	down(&dir->d_inode->i_sem);
	dentry = __lookup_hash(&nd->last, nd->dentry, nd);
	putname(nd->last.name);
	goto do_last;
}

struct dentry *lookup_create(struct nameidata *nd, int is_dir)
{
	struct dentry *dentry;

	down(&nd->dentry->d_inode->i_sem);
	dentry = ERR_PTR(-EEXIST);
	if (nd->last_type != LAST_NORM)
		goto fail;
	nd->flags &= ~LOOKUP_PARENT;
	dentry = lookup_hash(&nd->last, nd->dentry);
	if (IS_ERR(dentry))
		goto fail;
	if (!is_dir && nd->last.name[nd->last.len] && !dentry->d_inode)
		goto enoent;
	return dentry;
enoent:
	dput(dentry);
	dentry = ERR_PTR(-ENOENT);
fail:
	return dentry;
}

int vfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	int error = may_create(dir, dentry, NULL);

	if (error)
		return error;

	if ((S_ISCHR(mode) || S_ISBLK(mode)) && !capable(CAP_MKNOD))
		return -EPERM;

	if (!dir->i_op || !dir->i_op->mknod)
		return -EPERM;

	error = security_inode_mknod(dir, dentry, mode, dev);
	if (error)
		return error;

	DQUOT_INIT(dir);
	error = dir->i_op->mknod(dir, dentry, mode, dev);
	if (!error) {
		inode_dir_notify(dir, DN_CREATE);
		security_inode_post_mknod(dir, dentry, mode, dev);
	}
	return error;
}

asmlinkage long sys_mknod(const char __user * filename, int mode, unsigned dev)
{
	int error = 0;
	char * tmp;
	struct dentry * dentry;
	struct nameidata nd;

	if (S_ISDIR(mode))
		return -EPERM;
	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	error = path_lookup(tmp, LOOKUP_PARENT, &nd);
	if (error)
		goto out;
	dentry = lookup_create(&nd, 0);
	error = PTR_ERR(dentry);

	if (!IS_POSIXACL(nd.dentry->d_inode))
		mode &= ~current->fs->umask;
	if (!IS_ERR(dentry)) {
		switch (mode & S_IFMT) {
		case 0: case S_IFREG:
			error = vfs_create(nd.dentry->d_inode,dentry,mode,&nd);
			break;
		case S_IFCHR: case S_IFBLK:
			error = vfs_mknod(nd.dentry->d_inode,dentry,mode,
					new_decode_dev(dev));
			break;
		case S_IFIFO: case S_IFSOCK:
			error = vfs_mknod(nd.dentry->d_inode,dentry,mode,0);
			break;
		case S_IFDIR:
			error = -EPERM;
			break;
		default:
			error = -EINVAL;
		}
		dput(dentry);
	}
	up(&nd.dentry->d_inode->i_sem);
	path_release(&nd);
out:
	putname(tmp);

	return error;
}

int vfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int error = may_create(dir, dentry, NULL);

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->mkdir)
		return -EPERM;

	mode &= (S_IRWXUGO|S_ISVTX);
	error = security_inode_mkdir(dir, dentry, mode);
	if (error)
		return error;

	DQUOT_INIT(dir);
	error = dir->i_op->mkdir(dir, dentry, mode);
	if (!error) {
		inode_dir_notify(dir, DN_CREATE);
		security_inode_post_mkdir(dir,dentry, mode);
	}
	return error;
}

int vfs_symlink(struct inode *dir, struct dentry *dentry, const char *oldname, int mode)
{
	int error = may_create(dir, dentry, NULL);

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->symlink)
		return -EPERM;

	error = security_inode_symlink(dir, dentry, oldname);
	if (error)
		return error;

	DQUOT_INIT(dir);
	error = dir->i_op->symlink(dir, dentry, oldname);
	if (!error) {
		inode_dir_notify(dir, DN_CREATE);
		security_inode_post_symlink(dir, dentry, oldname);
	}
	return error;
}

asmlinkage long sys_symlink(const char __user * oldname, const char __user * newname)
{
	int error = 0;
	char * from;
	char * to;

	from = getname(oldname);
	if(IS_ERR(from))
		return PTR_ERR(from);
	to = getname(newname);
	error = PTR_ERR(to);
	if (!IS_ERR(to)) {
		struct dentry *dentry;
		struct nameidata nd;

		error = path_lookup(to, LOOKUP_PARENT, &nd);
		if (error)
			goto out;
		dentry = lookup_create(&nd, 0);
		error = PTR_ERR(dentry);
		if (!IS_ERR(dentry)) {
			error = vfs_symlink(nd.dentry->d_inode, dentry, from, S_IALLUGO);
			dput(dentry);
		}
		up(&nd.dentry->d_inode->i_sem);
		path_release(&nd);
out:
		putname(to);
	}
	putname(from);
	return error;
}

int vfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	struct inode *inode = old_dentry->d_inode;
	int error;

	if (!inode)
		return -ENOENT;

	error = may_create(dir, new_dentry, NULL);
	if (error)
		return error;

	if (dir->i_sb != inode->i_sb)
		return -EXDEV;

	/*
	 * A link to an append-only or immutable file cannot be created.
	 */
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;
	if (!dir->i_op || !dir->i_op->link)
		return -EPERM;
	if (S_ISDIR(old_dentry->d_inode->i_mode))
		return -EPERM;

	error = security_inode_link(old_dentry, dir, new_dentry);
	if (error)
		return error;

	down(&old_dentry->d_inode->i_sem);
	DQUOT_INIT(dir);
	error = dir->i_op->link(old_dentry, dir, new_dentry);
	up(&old_dentry->d_inode->i_sem);
	if (!error) {
		inode_dir_notify(dir, DN_CREATE);
		security_inode_post_link(old_dentry, dir, new_dentry);
	}
	return error;
}

asmlinkage long sys_mkdir(const char __user * pathname, int mode)
{
	int error = 0;
	char * tmp;

	tmp = getname(pathname);
	error = PTR_ERR(tmp);
	if (!IS_ERR(tmp)) {
		struct dentry *dentry;
		struct nameidata nd;

		error = path_lookup(tmp, LOOKUP_PARENT, &nd);
		if (error)
			goto out;
		dentry = lookup_create(&nd, 1);
		error = PTR_ERR(dentry);
		if (!IS_ERR(dentry)) {
			if (!IS_POSIXACL(nd.dentry->d_inode))
				mode &= ~current->fs->umask;
			error = vfs_mkdir(nd.dentry->d_inode, dentry, mode);
			dput(dentry);
		}
		up(&nd.dentry->d_inode->i_sem);
		path_release(&nd);
out:
		putname(tmp);
	}

	return error;
}



asmlinkage long sys_link(const char __user * oldname, const char __user * newname)
{
	struct dentry *new_dentry;
	struct nameidata nd, old_nd;
	int error;
	char *to;

	to = getname(newname);
	if (IS_ERR(to))
		return PTR_ERR(to);

	error = __user_walk(oldname, 0, &old_nd);
	if (error)
		goto exit;
	error = path_lookup(to, LOOKUP_PARENT, &nd);
	if (error)
		goto out;
	error = -EXDEV;
	if (old_nd.mnt != nd.mnt)
		goto out_release;
	new_dentry = lookup_create(&nd, 0);
	error = PTR_ERR(new_dentry);
	if (!IS_ERR(new_dentry)) {
		error = vfs_link(old_nd.dentry, nd.dentry->d_inode, new_dentry);
		dput(new_dentry);
	}
	up(&nd.dentry->d_inode->i_sem);
out_release:
	path_release(&nd);
out:
	path_release(&old_nd);
exit:
	putname(to);

	return error;
}

int generic_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
    return 0;
}

int page_follow_link_light(struct dentry *dentry, struct nameidata *nd)
{
	return 0;
}

void page_put_link(struct dentry *dentry, struct nameidata *nd)
{
    panic("in page_put_link function");
}

int page_symlink(struct inode *inode, const char *symname, int len)
{
    return 0;
}

struct inode_operations page_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
};

EXPORT_SYMBOL(page_symlink_inode_operations);