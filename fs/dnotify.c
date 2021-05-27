#include <linux/fs.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/dnotify.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

int dir_notify_enable = 1;

static kmem_cache_t *dn_cache;

static void redo_inode_mask(struct inode *inode)
{
	unsigned long new_mask;
	struct dnotify_struct *dn;

	new_mask = 0;
	for (dn = inode->i_dnotify; dn != NULL; dn = dn->dn_next)
		new_mask |= dn->dn_mask & ~DN_MULTISHOT;
	inode->i_dnotify_mask = new_mask;
}

void dnotify_flush(struct file *filp, fl_owner_t id)
{
	struct dnotify_struct *dn;
	struct dnotify_struct **prev;
	struct inode *inode;

	inode = filp->f_dentry->d_inode;
	if (!S_ISDIR(inode->i_mode))
		return;
	spin_lock(&inode->i_lock);
	prev = &inode->i_dnotify;
	while ((dn = *prev) != NULL) {
		if ((dn->dn_owner == id) && (dn->dn_filp == filp)) {
			*prev = dn->dn_next;
			redo_inode_mask(inode);
			kmem_cache_free(dn_cache, dn);
			break;
		}
		prev = &dn->dn_next;
	}
	spin_unlock(&inode->i_lock);
}

void __inode_dir_notify(struct inode *inode, unsigned long event)
{
    struct dnotify_struct *	dn;
	struct dnotify_struct **prev;
	struct fown_struct *	fown;
	int			changed = 0;

	spin_lock(&inode->i_lock);
	prev = &inode->i_dnotify;
	while ((dn = *prev) != NULL) {
		if ((dn->dn_mask & event) == 0) {
			prev = &dn->dn_next;
			continue;
		}
		fown = &dn->dn_filp->f_owner;
		send_sigio(fown, dn->dn_fd, POLL_MSG);
		if (dn->dn_mask & DN_MULTISHOT)
			prev = &dn->dn_next;
		else {
			*prev = dn->dn_next;
			changed = 1;
			kmem_cache_free(dn_cache, dn);
		}
	}
	if (changed)
		redo_inode_mask(inode);
	spin_unlock(&inode->i_lock);
}

EXPORT_SYMBOL(__inode_dir_notify);

void dnotify_parent(struct dentry *dentry, unsigned long event)
{
	struct dentry *parent;

	if (!dir_notify_enable)
		return;

	spin_lock(&dentry->d_lock);
	parent = dentry->d_parent;
	if (parent->d_inode->i_dnotify_mask & event) {
		dget(parent);
		spin_unlock(&dentry->d_lock);
		__inode_dir_notify(parent->d_inode, event);
		dput(parent);
	} else {
		spin_unlock(&dentry->d_lock);
	}
}
EXPORT_SYMBOL_GPL(dnotify_parent);