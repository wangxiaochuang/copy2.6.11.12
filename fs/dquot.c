#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/tty.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/kmod.h>
#include <linux/namei.h>
#include <linux/buffer_head.h>

#include <asm/uaccess.h>

static DEFINE_SPINLOCK(dq_list_lock);
DEFINE_SPINLOCK(dq_data_lock);

struct dqstats dqstats;

static void dqput(struct dquot *dquot);

int dquot_mark_dquot_dirty(struct dquot *dquot)
{
    return 0;
}

static inline int clear_dquot_dirty(struct dquot *dquot)
{
	if (!test_and_clear_bit(DQ_MOD_B, &dquot->dq_flags))
		return 0;
	list_del_init(&dquot->dq_dirty);
	return 1;
}

int dquot_acquire(struct dquot *dquot)
{
    return 0;
}

int dquot_commit(struct dquot *dquot)
{
    return 0;
}

int dquot_release(struct dquot *dquot)
{
    return 0;
}

int vfs_quota_sync(struct super_block *sb, int type)
{
    struct list_head *dirty;
	struct dquot *dquot;
	struct quota_info *dqopt = sb_dqopt(sb);
	int cnt;

	down(&dqopt->dqonoff_sem);
	for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
		if (type != -1 && cnt != type)
			continue;
		if (!sb_has_quota_enabled(sb, cnt))
			continue;
		spin_lock(&dq_list_lock);
		dirty = &dqopt->info[cnt].dqi_dirty_list;
		while (!list_empty(dirty)) {
			dquot = list_entry(dirty->next, struct dquot, dq_dirty);
			/* Dirty and inactive can be only bad dquot... */
			if (!test_bit(DQ_ACTIVE_B, &dquot->dq_flags)) {
				clear_dquot_dirty(dquot);
				continue;
			}
			/* Now we have active dquot from which someone is
 			 * holding reference so we can safely just increase
			 * use count */
			atomic_inc(&dquot->dq_count);
			dqstats.lookups++;
			spin_unlock(&dq_list_lock);
			sb->dq_op->write_dquot(dquot);
			dqput(dquot);
			spin_lock(&dq_list_lock);
		}
		spin_unlock(&dq_list_lock);
	}

	for (cnt = 0; cnt < MAXQUOTAS; cnt++)
		if ((cnt == type || type == -1) && sb_has_quota_enabled(sb, cnt)
			&& info_dirty(&dqopt->info[cnt]))
			sb->dq_op->write_info(sb, cnt);
	spin_lock(&dq_list_lock);
	dqstats.syncs++;
	spin_unlock(&dq_list_lock);
	up(&dqopt->dqonoff_sem);

	return 0;
}

static void dqput(struct dquot *dquot)
{
    panic("in dqput function");
}

int dquot_initialize(struct inode *inode, int type)
{
    return 0;
}

int dquot_drop(struct inode *inode)
{
    return 0;
}

int dquot_alloc_space(struct inode *inode, qsize_t number, int warn)
{
    return 0;
}

int dquot_alloc_inode(const struct inode *inode, unsigned long number)
{
    return 0;
}

int dquot_free_space(struct inode *inode, qsize_t number)
{
    return 0;
}

int dquot_free_inode(const struct inode *inode, unsigned long number)
{
    return 0;
}

int dquot_transfer(struct inode *inode, struct iattr *iattr)
{
    return 0;
}

int dquot_commit_info(struct super_block *sb, int type)
{
    return 0;
}



struct dquot_operations dquot_operations = {
	.initialize	= dquot_initialize,
	.drop		= dquot_drop,
	.alloc_space	= dquot_alloc_space,
	.alloc_inode	= dquot_alloc_inode,
	.free_space	= dquot_free_space,
	.free_inode	= dquot_free_inode,
	.transfer	= dquot_transfer,
	.write_dquot	= dquot_commit,
	.acquire_dquot	= dquot_acquire,
	.release_dquot	= dquot_release,
	.mark_dirty	= dquot_mark_dquot_dirty,
	.write_info	= dquot_commit_info
};

int vfs_quota_off(struct super_block *sb, int type)
{
    return 0;
}

int vfs_quota_on(struct super_block *sb, int type, int format_id, char *path)
{
    return 0;
}

int vfs_get_dqblk(struct super_block *sb, int type, qid_t id, struct if_dqblk *di)
{
    return 0;
}

int vfs_set_dqblk(struct super_block *sb, int type, qid_t id, struct if_dqblk *di)
{
    return 0;
}

int vfs_get_dqinfo(struct super_block *sb, int type, struct if_dqinfo *ii)
{
    return 0;
}

int vfs_set_dqinfo(struct super_block *sb, int type, struct if_dqinfo *ii)
{
    return 0;
}

struct quotactl_ops vfs_quotactl_ops = {
	.quota_on	= vfs_quota_on,
	.quota_off	= vfs_quota_off,
	.quota_sync	= vfs_quota_sync,
	.get_info	= vfs_get_dqinfo,
	.set_info	= vfs_set_dqinfo,
	.get_dqblk	= vfs_get_dqblk,
	.set_dqblk	= vfs_set_dqblk
};

EXPORT_SYMBOL(dquot_commit);
EXPORT_SYMBOL(dquot_commit_info);
EXPORT_SYMBOL(dquot_acquire);
EXPORT_SYMBOL(dquot_release);
EXPORT_SYMBOL(dquot_mark_dquot_dirty);
EXPORT_SYMBOL(dquot_initialize);
EXPORT_SYMBOL(dquot_drop);
EXPORT_SYMBOL(dquot_alloc_space);
EXPORT_SYMBOL(dquot_alloc_inode);
EXPORT_SYMBOL(dquot_free_space);
EXPORT_SYMBOL(dquot_free_inode);
EXPORT_SYMBOL(dquot_transfer);