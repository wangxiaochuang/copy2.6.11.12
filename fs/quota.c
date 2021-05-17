#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <asm/current.h>
#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/smp_lock.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/buffer_head.h>

static struct super_block *get_super_to_sync(int type)
{
    panic("in get_super_to_sync function");
    return NULL;
}

static void quota_sync_sb(struct super_block *sb, int type)
{
	int cnt;
	struct inode *discard[MAXQUOTAS];

	sb->s_qcop->quota_sync(sb, type);
	if (sb->s_op->sync_fs)
		sb->s_op->sync_fs(sb, 1);
	sync_blockdev(sb->s_bdev);

	down(&sb_dqopt(sb)->dqonoff_sem);
	for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
		discard[cnt] = NULL;
		if (type != -1 && cnt != type)
			continue;
		if (!sb_has_quota_enabled(sb, cnt))
			continue;
		discard[cnt] = igrab(sb_dqopt(sb)->files[cnt]);
	}
	up(&sb_dqopt(sb)->dqonoff_sem);
	for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
		if (discard[cnt]) {
			down(&discard[cnt]->i_sem);
			truncate_inode_pages(&discard[cnt]->i_data, 0);
			up(&discard[cnt]->i_sem);
			iput(discard[cnt]);
		}
	}
}

void sync_dquots(struct super_block *sb, int type)
{
	if (sb) {
		if (sb->s_qcop->quota_sync)
			quota_sync_sb(sb, type);
	}
	else {
		while ((sb = get_super_to_sync(type)) != NULL) {
			if (sb->s_qcop->quota_sync)
				quota_sync_sb(sb, type);
			drop_super(sb);
		}
	}
}