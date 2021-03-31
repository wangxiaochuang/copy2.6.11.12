#ifndef _LINUX_PID_H
#define _LINUX_PID_H

enum pid_type
{
	PIDTYPE_PID,
	PIDTYPE_TGID,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX
};

struct pid
{
	/* Try to keep pid_chain in the same cacheline as nr for find_pid */
	int nr;
	struct hlist_node pid_chain;
	/* list of pids with the same nr, only one of them is in the hash */
	struct list_head pid_list;
};

#endif /* _LINUX_PID_H */
