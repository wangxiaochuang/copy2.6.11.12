#include <linux/raid/md.h>

#include "do_mounts.h"

static int __initdata raid_noautodetect, raid_autopart;

static struct {
	int minor;
	int partitioned;
	int pers;
	int chunk;
	char *device_names;
} md_setup_args[MAX_MD_DEVS] __initdata;

static int md_setup_ents __initdata;

extern int mdp_major;


static int __init md_setup(char *str)
{
    panic("in md_setup function");
    return 0;
}


#define MdpMinorShift 6

static void __init md_setup_drive(void)
{
	int minor, i, ent, partitioned;
	dev_t dev;
	dev_t devices[MD_SB_DISKS+1];

    for (ent = 0; ent < md_setup_ents; ent++) {
        panic("in md_setup_drive function");
    }
}

static int __init raid_setup(char *str)
{
	int len, pos;

	len = strlen(str) + 1;
	pos = 0;

	while (pos < len) {
		char *comma = strchr(str+pos, ',');
		int wlen;
		if (comma)
			wlen = (comma-str)-pos;
		else	wlen = (len-1)-pos;

		if (!strncmp(str, "noautodetect", wlen))
			raid_noautodetect = 1;
		if (strncmp(str, "partitionable", wlen)==0)
			raid_autopart = 1;
		if (strncmp(str, "part", wlen)==0)
			raid_autopart = 1;
		pos += wlen+1;
	}
	return 1;
}

__setup("raid=", raid_setup);
__setup("md=", md_setup);

void __init md_run_setup(void)
{
    create_dev("/dev/md0", MKDEV(MD_MAJOR, 0), "md/0");
    if (raid_noautodetect) {
		printk(KERN_INFO "md: Skipping autodetection of RAID arrays. (raid=noautodetect)\n");
    } else {
        int fd = sys_open("/dev/md0", 0, 0);
        if (fd >= 0) {
            sys_ioctl(fd, RAID_AUTORUN, raid_autopart);
            sys_close(fd);
        }
    }
    md_setup_drive();
}