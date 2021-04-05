#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/err.h>
#include <asm/uaccess.h>
#include "internal.h"

static int keyring_instantiate(struct key *keyring,
			       const void *data, size_t datalen);
static int keyring_duplicate(struct key *keyring, const struct key *source);
static int keyring_match(const struct key *keyring, const void *criterion);
static void keyring_destroy(struct key *keyring);
static void keyring_describe(const struct key *keyring, struct seq_file *m);
static long keyring_read(const struct key *keyring,
			 char __user *buffer, size_t buflen);

struct key_type key_type_keyring = {
	.name		= "keyring",
	.def_datalen	= sizeof(struct keyring_list),
	.instantiate	= keyring_instantiate,
	.duplicate	= keyring_duplicate,
	.match		= keyring_match,
	.destroy	= keyring_destroy,
	.describe	= keyring_describe,
	.read		= keyring_read,
};

static int keyring_instantiate(struct key *keyring,
			       const void *data, size_t datalen) {
                       return 0;
                   }

static int keyring_duplicate(struct key *keyring, const struct key *source) {
    return 0;
}

static int keyring_match(const struct key *keyring, const void *description) {
    return 0;
}

static void keyring_destroy(struct key *keyring) {
    return 0;
}

static void keyring_describe(const struct key *keyring, struct seq_file *m) {

}

static long keyring_read(const struct key *keyring,
			 char __user *buffer, size_t buflen) {
                 return 0;
             }