#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/err.h>
#include <asm/uaccess.h>
#include "internal.h"

static int user_instantiate(struct key *key, const void *data, size_t datalen);
static int user_duplicate(struct key *key, const struct key *source);
static int user_update(struct key *key, const void *data, size_t datalen);
static int user_match(const struct key *key, const void *criterion);
static void user_destroy(struct key *key);
static void user_describe(const struct key *user, struct seq_file *m);
static long user_read(const struct key *key,
		      char __user *buffer, size_t buflen);

struct key_type key_type_user = {
	.name		= "user",
	.instantiate	= user_instantiate,
	.duplicate	= user_duplicate,
	.update		= user_update,
	.match		= user_match,
	.destroy	= user_destroy,
	.describe	= user_describe,
	.read		= user_read,
};

static int user_instantiate(struct key *key, const void *data, size_t datalen)
{
    return 0;
}

static int user_duplicate(struct key *key, const struct key *source)
{
    return 0;
}

static int user_update(struct key *key, const void *data, size_t datalen)
{
    return 0;
}

static int user_match(const struct key *key, const void *description)
{
    return 0;
}

static void user_destroy(struct key *key)
{
    kfree(key->payload.data);
}

static void user_describe(const struct key *key, struct seq_file *m)
{

}

static long user_read(const struct key *key,
		      char __user *buffer, size_t buflen)
{
    return 0;
}

