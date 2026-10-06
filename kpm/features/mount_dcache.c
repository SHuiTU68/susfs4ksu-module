// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mount_dcache - E7, the dcache-synthesising mount engine.
 *
 * Why this exists: stock APatch removed mounting from the daemon, so a module's
 * system/ tree only appears if a metamodule mounts it.  Mounting is always
 * detectable in principle - /proc/mounts grows an entry, st_dev of the file
 * differs from the partition it claims to live on, statfs disagrees.  E7 avoids
 * all of it by never mounting: it fabricates dentry+inode pairs directly in the
 * *target* partition's dcache, so a path such as /system/bin/foo resolves to an
 * inode whose i_sb is /system's real superblock.  st_dev, st_ino, statfs and
 * /proc/mounts are then correct by construction.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS FILE IS (and is not) RIGHT NOW
 *
 * The rule store plus its userspace ABI.  Nothing here touches the VFS yet,
 * which is deliberate: the store is what the dcache work will read from, and a
 * rule store with no VFS side effects can be loaded, exercised and unloaded on
 * a live device without any way to take the boot down.  The VFS half arrives as
 * separate slices, and the capability string is what tells userspace whether it
 * is there:
 *
 *   slice 1 (this file)  rule store + ABI + capability reporting
 *   slice 2              synthetic dentry/inode pairs (shadow f_op + a_ops for
 *                        regular files, i_op->get_link for symlinks)
 *   slice 3              getdents64/iterate_dir merge, so listings agree with
 *                        lookups - only then is "readdir" advertised
 *
 * metamount.sh refuses to pick E7 until the engine advertises "readdir", so a
 * half-built engine can never become the default mount path behind the user's
 * back: lookups that succeed while `ls` does not show the file are precisely
 * the anomaly a root-hiding system must not have.
 *
 * ---------------------------------------------------------------------------
 * RULE MODEL
 *
 * One rule is one virtual path (what the app asks for, e.g.
 * /system/bin/foo) mapped to one real path inside the module tree (e.g.
 * /data/adb/modules/example/system/bin/foo).  metamount.sh walks the module set
 * and sends the pairs through mctl; over 10^3-10^4 files that is a few
 * milliseconds of syscalls, so the protocol stays the simple per-rule one the
 * rest of this KPM already speaks ("<CMD_HEX>|<arg>|<arg>" via ctl0) instead of
 * growing a binary bulk channel.
 *
 * Rules are stored in a 256-way bucket table keyed on the first 8 bytes of the
 * virtual path, with an insertion-ordered list alongside it for cleanup and
 * listing.  Readers (slice 2) take the lock only while walking one bucket;
 * susfs_dc_rule_count() is published separately and read without the lock on
 * the hot path.
 *
 * Lifetime: add/clear are called from userspace (post-fs-data, and the Action
 * button for a hot rebuild), so a rule set can be replaced at runtime.  Slice 2
 * will have to tear down the dentries it created before freeing the strings
 * they point at - that is why the teardown entry point
 * susfs_dc_rules_reset_notify() exists here already, called by clear() before
 * anything is freed.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <log.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <uapi/asm-generic/errno.h>

#include "../include/susfs_kpm.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

/* Bucket count is a power of two so the hash can be masked, and 256 is the
 * sweet spot for the rule counts we expect (10^3-10^4): ~4-40 entries per
 * bucket, each compared with one 8-byte load plus a full strcmp on a hit. */
#define DC_NBUCKET 256
#define DC_BUCKET_MASK (DC_NBUCKET - 1)

/* Hard cap.  16k rules is ~32k allocations of ~128 bytes; beyond that the
 * module set is pathological and userspace gets -ENOSPC rather than a slow
 * death by OOM. */
#define DC_MAX_RULES 16384

struct dc_rule {
    struct list_head list;      /* insertion order: listing + cleanup */
    struct dc_rule *idx_next;   /* bucket chain */
    uint64_t hdr;               /* first 8 bytes of virt, zero padded */
    char *virt;                 /* kzalloc'd, NUL-terminated, absolute */
    char *real;                 /* kzalloc'd, NUL-terminated, absolute */
    int virt_len;
    int real_len;
};

static LIST_HEAD(dc_rule_list);
static DEFINE_SPINLOCK(dc_rule_lock);
static struct dc_rule *dc_bucket[DC_NBUCKET];

/* Read without the lock on the hot path (slice 2).  Published after the rule is
 * fully linked, so a reader that sees a non-zero count only ever walks linked,
 * fully-initialised entries. */
static int dc_rule_count = 0;
static int dc_rule_dups = 0;      /* add() calls that replaced a real path */
static int dc_rule_errors = 0;    /* rejected add() calls, for status */

/* ===== small string helpers =====
 *
 * No strlen/strcmp/snprintf here.  KernelPatch's <linux/string.h> inline
 * wrappers reference kf_* pointers that a KPM cannot resolve (see
 * susfs_kpm.h), and there is no snprintf at all, so the few operations we need
 * are written out.  The Makefile builds with -fno-builtin, so clang will not
 * turn these loops back into memcpy()/memset() calls. */

static int dc_strlen(const char *s)
{
    int n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

/* -1 / 0 / 1 */
static int dc_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static uint64_t dc_hash8(const char *p, int len)
{
    uint64_t w = 0;
    int i, n = len < 8 ? len : 8;

    for (i = 0; i < n; i++)
        w |= ((uint64_t)(unsigned char)p[i]) << (8 * i);
    return w;
}

static unsigned dc_bucket_of(uint64_t hdr)
{
    /* one multiply; spreads the shared prefixes ("/system/", "/vendor/",
     * "/product/") over the whole table */
    return (unsigned)((hdr * 0x9E3779B97F4A7C15ull) >> (64 - 8)) & DC_BUCKET_MASK;
}

/* Append s to out (length capped at outlen-1, always NUL-terminated).
 * Returns the number of bytes written, or -ENOSPC once it no longer fits. */
static int dc_append(char *out, int outlen, int pos, const char *s)
{
    int n = dc_strlen(s);

    if (pos + n > outlen - 1) return -ENOSPC;
    while (n-- > 0) out[pos++] = *s++;
    out[pos] = '\0';
    return pos;
}

/* Decimal, no leading zeros.  Returns the new position, or -ENOSPC. */
static int dc_append_int(char *out, int outlen, int pos, int v)
{
    char tmp[12];
    int n = 0, i;

    if (v < 0) {
        if (pos + 1 > outlen - 1) return -ENOSPC;
        out[pos++] = '-';
        v = -v;
    }
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v);

    if (pos + n > outlen - 1) return -ENOSPC;
    for (i = n - 1; i >= 0; i--) out[pos++] = tmp[i];
    out[pos] = '\0';
    return pos;
}

static void dc_copy_out(char *out, int outlen, const char *s)
{
    int i = 0;

    if (!out || outlen <= 0) return;
    while (s && s[i] && i < outlen - 1) { out[i] = s[i]; i++; }
    out[i] = '\0';
}

/* ===== rule store ===== */

static struct dc_rule *dc_bucket_find(unsigned b, const char *virt, uint64_t hdr)
{
    struct dc_rule *e;

    for (e = dc_bucket[b]; e; e = e->idx_next) {
        if (e->hdr != hdr) continue;            /* one compare rejects nearly all */
        if (dc_strcmp(e->virt, virt) == 0) return e;
    }
    return NULL;
}

/* Called with dc_rule_lock held, before anything is freed.  Slice 2 uses this
 * to drop the dentries it created for the outgoing rules; slice 1 has nothing
 * to drop, which is the point of having the hook from the start rather than
 * bolting teardown onto clear() later and forgetting a path. */
static void susfs_dc_rules_reset_notify(void)
{
    /* no VFS state yet (slice 2) */
}

static void dc_free_rule(struct dc_rule *e)
{
    if (e->virt && susfs_kfree) susfs_kfree(e->virt);
    if (e->real && susfs_kfree) susfs_kfree(e->real);
    if (susfs_kfree) susfs_kfree(e);
}

static char *dc_dup_abs(const char *s, int *len_out)
{
    char *p;
    int n = dc_strlen(s);

    if (n <= 0 || n >= SUSFS_MAX_LEN_PATHNAME) return NULL;
    if (s[0] != '/') return NULL;
    /* Trailing slashes make two spellings of one path, and the rule table is
     * compared textually; normalise by refusing them. */
    if (n > 1 && s[n - 1] == '/') return NULL;

    p = susfs_kzalloc((size_t)n + 1, SUSFS_GFP_KERNEL);
    if (!p) return NULL;
    susfs_memcpy(p, s, (__kernel_size_t)n);
    p[n] = '\0';
    *len_out = n;
    return p;
}

int susfs_dc_rule_add(const char *virt, const char *real)
{
    struct dc_rule *e, *old;
    uint64_t hdr;
    unsigned b;
    char *v, *r;
    int vlen = 0, rlen = 0;

    if (!virt || !*virt || !real || !*real) return -EINVAL;
    /* susfs_kzalloc() is a wrapper, not a pointer: it already returns NULL when
     * its backend failed to resolve, so the allocation below is the real probe
     * for it.  Only the two raw string pointers need checking up front. */
    if (!susfs_kfree || !susfs_memcpy) {
        dc_rule_errors++;
        return -ENOSYS;
    }
    if (dc_rule_count >= DC_MAX_RULES) {
        dc_rule_errors++;
        return -ENOSPC;
    }

    v = dc_dup_abs(virt, &vlen);
    if (!v) { dc_rule_errors++; return -EINVAL; }
    r = dc_dup_abs(real, &rlen);
    if (!r) {
        susfs_kfree(v);
        dc_rule_errors++;
        return -EINVAL;
    }

    hdr = dc_hash8(v, vlen);
    b = dc_bucket_of(hdr);

    susfs__raw_spin_lock(&dc_rule_lock);
    old = dc_bucket_find(b, v, hdr);
    if (old) {
        /* Replace in place: same virtual path, new real path (a module was
         * updated, or the same tree was walked twice).  Keeping the entry means
         * the bucket chain and the list order stay put. */
        if (susfs_kfree) susfs_kfree(old->real);
        old->real = r;
        old->real_len = rlen;
        susfs__raw_spin_unlock(&dc_rule_lock);
        if (susfs_kfree) susfs_kfree(v);
        dc_rule_dups++;
        return 0;
    }

    e = susfs_kzalloc(sizeof(*e), SUSFS_GFP_KERNEL);
    if (!e) {
        susfs__raw_spin_unlock(&dc_rule_lock);
        susfs_kfree(v);
        susfs_kfree(r);
        dc_rule_errors++;
        return -ENOMEM;
    }
    e->virt = v;
    e->real = r;
    e->virt_len = vlen;
    e->real_len = rlen;
    e->hdr = hdr;
    e->idx_next = dc_bucket[b];
    dc_bucket[b] = e;
    list_add_tail(&e->list, &dc_rule_list);
    susfs__raw_spin_unlock(&dc_rule_lock);

    /* Publish last: readers gate on the count. */
    dc_rule_count++;
    return 0;
}

int susfs_dc_rule_count(void)
{
    return dc_rule_count;
}

int susfs_dc_rule_clear(void)
{
    struct dc_rule *e, *tmp;

    susfs__raw_spin_lock(&dc_rule_lock);
    /* Hand the VFS half the chance to unwind before the strings it references
     * go away. */
    susfs_dc_rules_reset_notify();
    dc_rule_count = 0;             /* stop readers first */
    list_for_each_entry_safe(e, tmp, &dc_rule_list, list) {
        list_del(&e->list);
        dc_free_rule(e);
    }
    {
        int i;
        for (i = 0; i < DC_NBUCKET; i++) dc_bucket[i] = NULL;
    }
    susfs__raw_spin_unlock(&dc_rule_lock);

    logki("susfs_kpm: mount_dcache: rules cleared\n");
    return 0;
}

/* "virtual=real\n" per rule.  Returns the number of rules written so that
 * userspace can tell a truncated listing from a complete one. */
int susfs_dc_rule_list(char *out, int outlen)
{
    struct dc_rule *e;
    int pos = 0, n = 0;

    if (!out || outlen <= 0) return -EINVAL;
    out[0] = '\0';

    susfs__raw_spin_lock(&dc_rule_lock);
    list_for_each_entry(e, &dc_rule_list, list) {
        pos = dc_append(out, outlen, pos, e->virt);
        if (pos < 0) { pos = -ENOSPC; break; }
        pos = dc_append(out, outlen, pos, "=");
        if (pos < 0) { pos = -ENOSPC; break; }
        pos = dc_append(out, outlen, pos, e->real);
        if (pos < 0) { pos = -ENOSPC; break; }
        pos = dc_append(out, outlen, pos, "\n");
        if (pos < 0) { pos = -ENOSPC; break; }
        n++;
    }
    susfs__raw_spin_unlock(&dc_rule_lock);

    if (pos < 0) {
        /* Truncated: emit the marker so nobody mistakes a short list for the
         * whole rule set. */
        dc_append(out, outlen, dc_strlen(out), "!truncated\n");
        return -ENOSPC;
    }
    return n;
}

/* One line, machine-parseable: which slices are actually there. */
int susfs_dc_caps(char *out, int outlen)
{
    dc_copy_out(out, outlen, SUSFS_DC_CAPS_STRING);
    return 0;
}

/* Human/status line for the Action button and boot-completed.sh. */
int susfs_dc_status(char *out, int outlen)
{
    int pos;

    if (!out || outlen <= 0) return -EINVAL;
    out[0] = '\0';

    pos = dc_append(out, outlen, 0, "dcache rules=");
    if (pos < 0) return -ENOSPC;
    pos = dc_append_int(out, outlen, pos, dc_rule_count);
    if (pos < 0) return -ENOSPC;
    pos = dc_append(out, outlen, pos, " dups=");
    if (pos < 0) return -ENOSPC;
    pos = dc_append_int(out, outlen, pos, dc_rule_dups);
    if (pos < 0) return -ENOSPC;
    pos = dc_append(out, outlen, pos, " errors=");
    if (pos < 0) return -ENOSPC;
    pos = dc_append_int(out, outlen, pos, dc_rule_errors);
    if (pos < 0) return -ENOSPC;
    pos = dc_append(out, outlen, pos, " caps=");
    if (pos < 0) return -ENOSPC;
    pos = dc_append(out, outlen, pos, SUSFS_DC_CAPS_STRING);
    if (pos < 0) return -ENOSPC;
    return dc_append(out, outlen, pos, "\n");
}

void susfs_dc_cleanup(void)
{
    susfs_dc_rule_clear();
}

/* Slice 1 installs no hooks and resolves nothing: the engine has no VFS
 * presence yet, so init is pure bookkeeping.  It still exists so that
 * susfs_init()/susfs_exit() have a single call each to add to as the later
 * slices land, instead of every slice having to edit the KPM core. */
int susfs_dc_init(void)
{
    logki("susfs_kpm: mount_dcache: rule store up (caps=%s)\n",
          SUSFS_DC_CAPS_STRING);
    return 0;
}
