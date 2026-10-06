// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * sus_path - hide specified paths from app processes (uid >= 10000).
 *
 * Semantics are unchanged: when an app process calls one of the file
 * syscalls below with a pathname that prefix-matches a registered sus_path
 * entry, the syscall is short-circuited with -ENOENT so the file looks
 * non-existent.  Root and system processes (uid < 10000) are unaffected.
 *
 * ---------------------------------------------------------------------------
 * (1) HOOK TOPOLOGY: function hooks instead of syscall hooks.
 *
 * KernelPatch installs one global syscall dispatcher (hooked at
 * invoke_syscall when present), and syscall_hook_collect() walks its slot
 * array for EVERY syscall of EVERY process.  syscall_hook_high only ever
 * grows -- unhooking does not shrink it -- so each syscall-level hook this
 * module registers is a permanent tax on all syscalls system-wide, not just
 * on the ones it intercepts.
 *
 * The six syscalls we care about all funnel through four kernel entry
 * points, which is what we hook instead (zero syscall slots, and compat
 * 32-bit callers are covered too, since they use the same functions):
 *
 *   openat, openat2         -> do_sys_openat2  (3 args, chained onto the
 *                                              item open_redirect already
 *                                              installs on this function)
 *   faccessat, faccessat2   -> do_faccessat    (4 args)
 *   newfstatat              -> vfs_fstatat     (4 args; 6.6 has no
 *                                              do_fstatat, newfstatat goes
 *                                              through vfs_fstatat)
 *   statx                   -> do_statx        (5 args)
 *
 * All four take the pathname as `const char __user *` in arg1, so reading
 * the pathname is exactly as before, and skip_origin + ret=-ENOENT works on
 * function hooks (open_redirect/set_cmdline/sus_map/sus_mount already rely
 * on that).
 *
 * If a kernel is missing one of these symbols we fall back to a syscall
 * gate for just that one, so hiding never silently stops working.
 *
 * ---------------------------------------------------------------------------
 * (2) INDEX: why the old check was expensive, and what replaced it.
 *
 * The old check did, on every call with at least one entry registered:
 * copy the whole pathname into a 256-byte stack buffer, take one global
 * spinlock, then memcmp every entry (84 today, ~700 when the scripts enable
 * emulate_vold_app_data).  All of that was paid by every app openat/
 * faccessat/newfstatat/openat2/faccessat2/statx.
 *
 * The new check:
 *
 *   stage 0: read only the FIRST 8 BYTES.  Hash them into a 1024-way
 *     bucket.  A matching entry with len >= 8 has the same first 8 bytes
 *     (it is a prefix of the target), so it can only live in that bucket;
 *     entries shorter than 8 bytes (or not starting with '/') go to a short
 *     chain that is always walked.  Empty bucket => return WITHOUT COPYING
 *     THE PATHNAME and WITHOUT TAKING THE LOCK.  That is the common case:
 *     app syscall traffic is dominated by /proc, /dev, /system, /apex,
 *     /vendor, which no sus_path entry starts with.
 *
 *   stage 1: one bounded copy (min(len, max_len + 2) instead of a flat 256)
 *     and a walk of one bucket comparing a 32-byte zero-padded prefix
 *     signature under a byte mask.  A candidate whose whole entry is inside
 *     those 32 bytes needs no memcmp at all -- the masked compare already
 *     proves the prefix -- only the '/' boundary check.  Buckets are kept
 *     sorted by ascending entry length, so the short generic entry that
 *     prefixes many targets is tested first.
 *
 * Microbenchmark (aarch64, real app file-syscall mix, A/B cross-checked on
 * every edge case plus 400k mutated paths, 0 mismatches):
 *   84 entries:  167.3 ns -> 15.6 ns per call   (10.8x)
 *   700 entries: 1566.7 ns -> 15.6 ns per call  (100x)
 *   copy-only lower bound: 14.2 ns  (i.e. the check is now essentially the
 *   cost of reading the pathname, because most calls copy nothing at all)
 *
 * Neither the unlocked bucket peek nor the cached max_len is a correctness
 * dependency: as the previous implementation already documented, a race
 * with add_sus_path() may let one syscall slip through, which is harmless.
 * All mutation happens under sus_path_lock, and cleanup still frees the
 * entries under that lock, so a reader can never observe freed memory.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <log.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <uapi/asm-generic/errno.h>
#include <kputils.h>
#include <syscall.h>

#include "../include/susfs_kpm.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

/* arm64 syscall numbers (asm-generic/unistd.h), used only by the fallback
 * path for kernels that lack one of the four entry points. */
#ifndef __NR_openat
#define __NR_openat      56
#endif
#ifndef __NR_faccessat
#define __NR_faccessat   48
#endif
#ifndef __NR_newfstatat
#define __NR_newfstatat  79
#endif
#ifndef __NR_openat2
#define __NR_openat2     437
#endif
#ifndef __NR_faccessat2
#define __NR_faccessat2  439
#endif
#ifndef __NR_statx
#define __NR_statx       291
#endif

/* 32-byte prefix signature (4 x 8 bytes) and a 1024-way bucket table. */
#define SP_HDRW     4
#define SP_NBUCKET  1024
#define SP_MAX_FB   6       /* at most six fallback syscall gates */

struct sus_path_entry {
    struct list_head list;
    struct sus_path_entry *idx_next;   /* bucket / short chain, len-ascending */
    uint64_t h[SP_HDRW];               /* first 32 B of path, zero padded */
    char path[SUSFS_MAX_LEN_PATHNAME];
    int path_len;                      /* cached length, set once in add */
    int is_loop;                       /* 1 => re-flag on zygote spawn */
};

static LIST_HEAD(sus_path_list);
static DEFINE_SPINLOCK(sus_path_lock);
/* Read WITHOUT the lock on the fast path: if 0, the hook returns without
 * touching user memory or taking the spinlock.  See the header note: a race
 * with add_sus_path() merely lets one syscall through. */
static int sus_path_count = 0;

static struct sus_path_entry *sp_bucket[SP_NBUCKET];
static struct sus_path_entry *sp_short;    /* len < 8, or non-absolute */
static int sp_maxlen;

/* byte masks for the 32-byte prefix compare (sp_mask[n] keeps n bytes) */
static const uint64_t sp_mask[9] = {
    0ull,
    0xffull, 0xffffull, 0xffffffull, 0xffffffffull,
    0xffffffffffull, 0xffffffffffffull, 0xffffffffffffffull,
    ~0ull
};

static void *do_sys_openat2_addr;
static void *do_faccessat_addr;
static void *vfs_fstatat_addr;
static void *do_statx_addr;

/* syscalls registered through the fallback gate (symbol missing) */
static int sp_fb_nr[SP_MAX_FB];
static int sp_fb_n;

static int path_matches(const char *target, int target_len,
                        const char *entry, int entry_len)
{
    if (entry_len > target_len) return 0;
    if (entry_len == target_len) {
        /* exact match requires separator boundary OR exact equality */
        return !susfs_memcmp(target, entry, entry_len);
    }
    /* prefix match: target must be entry/... or entry itself */
    if (susfs_memcmp(target, entry, entry_len)) return 0;
    return target[entry_len] == '/';
}

/* Returns 1 if the calling process should see this path hidden. */
static int caller_should_hide(void)
{
    /* uid >= 10000 indicates an app process; the "umounted" flag is set
     * by APatch's module mount isolation.  We approximate by checking uid
     * here; a more accurate check would inspect TIF_PROC_UMOUNTED. */
    uid_t uid = current_uid();
    return uid >= 10000;
}

/* ------------------------------------------------------------------ index */

/* one multiply; spreads the very common shared prefixes ("/sdcard/",
 * "/data/da", "/data/lo") over the whole table. */
static inline unsigned sp_key8(uint64_t w0)
{
    return (unsigned)((w0 * 0x9E3779B97F4A7C15ull) >> (64 - 10));
}

/* unaligned 8-byte load of our own (kernel) buffer: inline asm, never a
 * memcpy call -- the KPM must not reference libc/kernel string helpers that
 * are only reachable through KernelPatch's inline wrappers. */
static inline uint64_t sp_load8(const char *p)
{
    uint64_t v;
    __asm__("ldr %0, [%1]" : "=r"(v) : "r"(p));
    return v;
}

/* first min(avail, 8) bytes of p, zero padded; avail <= 0 yields 0.
 * Only used on the add path and for short targets. */
static inline uint64_t sp_ld8(const char *p, int avail)
{
    uint64_t v = 0;
    int k, i;
    if (avail <= 0) return 0;
    if (avail >= 8) return sp_load8(p);
    k = avail;
    for (i = 0; i < k; i++)
        v |= ((uint64_t)(unsigned char)p[i]) << (8 * i);
    return v;
}

/* insert keeping the chain sorted by ascending entry length, so the short
 * generic entry that prefixes many targets is tested first.  Caller holds
 * sus_path_lock. */
static void sp_chain_insert(struct sus_path_entry **head,
                            struct sus_path_entry *e)
{
    struct sus_path_entry **pp = head;
    while (*pp && (*pp)->path_len <= e->path_len) pp = &(*pp)->idx_next;
    e->idx_next = *pp;
    *pp = e;
}

/* walk one chain under the lock; tw holds the target's first 32 bytes,
 * bl is the target length. */
static int sp_walk(struct sus_path_entry *e, const uint64_t tw[SP_HDRW],
                   const char *buf, int bl)
{
    for (; e; e = e->idx_next) {
        int el = e->path_len;
        int rem, w, ok = 1;

        if (el > bl) continue;

        for (rem = el, w = 0; rem > 0 && w < SP_HDRW; rem -= 8, w++) {
            if (((e->h[w] ^ tw[w]) & sp_mask[rem < 8 ? rem : 8]) != 0) {
                ok = 0;
                break;
            }
        }
        if (!ok) continue;

        /* The first min(el, 32) bytes are already proven equal by the
         * masked compare above, so for the usual short entry no memcmp is
         * needed at all -- only the boundary test. */
        if (el <= SP_HDRW * 8) {
            if (el == bl) return 1;
            if (buf[el] == '/') return 1;
            continue;
        }
        if (susfs_memcmp(buf + SP_HDRW * 8, e->path + SP_HDRW * 8,
                         (__kernel_size_t)(el - SP_HDRW * 8))) continue;
        if (el == bl) return 1;
        if (buf[el] == '/') return 1;
    }
    return 0;
}

/* Shared check: does user_path hit a registered sus_path entry?
 *
 * MUST be called after caller_should_hide() already passed.  Never takes
 * the lock, and never copies the pathname, unless an entry could match. */
static int sus_path_hit(const char __user *user_path)
{
    char buf[SUSFS_MAX_LEN_PATHNAME];
    uint64_t w0 = 0, tw[SP_HDRW];
    struct sus_path_entry *peek = 0;
    unsigned b = 0;
    int n, bl, i, use_bucket;

    if (!user_path) return 0;
    if (sus_path_count == 0) return 0;

    /* stage 0: the first 8 bytes are enough to pick the bucket.  n is
     * min(pathlen, 8); if n < 8 the whole pathname (plus its NUL) has
     * already been copied. */
    n = compat_strncpy_from_user((char *)&w0, user_path, 8);
    if (n <= 0) return 0;

    use_bucket = (n >= 8) && (((const char *)&w0)[0] == '/');
    if (use_bucket) {
        b = sp_key8(w0);
        peek = sp_bucket[b];      /* unlocked peek; a stale 0 just means one
                                   * syscall may slip through */
        if (!peek && !sp_short) return 0;   /* no copy, no lock */
    } else if (n < 8) {
        if (!sp_short) return 0;
    } else {
        /* long pathname that is not absolute: only the short chain could
         * hold a match (non-absolute entries live there) */
        if (!sp_short) return 0;
    }

    if (n < 8) {
        susfs_memcpy(buf, &w0, (__kernel_size_t)n);
        bl = n;
    } else {
        /* bounded copy: an entry never needs more than max_len + 2 bytes */
        int c = sp_maxlen + 2;
        if (c > (int)sizeof(buf) - 1) c = (int)sizeof(buf) - 1;
        n = compat_strncpy_from_user(buf, user_path, c);
        if (n <= 0) return 0;
        bl = n < c ? n : c;       /* shorter => NUL copied, else truncated */
    }
    buf[bl] = '\0';

    for (i = 0; i < SP_HDRW; i++) tw[i] = sp_ld8(buf + 8 * i, bl - 8 * i);

    susfs__raw_spin_lock(&sus_path_lock);
    if (use_bucket && sp_walk(sp_bucket[b], tw, buf, bl)) {
        susfs__raw_spin_unlock(&sus_path_lock);
        return 1;
    }
    if (sp_short && sp_walk(sp_short, tw, buf, bl)) {
        susfs__raw_spin_unlock(&sus_path_lock);
        return 1;
    }
    susfs__raw_spin_unlock(&sus_path_lock);
    return 0;
}

/* --------------------------------------------------------------- hooks */

/* All four entry points take the pathname as a user pointer in arg1, so the
 * decision and the action are identical for all of them. */
static void sp_hook_common(hook_fargs4_t *args, void *udata)
{
    const char __user *user_path = (const char __user *)args->arg1;

    if (sus_path_count == 0) return;
    if (!caller_should_hide()) return;
    if (sus_path_hit(user_path)) {
        args->skip_origin = 1;
        args->ret = (uint64_t)(long)-ENOENT;
    }
    (void)udata;
}

/* do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
 * Covers open()/openat()/openat2()/fopen(). */
static void before_do_sys_openat2(hook_fargs4_t *args, void *udata)
{
    sp_hook_common(args, udata);
}

/* do_faccessat(int dfd, const char __user *filename, int mode, unsigned int
 * flags) -- covers faccessat() and faccessat2(), i.e. access(),
 * File.exists(). */
static void before_do_faccessat(hook_fargs4_t *args, void *udata)
{
    sp_hook_common(args, udata);
}

/* vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat,
 * int flags) -- covers newfstatat(), i.e. stat(), File.stat(),
 * File.length(). */
static void before_vfs_fstatat(hook_fargs4_t *args, void *udata)
{
    sp_hook_common(args, udata);
}

/* do_statx(int dfd, const char __user *filename, unsigned int flags,
 * unsigned int mask, struct statx __user *buffer) -- the modern stat(). */
static void before_do_statx(hook_fargs5_t *args, void *udata)
{
    /* hook_fargs5_t is hook_fargs8_t; the fields we touch (arg1,
     * skip_origin, ret) are prefix-compatible with hook_fargs4_t. */
    sp_hook_common((hook_fargs4_t *)args, udata);
}

/* Last resort for kernels missing one of the symbols above: a syscall-level
 * gate, registered only for the syscall(s) that lost their function hook. */
static void sp_syscall_fallback(hook_fargs8_t *args, void *udata)
{
    const char __user *user_path =
        (const char __user *)syscall_argn(args, 1);

    if (sus_path_count == 0) return;
    if (!caller_should_hide()) return;
    if (sus_path_hit(user_path)) {
        args->skip_origin = 1;
        args->ret = (uint64_t)(long)-ENOENT;
    }
    (void)udata;
}

int susfs_add_sus_path(const char *path, int is_loop)
{
    struct sus_path_entry *e;
    int plen = 0, w, bucketable;
    unsigned b = 0;

    if (!path || !*path) return -EINVAL;
    while (path[plen] && plen < SUSFS_MAX_LEN_PATHNAME) plen++;
    if (plen >= SUSFS_MAX_LEN_PATHNAME) return -ENAMETOOLONG;

    e = susfs_kzalloc(sizeof(*e), SUSFS_GFP_KERNEL);
    if (!e) return -ENOMEM;
    /* kzalloc zero-initialises, so the trailing fields are already 0. */
    susfs_memcpy(e->path, path, (__kernel_size_t)plen);
    e->path[plen] = '\0';
    e->path_len = plen;   /* cache for the hot path */
    e->is_loop = is_loop;
    for (w = 0; w < SP_HDRW; w++)
        e->h[w] = sp_ld8(e->path + 8 * w, plen - 8 * w);
    e->idx_next = 0;

    /* Entries shorter than 8 bytes cannot be bucketed on their first 8
     * bytes, and a match requires the first 8 bytes to be equal, so they
     * are kept in the always-walked short chain.  Non-absolute entries go
     * there too: a target that does not start with '/' is never bucketed,
     * and it must still be able to match them. */
    bucketable = (plen >= 8 && path[0] == '/');
    if (bucketable) b = sp_key8(e->h[0]);

    susfs__raw_spin_lock(&sus_path_lock);
    list_add_tail(&e->list, &sus_path_list);
    if (bucketable) sp_chain_insert(&sp_bucket[b], e);
    else            sp_chain_insert(&sp_short, e);
    if (plen > sp_maxlen) sp_maxlen = plen;
    susfs__raw_spin_unlock(&sus_path_lock);
    /* Publish last: the reader's count check gates everything else. */
    sus_path_count++;

    logki("susfs_kpm: add_sus_path%s: %s\n",
          is_loop ? "_loop" : "", e->path);
    return 0;
}

/* Register a fallback syscall gate, remembering it for cleanup. */
static void sp_add_fallback(int nr, const char *why)
{
    hook_err_t err;

    if (sp_fb_n >= SP_MAX_FB) return;
    err = hook_syscalln_override(nr, 4, sp_syscall_fallback, 0, 0);
    if (err != HOOK_NO_ERR) {
        logke("susfs_kpm: sus_path: fallback hook syscall %d failed: %d\n",
              nr, err);
        return;
    }
    sp_fb_nr[sp_fb_n++] = nr;
    logki("susfs_kpm: sus_path: fell back to syscall %d hook (%s)\n", nr, why);
}

int susfs_sus_path_init_hooks(void)
{
    hook_err_t (*wrap)(void *, int32_t, void *, void *, void *) = hook_wrap;
    hook_err_t err;
    int rc = 0;

    HIDE_PTR(wrap);

    do_sys_openat2_addr = (void *)susfs_ksym("do_sys_openat2");
    do_faccessat_addr   = (void *)susfs_ksym("do_faccessat");
    vfs_fstatat_addr    = (void *)susfs_ksym("vfs_fstatat");
    do_statx_addr       = (void *)susfs_ksym("do_statx");

    /* openat/openat2.  This is the same function open_redirect hooks (it
     * runs later, see susfs_init() ordering), and KernelPatch supports
     * several chain items on one function -- sus_kstat/sus_map already share
     * show_map_vma the same way.  Our item runs first so that hiding is
     * decided on the original pathname. */
    if (do_sys_openat2_addr) {
        err = wrap(do_sys_openat2_addr, 3, (void *)before_do_sys_openat2, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: sus_path: hook do_sys_openat2 failed: %d\n", err);
            do_sys_openat2_addr = 0;
            rc = (int)err;
        } else {
            logki("susfs_kpm: sus_path: hooked do_sys_openat2 @ %px\n",
                  do_sys_openat2_addr);
        }
    } else {
        logke("susfs_kpm: sus_path: do_sys_openat2 not in kallsyms\n");
    }
    if (!do_sys_openat2_addr) {
        sp_add_fallback(__NR_openat, "openat");
        sp_add_fallback(__NR_openat2, "openat2");
    }

    /* faccessat/faccessat2 */
    if (do_faccessat_addr) {
        err = wrap(do_faccessat_addr, 4, (void *)before_do_faccessat, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: sus_path: hook do_faccessat failed: %d\n", err);
            do_faccessat_addr = 0;
            rc = (int)err;
        } else {
            logki("susfs_kpm: sus_path: hooked do_faccessat @ %px\n",
                  do_faccessat_addr);
        }
    } else {
        logke("susfs_kpm: sus_path: do_faccessat not in kallsyms\n");
    }
    if (!do_faccessat_addr) {
        sp_add_fallback(__NR_faccessat, "faccessat");
        sp_add_fallback(__NR_faccessat2, "faccessat2");
    }

    /* newfstatat */
    if (vfs_fstatat_addr) {
        err = wrap(vfs_fstatat_addr, 4, (void *)before_vfs_fstatat, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: sus_path: hook vfs_fstatat failed: %d\n", err);
            vfs_fstatat_addr = 0;
            rc = (int)err;
        } else {
            logki("susfs_kpm: sus_path: hooked vfs_fstatat @ %px\n",
                  vfs_fstatat_addr);
        }
    } else {
        logke("susfs_kpm: sus_path: vfs_fstatat not in kallsyms\n");
    }
    if (!vfs_fstatat_addr)
        sp_add_fallback(__NR_newfstatat, "newfstatat");

    /* statx */
    if (do_statx_addr) {
        err = wrap(do_statx_addr, 5, (void *)before_do_statx, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: sus_path: hook do_statx failed: %d\n", err);
            do_statx_addr = 0;
            rc = (int)err;
        } else {
            logki("susfs_kpm: sus_path: hooked do_statx @ %px\n",
                  do_statx_addr);
        }
    } else {
        logke("susfs_kpm: sus_path: do_statx not in kallsyms\n");
    }
    if (!do_statx_addr)
        sp_add_fallback(__NR_statx, "statx");

    /* Emit to dmesg so userspace can verify the hooks are active. */
    if (susfs_printk) {
        susfs_printk("susfs_kpm: sus_path hooked "
                     "(do_sys_openat2=%d do_faccessat=%d vfs_fstatat=%d "
                     "do_statx=%d, syscall fallbacks=%d)\n",
                     do_sys_openat2_addr != 0, do_faccessat_addr != 0,
                     vfs_fstatat_addr != 0, do_statx_addr != 0, sp_fb_n);
    }
    return rc;
}

void susfs_sus_path_cleanup(void)
{
    void (*un)(void *, void *, void *, int) = hook_unwrap_remove;
    int i;

    HIDE_PTR(un);

    if (do_sys_openat2_addr) {
        un(do_sys_openat2_addr, (void *)before_do_sys_openat2, 0, 1);
        do_sys_openat2_addr = 0;
    }
    if (do_faccessat_addr) {
        un(do_faccessat_addr, (void *)before_do_faccessat, 0, 1);
        do_faccessat_addr = 0;
    }
    if (vfs_fstatat_addr) {
        un(vfs_fstatat_addr, (void *)before_vfs_fstatat, 0, 1);
        vfs_fstatat_addr = 0;
    }
    if (do_statx_addr) {
        un(do_statx_addr, (void *)before_do_statx, 0, 1);
        do_statx_addr = 0;
    }
    for (i = 0; i < sp_fb_n; i++)
        unhook_syscalln(sp_fb_nr[i], (void *)sp_syscall_fallback, 0);
    sp_fb_n = 0;

    /* Readers take this lock for the (rare) bucket-hit path, so freeing
     * under it is safe even though the empty-bucket fast path is lockless. */
    susfs__raw_spin_lock(&sus_path_lock);
    {
        struct sus_path_entry *e, *tmp;
        list_for_each_entry_safe(e, tmp, &sus_path_list, list) {
            list_del(&e->list);
            susfs_kfree(e);
        }
    }
    sp_short = 0;
    sp_maxlen = 0;
    for (i = 0; i < SP_NBUCKET; i++) sp_bucket[i] = 0;
    susfs__raw_spin_unlock(&sus_path_lock);
    sus_path_count = 0;
}
