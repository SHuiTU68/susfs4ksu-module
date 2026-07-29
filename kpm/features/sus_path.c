// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * sus_path - hide specified paths from app processes (uid >= 10000).
 *
 * Hooks three syscalls that file-existence detectors most commonly use:
 *   __NR_openat     — open(), fopen(), File.openInput()
 *   __NR_faccessat  — access(), File.exists()
 *   __NR_newfstatat — stat(), File.stat(), File.length()
 *
 * Hiding logic: when an app process (uid >= 10000) calls any of these
 * with a pathname that prefix-matches a registered sus_path entry, we
 * short-circuit the syscall with -ENOENT so the file appears non-existent.
 * Root and system processes (uid < 10000) are unaffected.
 *
 * This approach is kernel-version-independent — unlike hooking path_openat
 * (which requires per-kernel struct nameidata offsets), the syscall args
 * give us the pathname as a direct user pointer that we read via
 * compat_strncpy_from_user.
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

/* arm64 syscall numbers (asm-generic/unistd.h).
 * We hook the three syscalls that file-existence detectors most commonly use:
 *   openat      — open("/path", ...)           → File.open(), fopen()
 *   faccessat   — access("/path", F_OK)        → File.exists()
 *   newfstatat  — stat("/path", &buf)          → File.stat()
 * When the pathname matches a registered sus_path AND the caller is an app
 * process (uid >= 10000), we short-circuit the syscall with -ENOENT so the
 * file appears non-existent.  Root and system processes are unaffected. */
#ifndef __NR_openat
#define __NR_openat      56
#endif
#ifndef __NR_faccessat
#define __NR_faccessat   48
#endif
#ifndef __NR_newfstatat
#define __NR_newfstatat  79
#endif

struct sus_path_entry {
    struct list_head list;
    char path[SUSFS_MAX_LEN_PATHNAME];
    int path_len;  /* cached length to avoid strlen in hot path */
    int is_loop;  /* 1 => re-flag on zygote spawn (sus_path_loop) */
};

static LIST_HEAD(sus_path_list);
static DEFINE_SPINLOCK(sus_path_lock);
/* Atomic counter of registered entries.  Read WITHOUT lock on the fast
 * path: if 0, the hook returns immediately without touching user memory
 * or taking the spinlock.  This makes the overhead on non-sus_path boots
 * (the common case) essentially zero — one int read + branch. */
static int sus_path_count = 0;

static void *path_openat_addr;
static void *do_filp_open_addr;

/* Track which syscall hooks are installed so cleanup only unhooks what was
 * successfully hooked.  Each is 1 after a successful hook_syscalln call. */
static int openat_hooked = 0;
static int faccessat_hooked = 0;
static int newfstatat_hooked = 0;

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

/* Shared check: copy pathname from user space and compare against the
 * sus_path list.  Returns 1 if the path should be hidden (-ENOENT returned
 * to the caller).  MUST be called after caller_should_hide() already passed.
 *
 * Fast path: if sus_path_count == 0 (no paths registered), return
 * immediately WITHOUT copying from user space or taking the spinlock.
 * This makes the per-syscall overhead on non-sus_path boots (the common
 * case) essentially zero — one int read + branch. */
static int sus_path_should_hide(const char __user *user_path)
{
    if (!user_path) return 0;

    /* Lock-free fast path: no entries → nothing to hide.
     * int reads are atomic on aarch64; the worst case of a race during
     * add_sus_path() is one syscall slipping through, which is harmless. */
    if (sus_path_count == 0) return 0;

    char path[SUSFS_MAX_LEN_PATHNAME];
    int n = compat_strncpy_from_user(path, user_path, sizeof(path) - 1);
    if (n <= 0) return 0;
    path[n] = '\0';
    int target_len = n;

    susfs__raw_spin_lock(&sus_path_lock);
    struct sus_path_entry *e;
    list_for_each_entry(e, &sus_path_list, list) {
        /* Use cached path_len instead of re-scanning the string on
         * every hook invocation.  Set once in susfs_add_sus_path(). */
        if (path_matches(path, target_len, e->path, e->path_len)) {
            susfs__raw_spin_unlock(&sus_path_lock);
            return 1;
        }
    }
    susfs__raw_spin_unlock(&sus_path_lock);
    return 0;
}

/* ---- syscall hooks (before) ----
 * Each reads arg1 (pathname) from user space; if it matches a sus_path
 * entry and the caller is an app process, we set skip_origin=1 and
 * ret=-ENOENT to make the file appear non-existent.
 *
 * Performance: the FIRST check is sus_path_count == 0 (a single int read,
 * no function call).  When no sus_paths are registered — the common case
 * on most boots — the hook returns in ~2 instructions without ever calling
 * current_uid() or touching user memory. */

/* openat(int dfd, const char *pathname, int flags, mode_t mode) — 4 args */
static void before_openat(hook_fargs4_t *args, void *udata)
{
    if (sus_path_count == 0) return;
    if (!caller_should_hide()) return;
    const char __user *user_path = (const char __user *)syscall_argn(args, 1);
    if (sus_path_should_hide(user_path)) {
        args->skip_origin = 1;
        args->ret = (uint64_t)(long)-ENOENT;
    }
    (void)udata;
}

/* faccessat(int dfd, const char *pathname, int mode) — 3 args */
static void before_faccessat(hook_fargs3_t *args, void *udata)
{
    if (sus_path_count == 0) return;
    if (!caller_should_hide()) return;
    const char __user *user_path = (const char __user *)syscall_argn(args, 1);
    if (sus_path_should_hide(user_path)) {
        args->skip_origin = 1;
        args->ret = (uint64_t)(long)-ENOENT;
    }
    (void)udata;
}

/* newfstatat(int dfd, const char *pathname, struct stat *buf, int flag) — 4 args */
static void before_newfstatat(hook_fargs4_t *args, void *udata)
{
    if (sus_path_count == 0) return;
    if (!caller_should_hide()) return;
    const char __user *user_path = (const char __user *)syscall_argn(args, 1);
    if (sus_path_should_hide(user_path)) {
        args->skip_origin = 1;
        args->ret = (uint64_t)(long)-ENOENT;
    }
    (void)udata;
}

int susfs_add_sus_path(const char *path, int is_loop)
{
    if (!path || !*path) return -EINVAL;
    int plen = 0;
    while (path[plen] && plen < SUSFS_MAX_LEN_PATHNAME) plen++;
    if (plen >= SUSFS_MAX_LEN_PATHNAME) return -ENAMETOOLONG;

    struct sus_path_entry *e = susfs_kzalloc(sizeof(*e), SUSFS_GFP_KERNEL);
    if (!e) return -ENOMEM;
    /* kzalloc zero-initialises, so the trailing fields are already 0. */
    susfs_memcpy(e->path, path, plen);
    e->path[plen] = '\0';
    e->path_len = plen;  /* cache for hot-path comparison */
    e->is_loop = is_loop;

    susfs__raw_spin_lock(&sus_path_lock);
    list_add_tail(&e->list, &sus_path_list);
    susfs__raw_spin_unlock(&sus_path_lock);
    /* Increment count AFTER adding so the fast-path check sees the new
     * entry.  Store-after-unlock is fine: the list is already visible. */
    sus_path_count++;

    logki("susfs_kpm: add_sus_path%s: %s\n",
          is_loop ? "_loop" : "", e->path);
    return 0;
}

int susfs_sus_path_init_hooks(void)
{
    int rc = 0;

    /* The path_openat / do_filp_open hook (hook_wrap) is kept for future
     * use but is inert — the actual hiding is done by the syscall hooks
     * below, which are kernel-version-independent and give us direct access
     * to the user-space pathname argument.  We no longer need per-kernel
     * nameidata offsets. */
    path_openat_addr = (void *)kallsyms_lookup_name("path_openat");
    if (!path_openat_addr)
        path_openat_addr = (void *)kallsyms_lookup_name("do_filp_open");
    if (path_openat_addr) {
        logki("susfs_kpm: path_openat found @ %px (inert, syscalls do the work)\n",
              path_openat_addr);
    }

    /* Hook openat — catches open(), fopen(), File.openInput(), etc. */
    hook_err_t err = hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err != HOOK_NO_ERR) {
        logke("susfs_kpm: hook openat failed: %d\n", err);
        rc = (int)err;
    } else {
        openat_hooked = 1;
        logki("susfs_kpm: hooked openat syscall (before)\n");
    }

    /* Hook faccessat — catches access(), File.exists() */
    err = hook_syscalln(__NR_faccessat, 3, before_faccessat, 0, 0);
    if (err != HOOK_NO_ERR) {
        logke("susfs_kpm: hook faccessat failed: %d\n", err);
        rc = (int)err;
    } else {
        faccessat_hooked = 1;
        logki("susfs_kpm: hooked faccessat syscall (before)\n");
    }

    /* Hook newfstatat — catches stat(), File.stat(), File.length() */
    err = hook_syscalln(__NR_newfstatat, 4, before_newfstatat, 0, 0);
    if (err != HOOK_NO_ERR) {
        logke("susfs_kpm: hook newfstatat failed: %d\n", err);
        rc = (int)err;
    } else {
        newfstatat_hooked = 1;
        logki("susfs_kpm: hooked newfstatat syscall (before)\n");
    }

    /* Emit to dmesg so userspace can verify the hooks are active. */
    if (susfs_printk) {
        susfs_printk("susfs_kpm: sus_path syscalls hooked "
                     "(openat=%d faccessat=%d newfstatat=%d)\n",
                     openat_hooked, faccessat_hooked, newfstatat_hooked);
    }

    return rc;
}

void susfs_sus_path_cleanup(void)
{
    if (openat_hooked) {
        unhook_syscalln(__NR_openat, before_openat, 0);
        openat_hooked = 0;
    }
    if (faccessat_hooked) {
        unhook_syscalln(__NR_faccessat, before_faccessat, 0);
        faccessat_hooked = 0;
    }
    if (newfstatat_hooked) {
        unhook_syscalln(__NR_newfstatat, before_newfstatat, 0);
        newfstatat_hooked = 0;
    }
    path_openat_addr = 0;
    do_filp_open_addr = 0;

    susfs__raw_spin_lock(&sus_path_lock);
    struct sus_path_entry *e, *tmp;
    list_for_each_entry_safe(e, tmp, &sus_path_list, list) {
        list_del(&e->list);
        susfs_kfree(e);
    }
    susfs__raw_spin_unlock(&sus_path_lock);
    sus_path_count = 0;
}
