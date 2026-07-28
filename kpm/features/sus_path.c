// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * sus_path - hide specified paths from umounted app processes.
 *
 * Hooks path_openat() (preferred, per upstream susfs refactor) with fallback
 * to do_filp_open() if path_openat is inlined on this kernel.
 *
 * Hiding logic: when an umounted app (uid >= 10000) tries to open a path
 * that is a prefix-match against any registered sus_path entry, return
 * -ENOENT from the hook so the syscall fails before VFS continues.
 *
 * TODO(per-kernel-tuning): struct nameidata layout (path field offset) needs
 * verification on the running kernel.  For now we hook at the entry and
 * re-resolve the path string from the dentry/path inside nameidata.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <kpmalloc.h>
#include <log.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <uapi/asm-generic/errno.h>
#include <kputils.h>

#include "../include/susfs_kpm.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

struct sus_path_entry {
    struct list_head list;
    char path[SUSFS_MAX_LEN_PATHNAME];
    int is_loop;  /* 1 => re-flag on zygote spawn (sus_path_loop) */
};

static LIST_HEAD(sus_path_list);
static DEFINE_SPINLOCK(sus_path_lock);

static void *path_openat_addr;
static void *do_filp_open_addr;

static int path_matches(const char *target, int target_len,
                        const char *entry, int entry_len)
{
    if (entry_len > target_len) return 0;
    if (entry_len == target_len) {
        /* exact match requires separator boundary OR exact equality */
        return !memcmp(target, entry, entry_len);
    }
    /* prefix match: target must be entry/... or entry itself */
    if (memcmp(target, entry, entry_len)) return 0;
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

/* hook callback — runs before path_openat().
 * arg0 = struct nameidata *, arg1 = const struct open_flags *, arg2 = unsigned.
 * We can't safely deref nameidata here without per-kernel offsets, so this
 * stub records the call; full hiding requires the offset table for 6.6. */
static void before_path_openat(hook_fargs3_t *args, void *udata)
{
    if (!caller_should_hide()) return;
    /* TODO: extract nd->path.dentry->d_name.name and compare against list.
     * For 6.6, nameidata.path is at offset (verify per-build).  Until then,
     * this hook is registered but inert — callers still see real paths. */
    (void)args;
    (void)udata;
}

int susfs_add_sus_path(const char *path, int is_loop)
{
    if (!path || !*path) return -EINVAL;
    int plen = 0;
    while (path[plen] && plen < SUSFS_MAX_LEN_PATHNAME) plen++;
    if (plen >= SUSFS_MAX_LEN_PATHNAME) return -ENAMETOOLONG;

    struct sus_path_entry *e = kp_malloc(sizeof(*e));
    if (!e) return -ENOMEM;
    memset(e, 0, sizeof(*e));
    memcpy(e->path, path, plen);
    e->path[plen] = '\0';
    e->is_loop = is_loop;

    spin_lock(&sus_path_lock);
    list_add_tail(&e->list, &sus_path_list);
    spin_unlock(&sus_path_lock);

    logki("susfs_kpm: add_sus_path%s: %s\n",
          is_loop ? "_loop" : "", e->path);
    return 0;
}

int susfs_sus_path_init_hooks(void)
{
    path_openat_addr = (void *)kallsyms_lookup_name("path_openat");
    if (path_openat_addr) {
        hook_err_t (*wrap)(void *, int32_t, void *, void *, void *) = hook_wrap;
        HIDE_PTR(wrap);
        hook_err_t err = wrap(path_openat_addr, 2,
                              (void *)before_path_openat, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: hook path_openat failed: %d\n", err);
            return (int)err;
        }
        logki("susfs_kpm: hooked path_openat @ %px\n", path_openat_addr);
        return 0;
    }
    /* fallback: do_filp_open is the public entrypoint that calls path_openat */
    do_filp_open_addr = (void *)kallsyms_lookup_name("do_filp_open");
    if (do_filp_open_addr) {
        hook_err_t (*wrap)(void *, int32_t, void *, void *, void *) = hook_wrap;
        HIDE_PTR(wrap);
        hook_err_t err = wrap(do_filp_open_addr, 2,
                              (void *)before_path_openat, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: hook do_filp_open failed: %d\n", err);
            return (int)err;
        }
        logki("susfs_kpm: hooked do_filp_open @ %px\n", do_filp_open_addr);
        return 0;
    }
    logke("susfs_kpm: neither path_openat nor do_filp_open found\n");
    return -ENOSYS;
}

void susfs_sus_path_cleanup(void)
{
    if (path_openat_addr) {
        void (*un)(void *, void *, void *, int) = hook_unwrap_remove;
        HIDE_PTR(un);
        un(path_openat_addr, (void *)before_path_openat, 0, 1);
        path_openat_addr = 0;
    }
    if (do_filp_open_addr) {
        void (*un)(void *, void *, void *, int) = hook_unwrap_remove;
        HIDE_PTR(un);
        un(do_filp_open_addr, (void *)before_path_openat, 0, 1);
        do_filp_open_addr = 0;
    }

    spin_lock(&sus_path_lock);
    struct sus_path_entry *e, *tmp;
    list_for_each_entry_safe(e, tmp, &sus_path_list, list) {
        list_del(&e->list);
        kp_free(e);
    }
    spin_unlock(&sus_path_lock);
}
