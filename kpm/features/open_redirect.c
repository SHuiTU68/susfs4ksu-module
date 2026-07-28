// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * open_redirect - redirect opens of target_path to redirected_path for
 * processes matching a UID scheme.
 *
 * Same hook point as sus_path (path_openat / do_filp_open).  When the hook
 * fires, if the requested path matches a registered target_path and the
 * caller matches the configured uid_scheme, we swap the nameidata path to
 * the redirected path.  The actual swap requires per-kernel nameidata
 * offsets and is left as a TODO.
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

#include "../include/susfs_kpm.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

struct open_redirect_entry {
    struct list_head list;
    char target[SUSFS_MAX_LEN_PATHNAME];
    char redirected[SUSFS_MAX_LEN_PATHNAME];
    int uid_scheme;
};

static LIST_HEAD(open_redirect_list);
static DEFINE_SPINLOCK(open_redirect_lock);

static void *path_openat_addr;

static int caller_matches_scheme(int scheme)
{
    uid_t uid = current_uid();
    switch (scheme) {
    case UID_NON_APP_PROC:        return uid < 10000;
    case UID_ROOT_PROC_EXCEPT_SU_PROC:
        return uid == 0; /* TODO: also check not in su domain */
    case UID_NON_SU_PROC:         return 1; /* TODO: exclude su domain */
    case UID_UMOUNTED_APP_PROC:   return uid >= 10000;
    case UID_UMOUNTED_PROC:       return 1; /* TODO: check TIF_PROC_UMOUNTED */
    default:                      return 0;
    }
}

static void before_path_openat_or(hook_fargs3_t *args, void *udata)
{
    /* TODO: extract requested path from nameidata, look up in
     * open_redirect_list, and if matched + caller_matches_scheme, swap
     * nd->path to redirected_path.  Requires per-kernel nameidata offsets. */
    (void)args;
    (void)udata;
}

int susfs_add_open_redirect(const char *target, const char *redirected,
                            int uid_scheme)
{
    if (!target || !*target || !redirected || !*redirected) return -EINVAL;
    if (uid_scheme < UID_NON_APP_PROC || uid_scheme > UID_UMOUNTED_PROC)
        return -EINVAL;

    struct open_redirect_entry *e = susfs_kzalloc(sizeof(*e), SUSFS_GFP_KERNEL);
    if (!e) return -ENOMEM;
    /* kzalloc zero-initialises, so the trailing fields are already 0. */

    int tl = 0, rl = 0;
    while (target[tl] && tl < SUSFS_MAX_LEN_PATHNAME - 1) tl++;
    while (redirected[rl] && rl < SUSFS_MAX_LEN_PATHNAME - 1) rl++;
    susfs_memcpy(e->target, target, tl); e->target[tl] = '\0';
    susfs_memcpy(e->redirected, redirected, rl); e->redirected[rl] = '\0';
    e->uid_scheme = uid_scheme;

    susfs__raw_spin_lock(&open_redirect_lock);
    list_add_tail(&e->list, &open_redirect_list);
    susfs__raw_spin_unlock(&open_redirect_lock);

    logki("susfs_kpm: add_open_redirect: %s -> %s (scheme=%d)\n",
          e->target, e->redirected, e->uid_scheme);
    return 0;
}

int susfs_open_redirect_init_hooks(void)
{
    path_openat_addr = (void *)kallsyms_lookup_name("path_openat");
    if (!path_openat_addr)
        path_openat_addr = (void *)kallsyms_lookup_name("do_filp_open");
    if (!path_openat_addr) {
        logke("susfs_kpm: open_redirect: no hook target found\n");
        return -ENOSYS;
    }
    hook_err_t (*wrap)(void *, int32_t, void *, void *, void *) = hook_wrap;
    HIDE_PTR(wrap);
    hook_err_t err = wrap(path_openat_addr, 2,
                          (void *)before_path_openat_or, 0, 0);
    if (err != HOOK_NO_ERR) {
        logke("susfs_kpm: open_redirect hook failed: %d\n", err);
        return (int)err;
    }
    logki("susfs_kpm: open_redirect hooked @ %px\n", path_openat_addr);
    return 0;
}

void susfs_open_redirect_cleanup(void)
{
    if (path_openat_addr) {
        void (*un)(void *, void *, void *, int) = hook_unwrap_remove;
        HIDE_PTR(un);
        un(path_openat_addr, (void *)before_path_openat_or, 0, 1);
        path_openat_addr = 0;
    }
    susfs__raw_spin_lock(&open_redirect_lock);
    struct open_redirect_entry *e, *tmp;
    list_for_each_entry_safe(e, tmp, &open_redirect_list, list) {
        list_del(&e->list);
        susfs_kfree(e);
    }
    susfs__raw_spin_unlock(&open_redirect_lock);
}
