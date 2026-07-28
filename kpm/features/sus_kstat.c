// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * sus_kstat - spoof inode stat results for umounted app processes.
 *
 * Maintains a kernel-side list of (path, target_ino, spoofed_kstat) entries.
 * Hooks vfs_statx / vfs_statx_fd / generic_fillattr so that when an app
 * queries stat on a target inode, the spoofed fields are returned instead.
 *
 * Real implementation needs per-kernel offsets into struct kstat; this file
 * provides list management + hook registration.  Hook callback is a stub.
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

#include "../include/susfs_kpm.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

struct sus_kstat_entry {
    struct list_head list;
    char path[SUSFS_MAX_LEN_PATHNAME];
    unsigned long target_ino;
    unsigned long spoofed_ino;
    unsigned long spoofed_dev;
    unsigned int  spoofed_nlink;
    long long     spoofed_size;
    long          spoofed_atime_sec;
    unsigned long spoofed_atime_nsec;
    long          spoofed_mtime_sec;
    unsigned long spoofed_mtime_nsec;
    long          spoofed_ctime_sec;
    unsigned long spoofed_ctime_nsec;
    long long     spoofed_blocks;
    long          spoofed_blksize;
    int           flags;
    int           is_static;
};

static LIST_HEAD(sus_kstat_list);
static DEFINE_SPINLOCK(sus_kstat_lock);

static void *vfs_statx_addr;

static void before_vfs_statx(hook_fargs5_t *args, void *udata)
{
    /* TODO: arg0 = dfd, arg1 = filename, arg2 = flags, arg3 = mask,
     * arg4 = struct kstat *.  Resolve filename, look up in list, and if
     * matched + caller uid >= 10000, overwrite fields in *kstat.
     * Needs per-kernel struct kstat offsets (ino/dev/nlink/size/atime/...). */
    (void)args;
    (void)udata;
}

int susfs_add_sus_kstat(const char *path, unsigned long target_ino,
                        unsigned long spoofed_ino, unsigned long spoofed_dev,
                        unsigned int spoofed_nlink, long long spoofed_size,
                        long atime_sec, unsigned long atime_nsec,
                        long mtime_sec, unsigned long mtime_nsec,
                        long ctime_sec, unsigned long ctime_nsec,
                        long long blocks, long blksize, int flags,
                        int is_static)
{
    if (!path || !*path) return -EINVAL;

    struct sus_kstat_entry *e = kp_malloc(sizeof(*e));
    if (!e) return -ENOMEM;
    memset(e, 0, sizeof(*e));

    int pl = 0;
    while (path[pl] && pl < SUSFS_MAX_LEN_PATHNAME - 1) pl++;
    memcpy(e->path, path, pl); e->path[pl] = '\0';

    e->target_ino         = target_ino;
    e->spoofed_ino        = spoofed_ino;
    e->spoofed_dev        = spoofed_dev;
    e->spoofed_nlink      = spoofed_nlink;
    e->spoofed_size       = spoofed_size;
    e->spoofed_atime_sec  = atime_sec;
    e->spoofed_atime_nsec = atime_nsec;
    e->spoofed_mtime_sec  = mtime_sec;
    e->spoofed_mtime_nsec = mtime_nsec;
    e->spoofed_ctime_sec  = ctime_sec;
    e->spoofed_ctime_nsec = ctime_nsec;
    e->spoofed_blocks     = blocks;
    e->spoofed_blksize    = blksize;
    e->flags              = flags;
    e->is_static          = is_static;

    spin_lock(&sus_kstat_lock);
    list_add_tail(&e->list, &sus_kstat_list);
    spin_unlock(&sus_kstat_lock);

    logki("susfs_kpm: add_sus_kstat%s: %s ino=%lu\n",
          is_static ? "_statically" : "", e->path, e->target_ino);
    return 0;
}

int susfs_sus_kstat_init_hooks(void)
{
    vfs_statx_addr = (void *)kallsyms_lookup_name("vfs_statx");
    if (!vfs_statx_addr)
        vfs_statx_addr = (void *)kallsyms_lookup_name("vfs_statx_fd");
    if (!vfs_statx_addr) {
        logke("susfs_kpm: sus_kstat: no vfs_statx symbol, inert\n");
        return 0;
    }
    hook_err_t (*wrap)(void *, int32_t, void *, void *, void *) = hook_wrap;
    HIDE_PTR(wrap);
    hook_err_t err = wrap(vfs_statx_addr, 2,
                          (void *)before_vfs_statx, 0, 0);
    if (err != HOOK_NO_ERR) {
        logke("susfs_kpm: sus_kstat hook failed: %d\n", err);
        return (int)err;
    }
    logki("susfs_kpm: sus_kstat hooked @ %px\n", vfs_statx_addr);
    return 0;
}

void susfs_sus_kstat_cleanup(void)
{
    if (vfs_statx_addr) {
        void (*un)(void *, void *, void *, int) = hook_unwrap_remove;
        HIDE_PTR(un);
        un(vfs_statx_addr, (void *)before_vfs_statx, 0, 1);
        vfs_statx_addr = 0;
    }
    spin_lock(&sus_kstat_lock);
    struct sus_kstat_entry *e, *tmp;
    list_for_each_entry_safe(e, tmp, &sus_kstat_list, list) {
        list_del(&e->list);
        kp_free(e);
    }
    spin_unlock(&sus_kstat_lock);
}
