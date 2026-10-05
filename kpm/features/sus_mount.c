// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * sus_mount - hide module mounts from app processes.
 *
 * WHAT NATIVE SUSFS DOES
 * ----------------------
 * kernel_patches/fs/susfs.c (v2.3.0):
 *   - susfs_set_hide_sus_mnts_for_non_su_procs() arms a static key.
 *   - while armed, /proc/mounts, /proc/self/mountinfo and /proc/self/mountstats
 *     are opened with susfs_show_vfsmnt / susfs_show_mountinfo /
 *     susfs_show_vfsstat instead of the stock show_vfsmnt / show_mountinfo /
 *     show_vfsstat (patch in fs/proc_namespace.c), i.e. mounts marked
 *     VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT (0x80000000 in mnt->mnt_flags) are
 *     omitted for non-su processes.
 *   - add_try_umount() additionally *detaches* the vfsmount in-kernel
 *     (unshare + vfsmount removal) so it disappears from every namespace.
 *
 * WHAT THIS KPM DOES
 * ------------------
 * A KPM cannot detach a mount (that needs struct mount internals, mount
 * namespace surgery and the kernel's own locks), so:
 *
 *   1. HIDING is done by hooking the three seq_ops.show callbacks that back
 *      those proc files — show_vfsmnt / show_mountinfo / show_vfsstat — all
 *      of which are `int show(struct seq_file *m, struct vfsmount *mnt)`.
 *      When the mount matches a registered entry and the reader is an app,
 *      we skip the original callback, so the line never reaches the buffer.
 *      (This is the hook-level equivalent of upstream swapping the callback
 *      function; neither touches the mount itself.)
 *
 *   2. The DETACH half of try_umount stays a userspace job: post-mount.sh
 *      runs `umount -l <path>` which removes the mount from the init mount
 *      namespace that zygote-spawned apps inherit.  The KPM records the path
 *      and exports it through dmesg so the scripts can pick it up, and the
 *      hiding hook above covers the window before/if that umount happens.
 *
 * Matching a mount: at add_try_umount() time we resolve the path with
 * kern_path() and read
 *      mnt->mnt_id                        (struct mount, offset 292 from the
 *                                          embedded struct vfsmount)
 *      mnt->mnt_root->d_inode->i_ino      (the bind source directory)
 *      mnt->mnt_root->d_inode->i_sb->s_dev
 * At show time the callback hands us the same struct vfsmount, so a match is
 * an integer comparison.  mnt_id is namespace-local, the (ino, dev) pair is
 * not, so either one matching is enough (see sus_mount_matches()).
 *
 * Gating: hidden from app processes (uid >= 10000) only — upstream's
 * "non-su proc"; the ksu_susfs CLI (root) must keep seeing the real list.
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

#include "../include/susfs_kpm.h"
#include "../include/susfs_offsets.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

#define SUSFS_TRY_UMOUNT_MAX      64
#define SUSFS_TRY_UMOUNT_PATH_LEN 256

/* Entry for one registered mount. */
struct try_umount_entry {
    struct list_head list;
    char path[SUSFS_TRY_UMOUNT_PATH_LEN];
    int  mode;              /* 0 = hide only, 1 = also umount in userspace */
    int  resolved;          /* 1 if the mount could be resolved at add time */
    int  mnt_id;            /* struct mount::mnt_id (namespace local) */
    unsigned long root_ino; /* mnt->mnt_root->d_inode->i_ino  */
    unsigned int  root_dev; /* mnt->mnt_root->d_inode->i_sb->s_dev */
};

static LIST_HEAD(try_umount_list);
static DEFINE_SPINLOCK(try_umount_lock);
static int try_umount_count = 0;
static int hide_sus_mnts_enabled = 0;

static void *show_vfsmnt_addr;
static void *show_mountinfo_addr;
static void *show_vfsstat_addr;
static int (*kpm_kern_path)(const char *, unsigned int, void *);
static void (*kpm_path_put)(void *);

/* ===== shared match helper (called with try_umount_lock held) ===== */
static int sus_mount_matches_locked(int mnt_id, void *root_inode)
{
    struct try_umount_entry *e;
    unsigned long ino = 0;
    unsigned int dev = 0;

    if (root_inode && kpm_inode_looks_valid(root_inode)) {
        ino = kpm_inode_ino(root_inode);
        dev = kpm_inode_dev(root_inode);
    }

    list_for_each_entry(e, &try_umount_list, list) {
        if (!e->resolved) continue;
        if (mnt_id >= 0 && e->mnt_id == mnt_id) return 1;
        /* namespace independent fallback: same bind source directory */
        if (root_inode && e->root_ino == ino && e->root_dev == dev) return 1;
    }
    return 0;
}

/* ===== hooks: show_vfsmnt / show_mountinfo / show_vfsstat (before) =====
 * int show(struct seq_file *m, struct vfsmount *mnt)
 * Skipping the original drops the line from /proc/mounts, /proc/self/mountinfo
 * and /proc/self/mountstats respectively. */
static void before_mount_show(hook_fargs2_t *args, void *udata)
{
    void *mnt, *root_inode;
    int hidden;

    if (!hide_sus_mnts_enabled) return;
    if (try_umount_count == 0) return;
    if (!kpm_is_app_proc()) return;

    mnt = (void *)args->arg1;
    if (!kpm_is_kernel_ptr(mnt)) return;
    root_inode = kpm_mnt_root_inode(mnt);

    susfs__raw_spin_lock(&try_umount_lock);
    hidden = sus_mount_matches_locked(kpm_mnt_id(mnt), root_inode);
    susfs__raw_spin_unlock(&try_umount_lock);

    if (hidden) {
        /* show_mountinfo() etc. return 0 on success; the return value of a
         * seq_ops.show callback is used as the iteration status, 0 = ok. */
        args->skip_origin = 1;
        args->ret = 0;
    }
    (void)udata;
}

/* ===== control entry points ===== */
int susfs_set_hide_sus_mnts(int enabled)
{
    hide_sus_mnts_enabled = enabled ? 1 : 0;
    logki("susfs_kpm: hide_sus_mnts_for_non_su_procs = %d\n",
          hide_sus_mnts_enabled);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: hide_sus_mnts_for_non_su_procs=%d\n",
                     hide_sus_mnts_enabled);
    }
    return 0;
}

/* Resolve a registered path to (mnt_id, root ino/dev). */
static void sus_mount_resolve(struct try_umount_entry *e)
{
    struct kpm_path { void *mnt; void *dentry; } p;
    void *inode;
    int rc;

    e->resolved = 0;
    e->mnt_id = -1;
    e->root_ino = 0;
    e->root_dev = 0;

    if (!kpm_kern_path || !kpm_path_put) return;

    p.mnt = 0;
    p.dentry = 0;
    rc = kpm_kern_path(e->path, 0, &p);
    if (rc) {
        logkw("susfs_kpm: try_umount: cannot resolve '%s' (rc=%d); the "
              "entry will only be usable after the mount exists\n",
              e->path, rc);
        return;
    }

    e->mnt_id = kpm_mnt_id(p.mnt);
    inode = kpm_mnt_root_inode(p.mnt);
    if (inode && kpm_inode_looks_valid(inode)) {
        e->root_ino = kpm_inode_ino(inode);
        e->root_dev = kpm_inode_dev(inode);
    }
    e->resolved = 1;
    kpm_path_put(&p);
}

/* add_try_umount / add_sus_mount.
 *
 * mode 0 = hide the mount from app processes only.
 * mode 1 = additionally mark it for the userspace `umount -l` pass; the KPM
 *          itself still only hides it (see the file header). */
int susfs_add_try_umount(const char *path, int mode)
{
    struct try_umount_entry *e;
    int len;

    if (!path || !*path) return -EINVAL;
    len = kpm_strlen_max(path, SUSFS_TRY_UMOUNT_PATH_LEN - 1);
    if (len == 0) return -EINVAL;

    /* Update in place when the path is already registered. */
    susfs__raw_spin_lock(&try_umount_lock);
    list_for_each_entry(e, &try_umount_list, list) {
        if (susfs_strcmp(e->path, path) == 0) {
            e->mode = mode ? 1 : 0;
            susfs__raw_spin_unlock(&try_umount_lock);
            sus_mount_resolve(e);       /* mount may exist by now */
            logki("susfs_kpm: try_umount update '%s' mode=%d\n", path,
                  mode ? 1 : 0);
            return 0;
        }
    }
    susfs__raw_spin_unlock(&try_umount_lock);

    if (try_umount_count >= SUSFS_TRY_UMOUNT_MAX) {
        logke("susfs_kpm: try_umount list full (%d), dropping '%s'\n",
              SUSFS_TRY_UMOUNT_MAX, path);
        return -ENOSPC;
    }

    e = susfs_kzalloc(sizeof(*e), SUSFS_GFP_KERNEL);
    if (!e) return -ENOMEM;
    susfs_memcpy(e->path, path, len);
    e->path[len] = '\0';
    e->mode = mode ? 1 : 0;
    sus_mount_resolve(e);

    susfs__raw_spin_lock(&try_umount_lock);
    list_add_tail(&e->list, &try_umount_list);
    susfs__raw_spin_unlock(&try_umount_lock);
    try_umount_count++;

    logki("susfs_kpm: try_umount add '%s' mode=%d mnt_id=%d root_ino=%lu "
          "(count=%d)\n", e->path, e->mode, e->mnt_id, e->root_ino,
          try_umount_count);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: add_try_umount path=%s mode=%d mnt_id=%d "
                     "resolved=%d\n", e->path, e->mode, e->mnt_id,
                     e->resolved);
    }
    return 0;
}

/* auto_add_try_umount_for_bind_mount — in upstream this makes the kernel scan
 * mount namespaces for bind mounts that belong to KSU and mark them.  From a
 * KPM that is neither possible nor needed: APatch knows exactly which mounts
 * it creates, and the module's own post-mount.sh already enumerates them
 * (`mount | grep modules`).  We report that the request was understood so the
 * WebUI toggle and the CLI call succeed, and tell userspace to do the scan. */
int susfs_auto_add_try_umount_for_bind_mount(void)
{
    logki("susfs_kpm: auto_add_try_umount_for_bind_mount requested "
          "(userspace post-mount.sh performs the enumeration)\n");
    if (susfs_printk) {
        susfs_printk("susfs_kpm: auto_add_try_umount_for_bind_mount=1\n");
    }
    return 0;
}

/* ===== hook lifecycle ===== */
int susfs_sus_mount_init_hooks(void)
{
    hook_err_t err;
    hook_err_t (*wrap)(void *, int32_t, void *, void *, void *) = hook_wrap;
    HIDE_PTR(wrap);

    kpm_kern_path = (typeof(kpm_kern_path))kallsyms_lookup_name("kern_path");
    kpm_path_put = (typeof(kpm_path_put))kallsyms_lookup_name("path_put");
    if (!kpm_kern_path)
        kpm_kern_path =
            (typeof(kpm_kern_path))kallsyms_lookup_name("kern_path.cfi_jt");
    if (!kpm_path_put)
        kpm_path_put =
            (typeof(kpm_path_put))kallsyms_lookup_name("path_put.cfi_jt");

    show_vfsmnt_addr = (void *)kallsyms_lookup_name("show_vfsmnt");
    show_mountinfo_addr = (void *)kallsyms_lookup_name("show_mountinfo");
    show_vfsstat_addr = (void *)kallsyms_lookup_name("show_vfsstat");

    /* show_vfsmnt  -> /proc/mounts, /proc/<pid>/mounts
     * show_mountinfo -> /proc/self/mountinfo
     * show_vfsstat -> /proc/self/mountstats */
    if (show_vfsmnt_addr) {
        err = wrap(show_vfsmnt_addr, 2, (void *)before_mount_show, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: sus_mount: hook show_vfsmnt failed: %d\n", err);
            show_vfsmnt_addr = 0;
        }
    }
    if (show_mountinfo_addr) {
        err = wrap(show_mountinfo_addr, 2, (void *)before_mount_show, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: sus_mount: hook show_mountinfo failed: %d\n",
                  err);
            show_mountinfo_addr = 0;
        }
    }
    if (show_vfsstat_addr) {
        err = wrap(show_vfsstat_addr, 2, (void *)before_mount_show, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: sus_mount: hook show_vfsstat failed: %d\n", err);
            show_vfsstat_addr = 0;
        }
    }

    logki("susfs_kpm: sus_mount: hooks vfsmnt=%d mountinfo=%d vfsstat=%d\n",
          show_vfsmnt_addr != 0, show_mountinfo_addr != 0,
          show_vfsstat_addr != 0);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: sus_mount hooked (vfsmnt=%d mountinfo=%d "
                     "vfsstat=%d)\n", show_vfsmnt_addr != 0,
                     show_mountinfo_addr != 0, show_vfsstat_addr != 0);
    }
    return 0;
}

void susfs_sus_mount_cleanup(void)
{
    void (*un)(void *, void *, void *, int) = hook_unwrap_remove;
    HIDE_PTR(un);

    if (show_vfsmnt_addr) {
        un(show_vfsmnt_addr, (void *)before_mount_show, 0, 1);
        show_vfsmnt_addr = 0;
    }
    if (show_mountinfo_addr) {
        un(show_mountinfo_addr, (void *)before_mount_show, 0, 1);
        show_mountinfo_addr = 0;
    }
    if (show_vfsstat_addr) {
        un(show_vfsstat_addr, (void *)before_mount_show, 0, 1);
        show_vfsstat_addr = 0;
    }

    susfs__raw_spin_lock(&try_umount_lock);
    {
        struct try_umount_entry *e, *tmp;
        list_for_each_entry_safe(e, tmp, &try_umount_list, list) {
            list_del(&e->list);
            susfs_kfree(e);
        }
    }
    susfs__raw_spin_unlock(&try_umount_lock);
    try_umount_count = 0;
    hide_sus_mnts_enabled = 0;
}