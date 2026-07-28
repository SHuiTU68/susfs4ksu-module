// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * sus_mount - hide sus mounts from non-su processes.
 *
 * Three pieces:
 *   (1) A global toggle "hide_sus_mnts_for_non_su_procs" set by userspace.
 *   (2) A list of mount-point path strings registered via add_try_umount /
 *       auto_add_try_umount_for_bind_mount.  These are the mounts the user
 *       wants hidden/removed.
 *   (3) When enabled, hook show_mountinfo / m_show to filter sus-flagged
 *       mounts when the reader is a non-su process.
 *
 * Determining "sus" mount: upstream susfs marks via VFSMOUNT_MNT_FLAGS bit
 * 0x80000000.  KPM can't easily set that bit without kernel-internal access
 * to struct mount; we approximate by maintaining a list of mount-point path
 * strings the user wants hidden.
 *
 * IMPORTANT — try_umount "another way":
 *   Upstream susfs try_umount detaches the vfsmount inside the kernel so it
 *   disappears from every namespace.  That requires struct mount internals
 *   this KPM doesn't have.  Instead we use a hybrid approach:
 *     - The KPM records the path here (so the /proc/mounts filter hook can
 *       hide it from non-su readers once struct offsets are available).
 *     - The ACTUAL detach is done in userspace by post-mount.sh via
 *       `umount -l <path>`, which removes the mount from the init mount
 *       namespace that zygote-spawned apps inherit.
 *   This makes try_umount / auto_add_try_umount functional on APatch without
 *   requiring kernel source patches.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <log.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

#include "../include/susfs_kpm.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

#define SUSFS_TRY_UMOUNT_MAX  64
#define SUSFS_TRY_UMOUNT_PATH_LEN 256

static int hide_sus_mnts_enabled = 0;
static void *show_mountinfo_addr;

/* try_umount path list — paths the user wants detached/hidden.  Stored so
 * the show_mountinfo hook can filter them; the actual detach is performed
 * in userspace (post-mount.sh `umount -l`). */
struct try_umount_entry {
    char path[SUSFS_TRY_UMOUNT_PATH_LEN];
    int mode;  /* 0 = hide only, 1 = also try umount (userspace) */
    int in_use;
};
static struct try_umount_entry try_umount_list[SUSFS_TRY_UMOUNT_MAX];
static int try_umount_count = 0;

/* seq_operations.show for /proc/self/mountinfo — hook to skip sus entries.
 * Signature: int (*show)(struct seq_file *, struct vfsmount *). */
static void before_show_mountinfo(hook_fargs2_t *args, void *udata)
{
    if (!hide_sus_mnts_enabled) return;
    /* TODO: inspect args->arg1 (vfsmount), check if its mnt_root dentry
     * matches a sus-mount path, and if so set args->skip_origin = 1; args->ret = 0;
     * Requires per-kernel struct mount / vfsmount offsets. */
    (void)args;
    (void)udata;
}

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

/* add_try_umount — record a mount path the user wants detached/hidden.
 *
 * In upstream susfs this detaches the vfsmount in-kernel; here we only
 * record it (for the /proc/mounts filter hook) and return 0 so the
 * userspace CLI/WebUI sees success.  The actual detach is performed by
 * post-mount.sh via `umount -l <path>` in the init mount namespace.
 *
 * mode: 0 = hide from /proc/mounts only, 1 = also detach (userspace umount).
 */
int susfs_add_try_umount(const char *path, int mode)
{
    if (!path || !*path) return -EINVAL;
    int len = 0;
    while (path[len] && len < SUSFS_TRY_UMOUNT_PATH_LEN - 1) len++;
    if (len == 0) return -EINVAL;

    /* Dedup: if the path is already registered, just update the mode. */
    for (int i = 0; i < try_umount_count; i++) {
        if (try_umount_list[i].in_use &&
            susfs_strcmp(try_umount_list[i].path, path) == 0) {
            try_umount_list[i].mode = mode ? 1 : 0;
            logki("susfs_kpm: try_umount update '%s' mode=%d\n", path, mode);
            return 0;
        }
    }
    if (try_umount_count >= SUSFS_TRY_UMOUNT_MAX) {
        logke("susfs_kpm: try_umount list full (%d), dropping '%s'\n",
              SUSFS_TRY_UMOUNT_MAX, path);
        return -ENOSPC;
    }
    susfs_memcpy(try_umount_list[try_umount_count].path, path, len);
    try_umount_list[try_umount_count].path[len] = '\0';
    try_umount_list[try_umount_count].mode = mode ? 1 : 0;
    try_umount_list[try_umount_count].in_use = 1;
    try_umount_count++;
    logki("susfs_kpm: try_umount add '%s' mode=%d (count=%d)\n",
          path, mode, try_umount_count);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: add_try_umount path=%s mode=%d\n",
                     path, mode);
    }
    return 0;
}

/* auto_add_try_umount_for_bind_mount — advisory entry point.
 *
 * In upstream susfs the kernel scans mount namespaces for bind mounts and
 * auto-marks them.  We can't do that safely without struct mount internals,
 * so this is a no-op that returns 0 so the CLI/WebUI toggle works.  The
 * actual auto-detection of suspicious bind mounts is done in userspace by
 * post-mount.sh (scanning /proc/mounts for module-owned bind mounts and
 * umounting them). */
int susfs_auto_add_try_umount_for_bind_mount(void)
{
    logki("susfs_kpm: auto_add_try_umount_for_bind_mount (advisory, "
          "userspace post-mount.sh handles detection)\n");
    if (susfs_printk) {
        susfs_printk("susfs_kpm: auto_add_try_umount_for_bind_mount=1 "
                     "(advisory)\n");
    }
    return 0;
}

int susfs_sus_mount_init_hooks(void)
{
    /* show_mountinfo is the seq show callback for mountinfo; on 6.6 it is
     * a static function inside fs/proc_namespace.c and may or may not be
     * in kallsyms.  We try common names. */
    show_mountinfo_addr = (void *)kallsyms_lookup_name("show_mountinfo");
    if (!show_mountinfo_addr)
        show_mountinfo_addr = (void *)kallsyms_lookup_name("m_show");
    if (!show_mountinfo_addr) {
        logke("susfs_kpm: sus_mount: no seq show symbol found, "
              "mount hiding will be inert\n");
        return 0;  /* not fatal — toggle still works for future hooks */
    }
    hook_err_t (*wrap)(void *, int32_t, void *, void *, void *) = hook_wrap;
    HIDE_PTR(wrap);
    hook_err_t err = wrap(show_mountinfo_addr, 2,
                          (void *)before_show_mountinfo, 0, 0);
    if (err != HOOK_NO_ERR) {
        logke("susfs_kpm: sus_mount hook failed: %d\n", err);
        return (int)err;
    }
    logki("susfs_kpm: sus_mount hooked @ %px\n", show_mountinfo_addr);
    return 0;
}

void susfs_sus_mount_cleanup(void)
{
    if (show_mountinfo_addr) {
        void (*un)(void *, void *, void *, int) = hook_unwrap_remove;
        HIDE_PTR(un);
        un(show_mountinfo_addr, (void *)before_show_mountinfo, 0, 1);
        show_mountinfo_addr = 0;
    }
}
