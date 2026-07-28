// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * sus_mount - hide sus mounts from non-su processes.
 *
 * Two pieces:
 *   (1) A global toggle "hide_sus_mnts_for_non_su_procs" set by userspace.
 *   (2) When enabled, hook show_mountinfo / m_show to filter sus-flagged
 *       mounts when the reader is a non-su process.
 *
 * Determining "sus" mount: upstream susfs marks via VFSMOUNT_MNT_FLAGS bit
 * 0x80000000.  KPM can't easily set that bit without kernel-internal access
 * to struct mount; we approximate by maintaining a list of mount-point path
 * strings the user wants hidden.  For now we just hold the toggle and the
 * list; actual /proc/mounts filtering is a TODO.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <kpmalloc.h>
#include <log.h>
#include <linux/printk.h>
#include <linux/string.h>

#include "../include/susfs_kpm.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

static int hide_sus_mnts_enabled = 0;
static void *show_mountinfo_addr;

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
