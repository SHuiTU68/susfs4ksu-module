// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * sus_map - hide mapped library files from /proc/self/maps et al.
 *
 * Maintains a list of file paths that should be hidden from
 * /proc/self/{maps,smaps,smaps_rollup,map_files,mem,pagemap} for umounted
 * app processes.  Hooks seq_show for proc_pid_maps and friends, plus the
 * show_meminfo-style callbacks.  Real filtering requires per-kernel
 * struct vm_area_struct offsets; stub for now.
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

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

struct sus_map_entry {
    struct list_head list;
    char path[SUSFS_MAX_LEN_PATHNAME];
};

static LIST_HEAD(sus_map_list);
static DEFINE_SPINLOCK(sus_map_lock);

static void *proc_pid_maps_show_addr;

static void before_maps_show(hook_fargs2_t *args, void *udata)
{
    /* TODO: extract vm_area_struct->vm_file->f_path.dentry from the
     * iterator's current vma, compare to sus_map_list, and if matched +
     * caller uid >= 10000, skip the seq_printf by setting skip_origin.
     * Needs per-kernel struct vm_area_struct + struct file offsets. */
    (void)args;
    (void)udata;
}

int susfs_add_sus_map(const char *path)
{
    if (!path || !*path) return -EINVAL;
    int pl = 0;
    while (path[pl] && pl < SUSFS_MAX_LEN_PATHNAME - 1) pl++;

    struct sus_map_entry *e = susfs_kzalloc(sizeof(*e), SUSFS_GFP_KERNEL);
    if (!e) return -ENOMEM;
    /* kzalloc zero-initialises, so the trailing fields are already 0. */
    susfs_memcpy(e->path, path, pl); e->path[pl] = '\0';

    susfs__raw_spin_lock(&sus_map_lock);
    list_add_tail(&e->list, &sus_map_list);
    susfs__raw_spin_unlock(&sus_map_lock);

    logki("susfs_kpm: add_sus_map: %s\n", e->path);
    return 0;
}

int susfs_sus_map_init_hooks(void)
{
    /* before_maps_show is an empty stub.  Hooking proc_pid_maps_show
     * (fired on every /proc/self/maps read — extremely frequent during
     * app startup, the dynamic linker and ART read it heavily) just to
     * do nothing adds a trampoline tax on each maps read.  Skip until
     * the real vma-filtering logic is implemented. */
    proc_pid_maps_show_addr = (void *)kallsyms_lookup_name("proc_pid_maps_show");
    if (!proc_pid_maps_show_addr)
        proc_pid_maps_show_addr = (void *)kallsyms_lookup_name("proc_maps_show");
    if (proc_pid_maps_show_addr) {
        logki("susfs_kpm: sus_map: show symbol found @ %px "
              "(not hooked — callback is a stub)\n", proc_pid_maps_show_addr);
    } else {
        logki("susfs_kpm: sus_map: no maps show symbol (inert)\n");
    }
    return 0;
}

void susfs_sus_map_cleanup(void)
{
    /* No hook installed — nothing to unhook. */
    proc_pid_maps_show_addr = 0;
    susfs__raw_spin_lock(&sus_map_lock);
    struct sus_map_entry *e, *tmp;
    list_for_each_entry_safe(e, tmp, &sus_map_list, list) {
        list_del(&e->list);
        susfs_kfree(e);
    }
    susfs__raw_spin_unlock(&sus_map_lock);
}
