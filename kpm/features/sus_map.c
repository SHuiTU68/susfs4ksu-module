// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * sus_map - hide module-injected mapped files from app processes.
 *
 * WHAT NATIVE SUSFS DOES
 * ----------------------
 * kernel_patches/fs/susfs.c (v2.3.0):
 *   - susfs_add_sus_map() resolves the path with kern_path() and sets
 *     AS_FLAGS_SUS_MAP (bit 39) in inode->i_mapping->flags.
 *   - the patch inserts `if (SUSFS_IS_INODE_SUS_MAP(inode)) return;` into
 *     show_map_vma() (fs/proc/task_mmu.c), i.e. the /proc/<pid>/maps line for
 *     that mapping is dropped entirely.
 *
 * WHAT THIS KPM DOES
 * ------------------
 * Exactly the same idea, but keyed on (i_ino, i_sb->s_dev) instead of a flag
 * bit in the inode: an "inode flag" is a marker for "this inode is
 * registered", and inode number + device identify the inode just as well.
 * Keying this way has two advantages for a KPM: we never *write* into a
 * kernel struct (nothing to corrupt), and the entry doubles as the lookup
 * table used by open_redirect/sus_kstat.
 *
 * Hook: show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
 *   before: vma->vm_file -> file_inode() -> compare (ino, dev);
 *           on a match, skip the original function so the line is omitted
 *           (its return value is unused, upstream simply `return;`s).
 *
 * Gating: the line is hidden from app processes (uid >= 10000) only.  Root /
 * system processes keep full visibility, which is what the rest of this KPM
 * does and what makes the ksu_susfs CLI and the manager WebUI able to
 * inspect the module.
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

struct sus_map_entry {
    struct list_head list;
    char path[SUSFS_MAX_LEN_PATHNAME];
    unsigned long target_ino;   /* inode number of the registered file */
    unsigned int  target_dev;   /* internal dev_t of its superblock */
};

static LIST_HEAD(sus_map_list);
static DEFINE_SPINLOCK(sus_map_lock);
static int sus_map_count = 0;

static void *show_map_vma_addr;
static int (*kpm_kern_path)(const char *, unsigned int, void *);
static void (*kpm_path_put)(void *);

/* ===== hook: show_map_vma (before) ===== */
static void before_show_map_vma_sus_map(hook_fargs2_t *args, void *udata)
{
    struct sus_map_entry *e;
    void *vma, *file, *inode;
    unsigned long ino;
    unsigned int dev;

    if (sus_map_count == 0) return;
    if (!kpm_is_app_proc()) return;

    vma = (void *)args->arg1;
    if (!kpm_is_kernel_ptr(vma)) return;
    file = kpm_rp(vma, KPM_OFF_VMA_VM_FILE);
    if (!kpm_is_kernel_ptr(file)) return;      /* anonymous vma — visible */
    inode = kpm_file_inode(file);
    if (!kpm_inode_looks_valid(inode)) return;

    ino = kpm_inode_ino(inode);
    dev = kpm_inode_dev(inode);

    susfs__raw_spin_lock(&sus_map_lock);
    list_for_each_entry(e, &sus_map_list, list) {
        if (e->target_ino == ino && e->target_dev == dev) {
            susfs__raw_spin_unlock(&sus_map_lock);
            /* Hide the whole /proc/<pid>/maps line: upstream does a bare
             * `return;` from show_map_vma() (which is void). */
            args->skip_origin = 1;
            args->ret = 0;
            (void)udata;
            return;
        }
    }
    susfs__raw_spin_unlock(&sus_map_lock);
    (void)udata;
}

/* ===== add ===== */
int susfs_add_sus_map(const char *path)
{
    struct sus_map_entry *e;
    unsigned long ino = 0;
    unsigned int dev = 0;
    int pl, rc;

    if (!path || !*path) return -EINVAL;

    /* Resolve the path: without a real inode there is nothing to hide.
     * Upstream returns -ENOENT here as well. */
    rc = -ENOSYS;
    if (kpm_kern_path && kpm_path_put) {
        struct kpm_path { void *mnt; void *dentry; } p;
        void *inode;

        p.mnt = 0;
        p.dentry = 0;
        rc = kpm_kern_path(path, 0, &p);
        if (rc == 0) {
            inode = kpm_dentry_inode(p.dentry);
            if (inode && kpm_inode_looks_valid(inode)) {
                ino = kpm_inode_ino(inode);
                dev = kpm_inode_dev(inode);
                rc = 0;
            } else {
                rc = -ENOENT;
            }
            kpm_path_put(&p);
        }
    }
    if (rc) {
        logke("susfs_kpm: add_sus_map: cannot resolve '%s' (rc=%d)\n",
              path, rc);
        if (susfs_printk)
            susfs_printk("susfs_kpm: add_sus_map path=%s rc=%d\n", path, rc);
        return rc;
    }

    /* Replace an existing entry for the same inode. */
    susfs__raw_spin_lock(&sus_map_lock);
    list_for_each_entry(e, &sus_map_list, list) {
        if (e->target_ino == ino && e->target_dev == dev) {
            susfs__raw_spin_unlock(&sus_map_lock);
            logki("susfs_kpm: add_sus_map: '%s' already registered\n", path);
            return 0;
        }
    }
    susfs__raw_spin_unlock(&sus_map_lock);

    e = susfs_kzalloc(sizeof(*e), SUSFS_GFP_KERNEL);
    if (!e) return -ENOMEM;

    pl = kpm_strlen_max(path, SUSFS_MAX_LEN_PATHNAME - 1);
    susfs_memcpy(e->path, path, pl);
    e->path[pl] = '\0';
    e->target_ino = ino;
    e->target_dev = dev;

    susfs__raw_spin_lock(&sus_map_lock);
    list_add_tail(&e->list, &sus_map_list);
    susfs__raw_spin_unlock(&sus_map_lock);
    sus_map_count++;

    logki("susfs_kpm: add_sus_map: '%s' ino=%lu dev=%u\n", e->path, ino, dev);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: add_sus_map path=%s ino=%lu dev=%u\n",
                     e->path, ino, dev);
    }
    return 0;
}

/* ===== hook lifecycle ===== */
int susfs_sus_map_init_hooks(void)
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

    show_map_vma_addr = (void *)kallsyms_lookup_name("show_map_vma");
    if (!show_map_vma_addr)
        show_map_vma_addr = (void *)kallsyms_lookup_name("show_map_vma.cfi_jt");

    if (!show_map_vma_addr) {
        logke("susfs_kpm: sus_map: show_map_vma not in kallsyms (inert)\n");
        if (susfs_printk)
            susfs_printk("susfs_kpm: sus_map=unavailable\n");
        return 0;
    }

    /* NOTE: sus_kstat also hooks show_map_vma (to fake the dev/ino column of
     * the line).  Both are chain items on the same function — this is exactly
     * what hook_wrap() exists for.  sus_kstat's item is registered first (see
     * susfs_init() ordering) and only *modifies arguments*, so when we skip
     * the original here its header hook simply never runs. */
    err = wrap(show_map_vma_addr, 2, (void *)before_show_map_vma_sus_map, 0, 0);
    if (err != HOOK_NO_ERR) {
        logke("susfs_kpm: sus_map: hook show_map_vma failed: %d\n", err);
        show_map_vma_addr = 0;
        return (int)err;
    }

    logki("susfs_kpm: sus_map: hooked show_map_vma @ %px\n", show_map_vma_addr);
    if (susfs_printk)
        susfs_printk("susfs_kpm: sus_map=hooked (show_map_vma @ %px)\n",
                     show_map_vma_addr);
    return 0;
}

void susfs_sus_map_cleanup(void)
{
    void (*un)(void *, void *, void *, int) = hook_unwrap_remove;
    HIDE_PTR(un);

    if (show_map_vma_addr) {
        un(show_map_vma_addr, (void *)before_show_map_vma_sus_map, 0, 1);
        show_map_vma_addr = 0;
    }

    susfs__raw_spin_lock(&sus_map_lock);
    {
        struct sus_map_entry *e, *tmp;
        list_for_each_entry_safe(e, tmp, &sus_map_list, list) {
            list_del(&e->list);
            susfs_kfree(e);
        }
    }
    susfs__raw_spin_unlock(&sus_map_lock);
    sus_map_count = 0;
}