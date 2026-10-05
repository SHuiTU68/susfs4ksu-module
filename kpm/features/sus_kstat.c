// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * sus_kstat - spoof stat()/statx() results for app processes.
 *
 * WHAT NATIVE SUSFS DOES
 * ----------------------
 * kernel_patches/fs/susfs.c (v2.3.0):
 *   - susfs_sus_kstat_spoof_generic_fillattr() rewrites the struct kstat that
 *     generic_fillattr() just produced, gated on
 *     test_bit(AS_FLAGS_SUS_KSTAT, &inode->i_mapping->flags).
 *   - that flag is set at add/update time by susfs_mark_inode_sus_kstat(),
 *     which resolves the path with kern_path() and reads
 *     inode->i_ino / inode->i_sb->s_dev.
 *   - the patch inserts the call into vfs_getattr_nosec() behind
 *     `if (susfs_is_current_app_uid())` — i.e. ONLY app processes see the
 *     spoofed values (the CLI help says "Only effective for umounted process
 *     with uid >= 10000").
 *   - susfs_sus_kstat_spoof_show_map_vma() additionally fakes the dev/ino
 *     that /proc/self/maps prints for the file, so an ino cross-check
 *     between stat() and maps stays consistent.
 *
 * WHAT THIS KPM DOES (no kernel patch available)
 * ---------------------------------------------
 * The "inode flag + call inserted into vfs_getattr_nosec" pair is replaced by
 * a single inline hook that already receives everything we need:
 *
 *   int vfs_getattr(const struct path *path, struct kstat *stat,
 *                   u32 request_mask, unsigned int query_flags)
 *
 * Every stat family syscall funnels through it — newfstatat/stat/lstat and
 * statx go through vfs_statx() -> vfs_getattr(), fstat()/statx(fd) through
 * vfs_fstat() -> vfs_getattr() — and the inner call chain is exactly the
 * vfs_getattr_nosec() upstream patched.  Hooking the *after* stage means the
 * fs has already filled `stat`, i.e. the same moment upstream runs after
 * generic_fillattr().  Matching uses (i_ino, i_sb->s_dev) of the resolved
 * inode, which is what upstream's hash table is keyed on, so the inode flag
 * bit is not needed at all.
 *
 * The maps dev/ino spoof is done with two further inline hooks:
 *   show_map_vma(m, vma)         before: remember the spoofed pair for the
 *                                inode of vma->vm_file, keyed by seq_file
 *   show_vma_header_prefix(...)  before: substitute dev/ino for that line
 * (show_vma_header_prefix is called by show_map_vma right after it computed
 * the real values, so the substitution lands on the intended line.)
 *
 * struct kstat's layout is pinned in struct kpm_kstat below; the offsets came
 * from the target kernel's BTF (see include/susfs_offsets.h).
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

/* ===== spoof flags — MUST match ksu_susfs/jni/features/sus_kstat.c ===== */
#define KSTAT_SPOOF_INO           (1 << 0)
#define KSTAT_SPOOF_DEV           (1 << 1)
#define KSTAT_SPOOF_NLINK         (1 << 2)
#define KSTAT_SPOOF_SIZE          (1 << 3)
#define KSTAT_SPOOF_ATIME_TV_SEC  (1 << 4)
#define KSTAT_SPOOF_ATIME_TV_NSEC (1 << 5)
#define KSTAT_SPOOF_MTIME_TV_SEC  (1 << 6)
#define KSTAT_SPOOF_MTIME_TV_NSEC (1 << 7)
#define KSTAT_SPOOF_CTIME_TV_SEC  (1 << 8)
#define KSTAT_SPOOF_CTIME_TV_NSEC (1 << 9)
#define KSTAT_SPOOF_BLOCKS        (1 << 10)
#define KSTAT_SPOOF_BLKSIZE       (1 << 11)

/* ===== struct kstat, target kernel layout (BTF, size 160) ===== */
struct kpm_timespec64 {
    long long tv_sec;
    long long tv_nsec;
};

struct kpm_kstat {
    unsigned int   result_mask;      /* 0   */
    unsigned short mode;             /* 4   */
    unsigned short __pad0;           /* 6   */
    unsigned int   nlink;            /* 8   */
    unsigned int   blksize;          /* 12  */
    unsigned long long attributes;   /* 16  */
    unsigned long long attributes_mask; /* 24 */
    unsigned long long ino;          /* 32  */
    unsigned int   dev;              /* 40  (internal packed dev_t) */
    unsigned int   rdev;             /* 44  */
    unsigned int   uid;              /* 48  */
    unsigned int   gid;              /* 52  */
    long long      size;             /* 56  */
    struct kpm_timespec64 atime;     /* 64  */
    struct kpm_timespec64 mtime;     /* 80  */
    struct kpm_timespec64 ctime;     /* 96  */
    struct kpm_timespec64 btime;     /* 112 */
    unsigned long long blocks;       /* 128 */
    unsigned long long mnt_id;       /* 136 */
    unsigned int   dio_mem_align;    /* 144 */
    unsigned int   dio_offset_align; /* 148 */
    unsigned long long change_cookie;/* 152 */
};

/* Compile-time proof that the struct above really has the layout read out of
 * BTF — a typo here would otherwise silently corrupt a stat result. */
_Static_assert(sizeof(struct kpm_kstat) == 160, "kpm_kstat size");
_Static_assert(local_offsetof(struct kpm_kstat, nlink) == 8, "kstat.nlink");
_Static_assert(local_offsetof(struct kpm_kstat, blksize) == 12, "kstat.blksize");
_Static_assert(local_offsetof(struct kpm_kstat, ino) == 32, "kstat.ino");
_Static_assert(local_offsetof(struct kpm_kstat, dev) == 40, "kstat.dev");
_Static_assert(local_offsetof(struct kpm_kstat, size) == 56, "kstat.size");
_Static_assert(local_offsetof(struct kpm_kstat, atime) == 64, "kstat.atime");
_Static_assert(local_offsetof(struct kpm_kstat, mtime) == 80, "kstat.mtime");
_Static_assert(local_offsetof(struct kpm_kstat, ctime) == 96, "kstat.ctime");
_Static_assert(local_offsetof(struct kpm_kstat, blocks) == 128, "kstat.blocks");

/* ===== sus_kstat entry list ===== */
struct sus_kstat_entry {
    struct list_head list;
    char path[SUSFS_MAX_LEN_PATHNAME];
    unsigned long target_ino;      /* inode number to match */
    unsigned int  target_dev;      /* internal dev_t to match; 0 = any */
    unsigned long spoofed_ino;
    unsigned int  spoofed_dev;     /* internal dev_t (already decoded) */
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
/* Read without the lock on the hot path: 0 => nothing registered, return
 * immediately (one int load). */
static int sus_kstat_count = 0;

/* ===== kernel symbols resolved at init ===== */
static void *vfs_getattr_addr;
static void *show_map_vma_addr;
static void *show_vma_header_prefix_addr;
static int (*kpm_kern_path)(const char *, unsigned int, void *);
static void (*kpm_path_put)(void *);

/* ===== maps dev/ino substitution state =====
 * show_map_vma() computes the real dev/ino and then calls
 * show_vma_header_prefix() itself, inside the same invocation.  The spoofed
 * pair travels through this slot; `m` (the seq_file) is the guard — every
 * open of /proc/<pid>/maps owns its own seq_file, so a match on both the
 * pointer and the seq_file can only belong to the line we just inspected.
 * The slot is consumed by the prefix hook so it cannot leak into a later
 * line. */
static void *g_vma_spoof_m;
static unsigned long g_vma_spoof_ino;
static unsigned int  g_vma_spoof_dev;
static int g_vma_spoof_valid;

/* ===== helpers ===== */
static struct sus_kstat_entry *sus_kstat_find_locked(unsigned long ino,
                                                     unsigned int dev)
{
    struct sus_kstat_entry *e;
    list_for_each_entry(e, &sus_kstat_list, list) {
        if (e->target_ino != ino) continue;
        /* target_dev == 0 means "the path could not be resolved at add
         * time" — fall back to ino-only matching. */
        if (e->target_dev != 0 && e->target_dev != dev) continue;
        return e;
    }
    return 0;
}

static struct sus_kstat_entry *sus_kstat_find_by_path_locked(const char *path)
{
    struct sus_kstat_entry *e;
    list_for_each_entry(e, &sus_kstat_list, list) {
        if (susfs_strcmp(e->path, path) == 0) return e;
    }
    return 0;
}

/* Resolve path -> (ino, dev) through the kernel.  0 on success. */
static int sus_kstat_resolve(const char *path, unsigned long *ino,
                             unsigned int *dev)
{
    struct kpm_path { void *mnt; void *dentry; } p;
    void *inode;
    int rc;

    if (!kpm_kern_path || !kpm_path_put) return -ENOSYS;

    p.mnt = 0;
    p.dentry = 0;
    rc = kpm_kern_path(path, 0 /* no LOOKUP_* flags */, &p);
    if (rc) return rc;

    inode = kpm_dentry_inode(p.dentry);
    if (!inode || !kpm_inode_looks_valid(inode)) {
        kpm_path_put(&p);
        return -ENOENT;
    }
    if (ino) *ino = kpm_inode_ino(inode);
    if (dev) *dev = kpm_inode_dev(inode);
    kpm_path_put(&p);
    return 0;
}

/* ===== hook: vfs_getattr (after) ===== */
static void after_vfs_getattr(hook_fargs4_t *args, void *udata)
{
    struct sus_kstat_entry *e;
    struct kpm_kstat *st;
    void *inode;
    unsigned long ino;
    unsigned int dev;

    if (sus_kstat_count == 0) return;
    if ((long)args->ret != 0) return;          /* stat failed — nothing to fix */
    if (!kpm_is_app_proc()) return;            /* upstream: app uids only */

    st = (struct kpm_kstat *)args->arg1;
    if (!st || !kpm_is_kernel_ptr(st)) return;

    inode = kpm_path_inode((void *)args->arg0);
    if (!kpm_inode_looks_valid(inode)) return; /* unknown layout — stay out */

    ino = kpm_inode_ino(inode);
    dev = kpm_inode_dev(inode);

    susfs__raw_spin_lock(&sus_kstat_lock);
    e = sus_kstat_find_locked(ino, dev);
    susfs__raw_spin_unlock(&sus_kstat_lock);
    if (!e) return;

    if (e->flags & KSTAT_SPOOF_INO)
        st->ino = (unsigned long long)e->spoofed_ino;
    if (e->flags & KSTAT_SPOOF_DEV)
        st->dev = e->spoofed_dev;
    if (e->flags & KSTAT_SPOOF_NLINK)
        st->nlink = e->spoofed_nlink;
    if (e->flags & KSTAT_SPOOF_SIZE)
        st->size = e->spoofed_size;
    if (e->flags & KSTAT_SPOOF_ATIME_TV_SEC)
        st->atime.tv_sec = e->spoofed_atime_sec;
    if (e->flags & KSTAT_SPOOF_ATIME_TV_NSEC)
        st->atime.tv_nsec = (long long)e->spoofed_atime_nsec;
    if (e->flags & KSTAT_SPOOF_MTIME_TV_SEC)
        st->mtime.tv_sec = e->spoofed_mtime_sec;
    if (e->flags & KSTAT_SPOOF_MTIME_TV_NSEC)
        st->mtime.tv_nsec = (long long)e->spoofed_mtime_nsec;
    if (e->flags & KSTAT_SPOOF_CTIME_TV_SEC)
        st->ctime.tv_sec = e->spoofed_ctime_sec;
    if (e->flags & KSTAT_SPOOF_CTIME_TV_NSEC)
        st->ctime.tv_nsec = (long long)e->spoofed_ctime_nsec;
    if (e->flags & KSTAT_SPOOF_BLKSIZE)
        st->blksize = (unsigned int)e->spoofed_blksize;
    if (e->flags & KSTAT_SPOOF_BLOCKS)
        st->blocks = (unsigned long long)e->spoofed_blocks;

    (void)udata;
}

/* ===== hook: show_map_vma (before) =====
 * show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
 *
 * Records the spoofed (dev, ino) for the vma's backing inode so the
 * show_vma_header_prefix() call that follows prints them instead of the real
 * ones — upstream's susfs_sus_kstat_spoof_show_map_vma(). */
static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct sus_kstat_entry *e;
    void *vma, *file, *inode;
    unsigned long ino;
    unsigned int dev;

    g_vma_spoof_valid = 0;
    if (sus_kstat_count == 0) return;
    if (!kpm_is_app_proc()) return;

    vma = (void *)args->arg1;
    if (!kpm_is_kernel_ptr(vma)) return;
    file = kpm_rp(vma, KPM_OFF_VMA_VM_FILE);
    if (!kpm_is_kernel_ptr(file)) return;
    inode = kpm_file_inode(file);
    if (!kpm_inode_looks_valid(inode)) return;

    ino = kpm_inode_ino(inode);
    dev = kpm_inode_dev(inode);

    susfs__raw_spin_lock(&sus_kstat_lock);
    e = sus_kstat_find_locked(ino, dev);
    susfs__raw_spin_unlock(&sus_kstat_lock);
    if (!e) return;

    g_vma_spoof_m = (void *)args->arg0;
    g_vma_spoof_ino = e->spoofed_ino;
    g_vma_spoof_dev = e->spoofed_dev;
    g_vma_spoof_valid = 1;
    (void)udata;
}

/* ===== hook: show_vma_header_prefix (before) =====
 * show_vma_header_prefix(m, start, end, flags, pgoff, dev, ino) — 7 args.
 * arg5 = dev_t (printed major:minor), arg6 = ino (printed %08lx). */
static void before_show_vma_header_prefix(hook_fargs7_t *args, void *udata)
{
    if (!g_vma_spoof_valid) return;
    if ((void *)args->arg0 != g_vma_spoof_m) return;
    g_vma_spoof_valid = 0;              /* consume */
    args->arg5 = (uint64_t)g_vma_spoof_dev;
    args->arg6 = (uint64_t)g_vma_spoof_ino;
    (void)udata;
}

/* ===== add / update ===== */
static void sus_kstat_fill(struct sus_kstat_entry *e,
                           unsigned long target_ino, unsigned int target_dev,
                           unsigned long spoofed_ino, unsigned int spoofed_dev,
                           unsigned int spoofed_nlink, long long spoofed_size,
                           long atime_sec, unsigned long atime_nsec,
                           long mtime_sec, unsigned long mtime_nsec,
                           long ctime_sec, unsigned long ctime_nsec,
                           long long blocks, long blksize, int flags,
                           int is_static)
{
    e->target_ino = target_ino;
    e->target_dev = target_dev;
    e->spoofed_ino = spoofed_ino;
    e->spoofed_dev = spoofed_dev;
    e->spoofed_nlink = spoofed_nlink;
    e->spoofed_size = spoofed_size;
    e->spoofed_atime_sec = atime_sec;
    e->spoofed_atime_nsec = atime_nsec;
    e->spoofed_mtime_sec = mtime_sec;
    e->spoofed_mtime_nsec = mtime_nsec;
    e->spoofed_ctime_sec = ctime_sec;
    e->spoofed_ctime_nsec = ctime_nsec;
    e->spoofed_blocks = blocks;
    e->spoofed_blksize = blksize;
    e->flags = flags;
    e->is_static = is_static;
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
    struct sus_kstat_entry *e;
    unsigned long resolved_ino = 0;
    unsigned int resolved_dev = 0;
    int pl, rc;

    if (!path || !*path) return -EINVAL;

    /* Resolve the path ourselves: the CLI only sends target_ino (from stat)
     * but we need target_dev too, to key the entry the same way upstream keys
     * its hash table (i_ino + i_sb->s_dev).  A failure is not fatal:
     * add_sus_kstat is normally issued *before* the bind mount and the path
     * may genuinely not exist yet — then we match on ino only and a later
     * update_sus_kstat() fills the dev in. */
    rc = sus_kstat_resolve(path, &resolved_ino, &resolved_dev);
    if (rc == 0) {
        if (!target_ino) target_ino = resolved_ino;
    } else {
        resolved_dev = 0;
    }

    /* Duplicate path => replace (upstream: hash_del + hash_add). */
    susfs__raw_spin_lock(&sus_kstat_lock);
    e = sus_kstat_find_by_path_locked(path);
    if (e) {
        sus_kstat_fill(e, target_ino, resolved_dev, spoofed_ino,
                       kpm_huge_decode_dev((unsigned long long)spoofed_dev),
                       spoofed_nlink, spoofed_size, atime_sec, atime_nsec,
                       mtime_sec, mtime_nsec, ctime_sec, ctime_nsec,
                       blocks, blksize, flags, is_static);
        susfs__raw_spin_unlock(&sus_kstat_lock);
        logki("susfs_kpm: add_sus_kstat%s: replaced '%s' target_ino=%lu "
              "target_dev=%u\n", is_static ? "_statically" : "", path,
              target_ino, resolved_dev);
        return 0;
    }
    susfs__raw_spin_unlock(&sus_kstat_lock);

    e = susfs_kzalloc(sizeof(*e), SUSFS_GFP_KERNEL);
    if (!e) return -ENOMEM;

    pl = kpm_strlen_max(path, SUSFS_MAX_LEN_PATHNAME - 1);
    susfs_memcpy(e->path, path, pl);
    e->path[pl] = '\0';
    sus_kstat_fill(e, target_ino, resolved_dev, spoofed_ino,
                   kpm_huge_decode_dev((unsigned long long)spoofed_dev),
                   spoofed_nlink, spoofed_size, atime_sec, atime_nsec,
                   mtime_sec, mtime_nsec, ctime_sec, ctime_nsec,
                   blocks, blksize, flags, is_static);

    susfs__raw_spin_lock(&sus_kstat_lock);
    list_add_tail(&e->list, &sus_kstat_list);
    susfs__raw_spin_unlock(&sus_kstat_lock);
    sus_kstat_count++;

    logki("susfs_kpm: add_sus_kstat%s: '%s' target_ino=%lu target_dev=%u "
          "spoof_flags=0x%x\n", is_static ? "_statically" : "", e->path,
          e->target_ino, e->target_dev, flags);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: add_sus_kstat path=%s ino=%lu dev=%u "
                     "flags=0x%x\n", e->path, e->target_ino, e->target_dev,
                     flags);
    }
    return 0;
}

/* update_sus_kstat: the path was bind-mounted/overlaid since add_sus_kstat,
 * so its inode changed.  Upstream keeps the stored spoof values and only
 * swaps target_ino (kernel_patches/fs/susfs.c:susfs_update_sus_kstat). */
int susfs_update_sus_kstat(const char *path, unsigned long target_ino,
                           unsigned long spoofed_ino,
                           unsigned long spoofed_dev,
                           unsigned int spoofed_nlink, long long spoofed_size,
                           long atime_sec, unsigned long atime_nsec,
                           long mtime_sec, unsigned long mtime_nsec,
                           long ctime_sec, unsigned long ctime_nsec,
                           long long blocks, long blksize, int flags)
{
    struct sus_kstat_entry *e;
    unsigned long resolved_ino = 0;
    unsigned int resolved_dev = 0;
    int rc;

    if (!path || !*path) return -EINVAL;

    rc = sus_kstat_resolve(path, &resolved_ino, &resolved_dev);
    if (rc == 0 && !target_ino) target_ino = resolved_ino;
    if (rc != 0) resolved_dev = 0;

    susfs__raw_spin_lock(&sus_kstat_lock);
    e = sus_kstat_find_by_path_locked(path);
    if (!e) {
        susfs__raw_spin_unlock(&sus_kstat_lock);
        logke("susfs_kpm: update_sus_kstat: '%s' not found (add it first)\n",
              path);
        return -ENOENT;
    }
    /* keep the previously stored spoofed values, swap the match key */
    e->target_ino = target_ino;
    e->target_dev = resolved_dev;
    e->is_static = 0;
    susfs__raw_spin_unlock(&sus_kstat_lock);

    logki("susfs_kpm: update_sus_kstat: '%s' target_ino=%lu target_dev=%u\n",
          path, target_ino, resolved_dev);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: update_sus_kstat path=%s ino=%lu dev=%u\n",
                     path, target_ino, resolved_dev);
    }
    return 0;
}

/* ===== hook lifecycle ===== */
int susfs_sus_kstat_init_hooks(void)
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

    /* 1) vfs_getattr — struct path *, struct kstat *, u32, unsigned int.
     *    After-hook: the fs has filled `stat` already. */
    vfs_getattr_addr = (void *)kallsyms_lookup_name("vfs_getattr");
    if (!vfs_getattr_addr)
        vfs_getattr_addr = (void *)kallsyms_lookup_name("vfs_getattr.cfi_jt");
    if (vfs_getattr_addr) {
        err = wrap(vfs_getattr_addr, 4, 0, (void *)after_vfs_getattr, 0);
        if (err == HOOK_NO_ERR) {
            logki("susfs_kpm: sus_kstat: hooked vfs_getattr @ %px\n",
                  vfs_getattr_addr);
        } else {
            logke("susfs_kpm: sus_kstat: hook vfs_getattr failed: %d\n", err);
            vfs_getattr_addr = 0;
        }
    } else {
        logke("susfs_kpm: sus_kstat: vfs_getattr not in kallsyms (inert)\n");
    }

    /* 2) show_map_vma(m, vma) + show_vma_header_prefix(...) — maps dev/ino */
    show_map_vma_addr = (void *)kallsyms_lookup_name("show_map_vma");
    if (show_map_vma_addr) {
        err = wrap(show_map_vma_addr, 2, (void *)before_show_map_vma, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: sus_kstat: hook show_map_vma failed: %d\n", err);
            show_map_vma_addr = 0;
        }
    }
    show_vma_header_prefix_addr =
        (void *)kallsyms_lookup_name("show_vma_header_prefix");
    if (show_vma_header_prefix_addr) {
        err = wrap(show_vma_header_prefix_addr, 7,
                   (void *)before_show_vma_header_prefix, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: sus_kstat: hook show_vma_header_prefix failed: "
                  "%d\n", err);
            show_vma_header_prefix_addr = 0;
        }
    }

    if (!vfs_getattr_addr) {
        if (susfs_printk)
            susfs_printk("susfs_kpm: sus_kstat=unavailable "
                         "(vfs_getattr not hookable)\n");
    } else {
        if (susfs_printk)
            susfs_printk("susfs_kpm: sus_kstat=hooked "
                         "(vfs_getattr=1 maps=%d)\n",
                         (show_map_vma_addr != 0 &&
                          show_vma_header_prefix_addr != 0));
    }
    return 0;   /* never fail the whole KPM load for one feature */
}

void susfs_sus_kstat_cleanup(void)
{
    void (*un)(void *, void *, void *, int) = hook_unwrap_remove;
    HIDE_PTR(un);

    if (vfs_getattr_addr) {
        un(vfs_getattr_addr, 0, (void *)after_vfs_getattr, 1);
        vfs_getattr_addr = 0;
    }
    if (show_map_vma_addr) {
        un(show_map_vma_addr, (void *)before_show_map_vma, 0, 1);
        show_map_vma_addr = 0;
    }
    if (show_vma_header_prefix_addr) {
        un(show_vma_header_prefix_addr, (void *)before_show_vma_header_prefix,
           0, 1);
        show_vma_header_prefix_addr = 0;
    }
    g_vma_spoof_valid = 0;

    susfs__raw_spin_lock(&sus_kstat_lock);
    {
        struct sus_kstat_entry *e, *tmp;
        list_for_each_entry_safe(e, tmp, &sus_kstat_list, list) {
            list_del(&e->list);
            susfs_kfree(e);
        }
    }
    susfs__raw_spin_unlock(&sus_kstat_lock);
    sus_kstat_count = 0;
}