// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * open_redirect - serve one file's content at another path.
 *
 * WHAT NATIVE SUSFS DOES
 * ----------------------
 * kernel_patches/fs/susfs.c (v2.3.0) + patch hunks in fs/namei.c:
 *   - add_open_redirect(target, redirected, uid_scheme) resolves BOTH paths
 *     with kern_path() and stores target_ino/dev + redirected_ino/dev, then
 *     marks *both* inodes with AS_FLAGS_OPEN_REDIRECT (bit 36).
 *   - path_openat()/do_o_path()/do_tmpfile() call
 *     susfs_open_redirect_spoof_do_sys_openat(inode) after path resolution:
 *     if the resolved inode is the *target* and the caller matches the uid
 *     scheme, the walk is restarted on the *redirected* path, so the opened
 *     file (and therefore the fd content) is the redirected one while the
 *     app believes it opened the target path.
 *   - because the fd then belongs to the redirected inode, three more places
 *     hide that fact (all keyed on the *redirected* inode):
 *       vfs_readlink()            -> reports the target path
 *       do_proc_readlink()        -> /proc/<pid>/fd/N, /proc/<pid>/exe
 *       show_map_vma()            -> /proc/<pid>/maps name column
 *
 * WHAT THIS KPM DOES
 * ------------------
 *   (a) REDIRECT OPENS — inline hook on
 *           do_sys_openat2(int dfd, const char __user *filename,
 *                          struct open_how *how)
 *       the single entry point of open/openat/openat2 (and of the legacy
 *       do_sys_open() wrapper).  The pathname is still a *user* pointer at
 *       that point, so instead of walking nameidata internals (struct
 *       nameidata / filename / open_flags offsets we would have to trust) we
 *       simply replace arg1 with a user-stack copy of the redirected path.
 *       The kernel then resolves and opens the redirected file natively, with
 *       correct permissions, audit data, fd alloc, O_PATH/O_TMPFILE handling
 *       and so on — i.e. exactly the end state upstream reaches by restarting
 *       the walk, without touching any kernel structure.
 *       The uid_scheme is evaluated before the swap, like upstream does.
 *
 *   (b) NAME DISGUISE — the fd belongs to the redirected file, so four
 *       read-only lookups are hooked to report the target path instead:
 *           vfs_readlink(dentry, buffer, buflen)      readlinkat() on a symlink
 *           d_path(path, buf, buflen)                 /proc/<pid>/fd/N, /proc/<pid>/exe
 *           seq_path(m, path, esc)                    /proc/<pid>/maps name column
 *       All three match on (i_ino, i_sb->s_dev) of the *redirected* inode —
 *       the exact condition upstream expresses as
 *       SUSFS_IS_INODE_OPEN_REDIRECT + reversed_lookup_only entry.
 *
 * LIMITATIONS (documented on purpose)
 *   - The open path is matched by *string* against the registered target
 *     pathname (absolute, as `realpath()` produced it in the CLI), not by
 *     resolved inode.  Opening the target through a different spelling
 *     (symlink, relative path, /proc/self/fd re-open) is therefore not
 *     redirected.  Native susfs catches those because it sits inside
 *     path_openat; matching a resolved inode from a KPM would require
 *     re-implementing that walk.
 *   - Only the forward direction (target -> redirected) redirects opens, which
 *     is what upstream does too (its reversed entries exist purely for the
 *     name disguise above).
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
#include "../include/susfs_offsets.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

struct open_redirect_entry {
    struct list_head list;
    char target[SUSFS_MAX_LEN_PATHNAME];
    char redirected[SUSFS_MAX_LEN_PATHNAME];
    int uid_scheme;
    int resolved;                 /* both paths resolved at add time */
    unsigned long target_ino;
    unsigned int  target_dev;
    unsigned long redirected_ino;
    unsigned int  redirected_dev;
};

static LIST_HEAD(open_redirect_list);
static DEFINE_SPINLOCK(open_redirect_lock);
static int open_redirect_count = 0;

static void *do_sys_openat2_addr;
static void *vfs_readlink_addr;
static void *d_path_addr;
static void *seq_path_addr;
static int (*kpm_kern_path)(const char *, unsigned int, void *);
static void (*kpm_path_put)(void *);

/* ===== uid scheme evaluation (mirrors upstream's switch) =====
 * uid_scheme is fixed by the userspace enum in include/susfs_kpm.h:
 *   UID_NON_APP_PROC, UID_ROOT_PROC_EXCEPT_SU_PROC, UID_NON_SU_PROC,
 *   UID_UMOUNTED_APP_PROC, UID_UMOUNTED_PROC
 *
 * Upstream additionally consults KSU's "is current process in the su domain"
 * test.  A KPM cannot read KSU's task flags, so (as everywhere else in this
 * KPM) uid 0 stands in for "su / manager" — the ksu_susfs CLI, Magisk/APatch
 * shells and the manager's root helper all run as uid 0. */
static int redirect_scheme_matches(int scheme)
{
    int uid = kpm_current_uid_int();

    switch (scheme) {
    case UID_NON_APP_PROC:
        return (uid % 100000) < KPM_APP_UID_MIN;
    case UID_ROOT_PROC_EXCEPT_SU_PROC:
        return uid == 0 && !kpm_is_su_like_proc();
    case UID_NON_SU_PROC:
        return !kpm_is_su_like_proc();
    case UID_UMOUNTED_APP_PROC:
        return uid >= KPM_APP_UID_MIN;
    case UID_UMOUNTED_PROC:
        /* "any process outside the su domain" — with our approximation that
         * is every process except root. */
        return !kpm_is_su_like_proc();
    default:
        return 0;
    }
}

/* ===== (a) open redirect ===== */
static void before_do_sys_openat2(hook_fargs3_t *args, void *udata)
{
    struct open_redirect_entry *e;
    const char __user *user_path = (const char __user *)args->arg1;
    char path[SUSFS_MAX_LEN_PATHNAME];
    int n;
    void *__user new_path;
    int rl;

    if (open_redirect_count == 0) return;
    if (!user_path) return;

    n = compat_strncpy_from_user(path, user_path, sizeof(path) - 1);
    if (n <= 0) return;
    path[n] = '\0';

    susfs__raw_spin_lock(&open_redirect_lock);
    list_for_each_entry(e, &open_redirect_list, list) {
        if (susfs_strcmp(e->target, path) != 0) continue;
        if (!redirect_scheme_matches(e->uid_scheme)) continue;

        rl = kpm_strlen_max(e->redirected, SUSFS_MAX_LEN_PATHNAME - 1);
        /* KernelSU-style trick: copy the replacement path into a scratch area
         * below the task's user stack and hand the syscall that pointer.  The
         * kernel resolves it normally (permissions, O_PATH, audit, ...). */
        new_path = copy_to_user_stack(e->redirected, rl + 1);
        susfs__raw_spin_unlock(&open_redirect_lock);

        if (!new_path || (unsigned long)new_path >> 48) {
            logke("susfs_kpm: open_redirect: copy_to_user_stack failed\n");
            return;
        }
        args->arg1 = (uint64_t)new_path;
        logki("susfs_kpm: open_redirect: '%s' -> '%s' (uid_scheme=%d pid=%d)\n",
              e->target, e->redirected, e->uid_scheme, (int)current_uid());
        (void)udata;
        return;
    }
    susfs__raw_spin_unlock(&open_redirect_lock);
    (void)udata;
}

/* ===== (b) name disguise helpers ===== */

/* Find the entry whose *redirected* inode this is; returns the path the app
 * should see (the target path).  Caller must hold the lock; *out_len gets the
 * length. */
static const char *redirect_disguise_locked(void *inode, int *out_len)
{
    struct open_redirect_entry *e;
    unsigned long ino;
    unsigned int dev;

    if (!inode || !kpm_inode_looks_valid(inode)) return 0;
    ino = kpm_inode_ino(inode);
    dev = kpm_inode_dev(inode);

    list_for_each_entry(e, &open_redirect_list, list) {
        if (!e->resolved) continue;
        if (e->redirected_ino != ino || e->redirected_dev != dev) continue;
        *out_len = kpm_strlen_max(e->target, SUSFS_MAX_LEN_PATHNAME - 1);
        return e->target;
    }
    return 0;
}

/* int vfs_readlink(struct dentry *dentry, char __user *buffer, int buflen) */
static void before_vfs_readlink(hook_fargs3_t *args, void *udata)
{
    void *inode;
    const char *fake;
    int len = 0;
    char __user *buffer = (char __user *)args->arg1;
    int buflen = (int)args->arg2;

    if (open_redirect_count == 0) return;

    inode = kpm_dentry_inode((void *)args->arg0);
    if (!kpm_inode_looks_valid(inode)) return;

    susfs__raw_spin_lock(&open_redirect_lock);
    fake = redirect_disguise_locked(inode, &len);
    susfs__raw_spin_unlock(&open_redirect_lock);
    if (!fake || len <= 0) return;

    if (len > buflen) {
        /* upstream: -ENAMETOOLONG when the buffer cannot hold the fake path */
        args->skip_origin = 1;
        args->ret = (uint64_t)(long)-ENAMETOOLONG;
        return;
    }

    if (compat_copy_to_user(buffer, fake, len) != 0) {
        args->skip_origin = 1;
        args->ret = (uint64_t)(long)-EFAULT;
        return;
    }
    /* NOTE: upstream returns 0 here, but vfs_readlink()'s contract is "number
     * of bytes written" (do_readlinkat passes it straight back to the
     * readlink()/readlinkat() caller).  Return the length so callers such as
     * the dynamic linker see a normal, non-empty symlink. */
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)len;
    (void)udata;
}

/* char *d_path(const struct path *path, char *buf, int buflen)
 * Covers /proc/<pid>/fd/<n>, /proc/<pid>/exe, /proc/<pid>/cwd style links
 * (proc_pid_readlink() -> do_proc_readlink() -> d_path()). */
static void after_d_path(hook_fargs3_t *args, void *udata)
{
    void *inode;
    const char *fake;
    char *buf = (char *)args->arg1;
    int buflen = (int)args->arg2;
    int len = 0;

    if (open_redirect_count == 0) return;
    if (buf == 0 || buflen <= 0) return;
    if (!kpm_is_kernel_ptr(buf)) return;

    inode = kpm_path_inode((void *)args->arg0);
    if (!kpm_inode_looks_valid(inode)) return;

    susfs__raw_spin_lock(&open_redirect_lock);
    fake = redirect_disguise_locked(inode, &len);
    susfs__raw_spin_unlock(&open_redirect_lock);
    if (!fake || len <= 0) return;
    if (len + 1 > buflen) return;      /* must leave room for the NUL */

    {
        int i;
        for (i = 0; i < len; i++) buf[i] = fake[i];
        buf[len] = '\0';
    }
    /* d_path() returns a pointer into the caller's buffer */
    args->ret = (uint64_t)(unsigned long)buf;
    (void)udata;
}

/* int seq_path(struct seq_file *m, const struct path *path, const char *esc)
 * The /proc/<pid>/maps "pathname" column comes from seq_file_path() ->
 * seq_path().  We own the seq buffer write here (same technique as
 * set_cmdline) so the redirected path never appears in maps. */
static void before_seq_path(hook_fargs3_t *args, void *udata)
{
    void *m = (void *)args->arg0;
    void *path = (void *)args->arg1;
    void *inode;
    const char *fake;
    int len = 0;
    int written;

    if (open_redirect_count == 0) return;

    inode = kpm_path_inode(path);
    if (!kpm_inode_looks_valid(inode)) return;

    susfs__raw_spin_lock(&open_redirect_lock);
    fake = redirect_disguise_locked(inode, &len);
    susfs__raw_spin_unlock(&open_redirect_lock);
    if (!fake || len <= 0) return;

    written = kpm_seq_append(m, fake, len, 0);
    if (written <= 0) return;          /* buffer full — let the kernel print */
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)written;
    (void)udata;
}

/* ===== add ===== */
int susfs_add_open_redirect(const char *target, const char *redirected,
                            int uid_scheme)
{
    struct open_redirect_entry *e;
    struct kpm_path { void *mnt; void *dentry; } tp, rp;
    void *tinode = 0, *rinode = 0;
    int tl, rl, rc, resolved = 0;

    if (!target || !*target || !redirected || !*redirected) return -EINVAL;
    if (uid_scheme < UID_NON_APP_PROC || uid_scheme > UID_UMOUNTED_PROC)
        return -EINVAL;

    /* Resolve both paths.  Upstream requires both to exist (it needs their
     * inodes to mark them); we use them for the name disguise, so a failure
     * only costs us (b) — the redirect in (a) is string based and still
     * works. */
    tp.mnt = 0; tp.dentry = 0;
    rp.mnt = 0; rp.dentry = 0;
    if (kpm_kern_path && kpm_path_put) {
        rc = kpm_kern_path(target, 0, &tp);
        if (rc == 0) {
            rc = kpm_kern_path(redirected, 0, &rp);
            if (rc == 0) {
                tinode = kpm_dentry_inode(tp.dentry);
                rinode = kpm_dentry_inode(rp.dentry);
                if (tinode && rinode && kpm_inode_looks_valid(tinode) &&
                    kpm_inode_looks_valid(rinode))
                    resolved = 1;
            }
            kpm_path_put(&rp);
        } else {
            kpm_path_put(&tp);
            logkw("susfs_kpm: open_redirect: target '%s' not resolvable "
                  "(rc=%d) — only the open redirect will work\n", target, rc);
            goto add_entry;
        }
        kpm_path_put(&tp);
    }

add_entry:
    tl = kpm_strlen_max(target, SUSFS_MAX_LEN_PATHNAME - 1);
    rl = kpm_strlen_max(redirected, SUSFS_MAX_LEN_PATHNAME - 1);

    /* Replace an existing redirect for the same target path. */
    susfs__raw_spin_lock(&open_redirect_lock);
    list_for_each_entry(e, &open_redirect_list, list) {
        if (susfs_strcmp(e->target, target) != 0) continue;
        susfs_memcpy(e->redirected, redirected, rl);
        e->redirected[rl] = '\0';
        e->uid_scheme = uid_scheme;
        e->resolved = resolved;
        if (resolved) {
            e->target_ino = kpm_inode_ino(tinode);
            e->target_dev = kpm_inode_dev(tinode);
            e->redirected_ino = kpm_inode_ino(rinode);
            e->redirected_dev = kpm_inode_dev(rinode);
        }
        susfs__raw_spin_unlock(&open_redirect_lock);
        logki("susfs_kpm: add_open_redirect: replaced %s -> %s (scheme=%d)\n",
              target, redirected, uid_scheme);
        return 0;
    }
    susfs__raw_spin_unlock(&open_redirect_lock);

    e = susfs_kzalloc(sizeof(*e), SUSFS_GFP_KERNEL);
    if (!e) return -ENOMEM;

    susfs_memcpy(e->target, target, tl);
    e->target[tl] = '\0';
    susfs_memcpy(e->redirected, redirected, rl);
    e->redirected[rl] = '\0';
    e->uid_scheme = uid_scheme;
    e->resolved = resolved;
    if (resolved) {
        e->target_ino = kpm_inode_ino(tinode);
        e->target_dev = kpm_inode_dev(tinode);
        e->redirected_ino = kpm_inode_ino(rinode);
        e->redirected_dev = kpm_inode_dev(rinode);
    }

    susfs__raw_spin_lock(&open_redirect_lock);
    list_add_tail(&e->list, &open_redirect_list);
    susfs__raw_spin_unlock(&open_redirect_lock);
    open_redirect_count++;

    logki("susfs_kpm: add_open_redirect: %s -> %s (scheme=%d resolved=%d "
          "t_ino=%lu r_ino=%lu)\n", e->target, e->redirected, e->uid_scheme,
          e->resolved, e->target_ino, e->redirected_ino);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: add_open_redirect %s -> %s scheme=%d "
                     "resolved=%d\n", e->target, e->redirected, e->uid_scheme,
                     e->resolved);
    }
    return 0;
}

/* ===== hook lifecycle ===== */
int susfs_open_redirect_init_hooks(void)
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

    do_sys_openat2_addr = (void *)kallsyms_lookup_name("do_sys_openat2");
    if (do_sys_openat2_addr) {
        err = wrap(do_sys_openat2_addr, 3, (void *)before_do_sys_openat2, 0, 0);
        if (err == HOOK_NO_ERR) {
            logki("susfs_kpm: open_redirect: hooked do_sys_openat2 @ %px\n",
                  do_sys_openat2_addr);
        } else {
            logke("susfs_kpm: open_redirect: hook do_sys_openat2 failed: %d\n",
                  err);
            do_sys_openat2_addr = 0;
        }
    } else {
        logke("susfs_kpm: open_redirect: do_sys_openat2 not in kallsyms "
              "(redirect inert)\n");
    }

    vfs_readlink_addr = (void *)kallsyms_lookup_name("vfs_readlink");
    if (vfs_readlink_addr) {
        err = wrap(vfs_readlink_addr, 3, (void *)before_vfs_readlink, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: open_redirect: hook vfs_readlink failed: %d\n",
                  err);
            vfs_readlink_addr = 0;
        }
    }

    d_path_addr = (void *)kallsyms_lookup_name("d_path");
    if (d_path_addr) {
        err = wrap(d_path_addr, 3, 0, (void *)after_d_path, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: open_redirect: hook d_path failed: %d\n", err);
            d_path_addr = 0;
        }
    }

    /* seq_path also has a chain item from nothing else; maps name column. */
    seq_path_addr = (void *)kallsyms_lookup_name("seq_path");
    if (seq_path_addr) {
        err = wrap(seq_path_addr, 3, (void *)before_seq_path, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: open_redirect: hook seq_path failed: %d\n", err);
            seq_path_addr = 0;
        }
    }

    logki("susfs_kpm: open_redirect: hooks openat2=%d readlink=%d d_path=%d "
          "seq_path=%d\n", do_sys_openat2_addr != 0, vfs_readlink_addr != 0,
          d_path_addr != 0, seq_path_addr != 0);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: open_redirect hooked (openat2=%d readlink=%d "
                     "d_path=%d seq_path=%d)\n", do_sys_openat2_addr != 0,
                     vfs_readlink_addr != 0, d_path_addr != 0,
                     seq_path_addr != 0);
    }
    return 0;
}

void susfs_open_redirect_cleanup(void)
{
    void (*un)(void *, void *, void *, int) = hook_unwrap_remove;
    HIDE_PTR(un);

    if (do_sys_openat2_addr) {
        un(do_sys_openat2_addr, (void *)before_do_sys_openat2, 0, 1);
        do_sys_openat2_addr = 0;
    }
    if (vfs_readlink_addr) {
        un(vfs_readlink_addr, (void *)before_vfs_readlink, 0, 1);
        vfs_readlink_addr = 0;
    }
    if (d_path_addr) {
        un(d_path_addr, 0, (void *)after_d_path, 1);
        d_path_addr = 0;
    }
    if (seq_path_addr) {
        un(seq_path_addr, (void *)before_seq_path, 0, 1);
        seq_path_addr = 0;
    }

    susfs__raw_spin_lock(&open_redirect_lock);
    {
        struct open_redirect_entry *e, *tmp;
        list_for_each_entry_safe(e, tmp, &open_redirect_list, list) {
            list_del(&e->list);
            susfs_kfree(e);
        }
    }
    susfs__raw_spin_unlock(&open_redirect_lock);
    open_redirect_count = 0;
}