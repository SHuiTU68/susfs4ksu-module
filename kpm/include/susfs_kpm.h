/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * susfs_kpm - KernelPatch Module reimplementation of susfs for APatch
 *
 * Targets: android15-6.6 GKI kernel only.
 * Receives commands from userspace via sc_kpm_control() with a text protocol:
 *   "<CMD_HEX>|<arg1>|<arg2>|..."
 */
#ifndef SUSFS_KPM_H
#define SUSFS_KPM_H

#include <ktypes.h> /* __kernel_size_t, gfp_t, size_t */

/* ===== kfunc resolvers =====
 *
 * KernelPatch's <linux/string.h>, <linux/spinlock.h> and <linux/slab.h>
 * declare memcpy/memset/strcmp/memcmp/spin_lock/kmalloc/kfree etc. as
 * static-inline wrappers that call the extern function-pointer variables
 * kf_memcpy, kf_memset, kf_strcmp, kf__raw_spin_lock ... (via the kfunc()
 * macro in <ksyms.h>).  Those kf_* pointers are never defined inside a KPM
 * and are NOT in KernelPatch's KP_EXPORT_SYMBOL table, so any reference to
 * them shows up as "unknown symbol" at load time and the module fails to
 * load.
 *
 * To stay loadable we instead resolve the bare kernel functions through
 * kallsyms_lookup_name (which IS exported) at KPM init, stash the pointers
 * in the susfs_* globals below, and call them everywhere instead of the
 * macro-defined inline wrappers.  -fno-builtin in the Makefile stops clang
 * from emitting its own memcpy/memset calls for struct copies.
 *
 * susfs_kpm.c defines these globals and resolves them in susfs_init().
 */

/* GFP_KERNEL = __GFP_RECLAIM | __GFP_IO | __GFP_FS = 0xC00|0x40|0x80 = 0xCC0.
 * <linux/gfp.h> in KernelPatch has the flag defines commented out, so we
 * hard-code the standard arm64 value here.  kzalloc() zeroes the buffer
 * internally (it is kmalloc + __GFP_ZERO). */
#define SUSFS_GFP_KERNEL ((gfp_t)0xCC0u)

extern void *(*susfs_memcpy)(void *, const void *, __kernel_size_t);
extern void *(*susfs_memset)(void *, int, __kernel_size_t);
extern int   (*susfs_strcmp)(const char *, const char *);
extern int   (*susfs_memcmp)(const void *, const void *, __kernel_size_t);
/* kzalloc is wrapped in a function (not a raw pointer) because on many GKI
 * kernels "kzalloc" is not exported via kallsyms; we fall back to
 * __kmalloc + memset.  See susfs_kpm.c:susfs_kzalloc(). */
extern void *(*susfs_kzalloc_real)(size_t, gfp_t);
extern int   susfs_kzalloc_fallback;
void *susfs_kzalloc(size_t size, gfp_t flags);
extern void  (*susfs_kfree)(const void *);
extern void *(*susfs_vmalloc)(unsigned long);
extern void  (*susfs_vfree)(const void *);
/* _raw_spin_lock / _raw_spin_unlock take raw_spinlock_t *; a spinlock_t *
 * has identical layout at offset 0, so we pass &lock directly.  Declared
 * with void * so the call sites compile without depending on <linux/spinlock.h>
 * being included before this header. */
extern void  (*susfs__raw_spin_lock)(void *);
extern void (*susfs__raw_spin_unlock)(void *);

/* printk — resolved like the other kfunc pointers so the KPM can write to
 * the regular kernel log buffer (dmesg).  logki/log_boot only reach KP's
 * internal boot log, which userspace cannot read without an authed
 * SUPERCALL_BOOTLOG; printk lets post-fs-data.sh / boot-completed.sh
 * detect the KPM via `dmesg | grep susfs_kpm`. */
extern int (*susfs_printk)(const char *fmt, ...);

/* ===== version-tolerant symbol resolution =====
 *
 * KernelPatch >= 0.13.6 exports kallsyms_lookup_name_by_suffix().  Unlike
 * kallsyms_lookup_name() (exact match only) it retries the lookup through a
 * kallsyms_on_each_symbol() scan, which is what lets a KPM survive kernels
 * whose toolchain renamed the function we want: LTO and clang's interprocedural
 * cloning emit "foo.llvm.1234", "foo.constprop.0", "foo.isra.0" instead of the
 * plain "foo".  On such kernels an exact-match lookup silently returns NULL and
 * the feature quietly degrades.
 *
 * We must NOT reference it directly.  The KPM loader
 * (KernelPatch kernel/patch/module/module.c:simplify_symbols) resolves every
 * SHN_UNDEF symbol against KernelPatch's export table and fails the WHOLE load
 * with -ENOENT when one is missing -- there is no weak-symbol semantics, so a
 * direct reference would make this KPM unloadable on any KernelPatch that
 * predates the symbol.  susfs_ksym_init() therefore asks symbol_lookup_name()
 * (KernelPatch's export-table query) for the pointer at runtime and simply
 * leaves it NULL when the running KernelPatch is too old.
 *
 * susfs_ksym() is the resolver feature code should use.  It tries, in order:
 *   1. the exact name                      (kallsyms_lookup_name)
 *   2. KernelPatch's scan, when available  (handles .llvm.<hash> et al.)
 *   3. a short list of toolchain suffixes  (see susfs_kpm.c; also covers
 *      KernelPatch < 0.13.6 and the case where cfi_bypass is false)
 * KernelPatch gates step 2 on cfi_bypass and returns 0 *before* entering
 * kallsyms_on_each_symbol() when CFI is not bypassed, so calling it is never
 * worse than an exact lookup and never hands an unchecked indirect target to a
 * CFI kernel on our behalf.
 */
typedef unsigned long (*susfs_klns_t)(const char *);
extern susfs_klns_t susfs_kallsyms_by_suffix;
void susfs_ksym_init(void);
unsigned long susfs_ksym(const char *name);

/* ===== Command codes =====
 *
 * This table is a byte-for-byte mirror of the authoritative susfs v2.3.0
 * table in  luyanci/susfs4oki  kernel_patches/include/linux/susfs_def.h
 * (the reference implementation this KPM reimplements).  Keeping the exact
 * numeric values means:
 *   - a stock ksu_susfs CLI built for real susfs addresses the same
 *     features when its command channel is pointed at this KPM, and
 *   - the KPM's wire protocol can be diffed against susfs_def.h by eye.
 *
 * The userspace half of this module keeps the identical table in
 * ksu_susfs/jni/includes/susfs_cmds.h — change BOTH if a value ever moves.
 *
 * NOTE: an earlier APatch KPM revision had ADD_TRY_UMOUNT=0x55562 and
 * ADD_SUS_MOUNT=0x55564.  Those values are wrong: in real susfs 0x55562 is
 * CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE and 0x55564 is unassigned.  Both
 * were corrected here (and in the CLI) to the values below. */
#define CMD_SUSFS_ADD_SUS_PATH                    0x55550
#define CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH      0x55551 /* [deprecated] */
#define CMD_SUSFS_SET_SDCARD_ROOT_PATH            0x55552 /* [deprecated] */
#define CMD_SUSFS_ADD_SUS_PATH_LOOP               0x55553
#define CMD_SUSFS_ADD_SUS_MOUNT                   0x55560 /* [deprecated] */
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS  0x55561
/* Legacy alias kept so older in-tree code (and out-of-tree callers) still
 * compiles; the canonical spelling is ..._NON_SU_PROCS. */
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU        CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS
#define CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE   0x55562 /* [deprecated] */
#define CMD_SUSFS_ADD_SUS_KSTAT                   0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT                0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY        0x55572
#define CMD_SUSFS_ADD_TRY_UMOUNT                  0x55580 /* [deprecated] */
#define CMD_SUSFS_SET_UNAME                       0x55590
#define CMD_SUSFS_ENABLE_LOG                      0x555a0
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG       0x555b0
#define CMD_SUSFS_ADD_OPEN_REDIRECT               0x555c0
#define CMD_SUSFS_SHOW_VERSION                    0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES           0x555e2
#define CMD_SUSFS_SHOW_VARIANT                    0x555e3
#define CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE        0x555e4 /* [deprecated] */
#define CMD_SUSFS_IS_SUS_SU_READY                 0x555f0 /* [deprecated] */
#define CMD_SUSFS_SUS_SU                          0x60000 /* [deprecated] */
#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING         0x60010
#define CMD_SUSFS_ADD_SUS_MAP                     0x60020
/* KPM-only extension — NOT part of stock susfs (0x55563 is an unused hole
 * in susfs_def.h, so it cannot collide with a future stock command that
 * stays below 0x55570).  Tells the KPM to mark the bind mounts it tracks
 * for the userspace half to detach; stock susfs does this purely in
 * post-fs-data.sh by walking /proc/mounts. */
#define CMD_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT 0x55563 /* KPM-only */

/* NOTE: the E7 dcache engine's rule ABI (0x55565-0x5556a) used to live here.
 * It is no longer part of the security engine: it now belongs to the separate
 * mount_kpm package (mountkpm/include/mount_kpm.h), which owns the mount half
 * and has its own command channel magic ("SUSFSMNT" vs this engine's
 * "SUSFSYSC").  The numbers are deliberately unchanged, so nothing that still
 * speaks the old mctl wire protocol has to move; only the engine that answers
 * them did.  A dcache command arriving on THIS engine's channel now returns
 * -ENOSYS. */

#define SUSFS_MAX_LEN_PATHNAME              256
#define SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE 8192
#define SUSFS_ENABLED_FEATURES_SIZE         8192
#define SUSFS_MAX_VERSION_BUFSIZE           16
#define SUSFS_MAX_VARIANT_BUFSIZE           16
#define __NEW_UTS_LEN                       64

/* KPM identity exposed to userspace.
 * VERSION tracks the upstream susfs release this KPM reimplements
 * (currently v2.3.0) so that:
 *   - The WebUI kernel-support status page shows the 4 try_umount / auto-*
 *     features as "Deprecated" (their deprecated threshold is 2.0.0 in the
 *     WebUI JS).  This is honest: this KPM implements them via a hybrid
 *     userspace approach (post-mount.sh `umount -l`) rather than in-kernel
 *     vfsmount detachment, so they ARE deprecated relative to native susfs.
 *   - All version-gated toggles (>= 1.5.5 ... >= 1.5.9) are unlocked.
 *   - Script branches gated on [ $SUSFS_DECIMAL_MAIN -ge 2 ] activate, but
 *     those branches only run the `apd kernel umount` fallback when
 *     CONFIG_KSU_SUSFS_TRY_UMOUNT is ABSENT from enabled_features.  Since
 *     this KPM DOES advertise TRY_UMOUNT (for toggle visibility), those
 *     fallback branches stay skipped and the native add_try_umount path
 *     runs instead — exactly what we want.
 *   - The WebUI's `!v(n,2,1,0)` gate on try_umount_zygote_toggle was
 *     removed so the toggle stays available even at 2.2.0+ (the feature
 *     is deprecated but manually usable).
 *
 * NOTE: modinfo/show() reads this at runtime.  The module scripts compare it
 * against the deployed .kpm to detect a *stale boot-image copy* shadowing the
 * module's own KPM (see post-fs-data.sh), so bump this whenever the KPM is
 * rebuilt and shipped in a module release. */
#define SUSFS_KPM_NAME    "susfs_kpm"
#define SUSFS_KPM_VERSION "2.3.1"
#define SUSFS_KPM_VARIANT "GKI-APATCH"

/* UID schemes for open_redirect (mirror upstream enum) */
enum uid_scheme {
    UID_NON_APP_PROC = 0,
    UID_ROOT_PROC_EXCEPT_SU_PROC,
    UID_NON_SU_PROC,
    UID_UMOUNTED_APP_PROC,
    UID_UMOUNTED_PROC,
};

/* Shared feature prototypes */
struct sus_path_entry;
struct open_redirect_entry;
struct sus_kstat_entry;
struct sus_map_entry;

/* features/sus_path.c */
int susfs_add_sus_path(const char *path, int is_loop);
void susfs_sus_path_cleanup(void);
int susfs_sus_path_init_hooks(void);

/* features/open_redirect.c */
int susfs_add_open_redirect(const char *target, const char *redirected, int uid_scheme);
void susfs_open_redirect_cleanup(void);
int susfs_open_redirect_init_hooks(void);

/* features/sus_mount.c */
int susfs_set_hide_sus_mnts(int enabled);
int susfs_add_try_umount(const char *path, int mode);
int susfs_auto_add_try_umount_for_bind_mount(void);
void susfs_sus_mount_cleanup(void);
int susfs_sus_mount_init_hooks(void);

/* features/sus_kstat.c */
int susfs_add_sus_kstat(const char *path, unsigned long target_ino,
                        unsigned long spoofed_ino, unsigned long spoofed_dev,
                        unsigned int spoofed_nlink, long long spoofed_size,
                        long atime_sec, unsigned long atime_nsec,
                        long mtime_sec, unsigned long mtime_nsec,
                        long ctime_sec, unsigned long ctime_nsec,
                        long long blocks, long blksize, int flags, int is_static);
/* UPDATE_SUS_KSTAT: same wire format, but the entry must already exist (it is
 * matched by path) and only the match key (target ino/dev) is swapped, exactly
 * like upstream's susfs_update_sus_kstat(). */
int susfs_update_sus_kstat(const char *path, unsigned long target_ino,
                           unsigned long spoofed_ino, unsigned long spoofed_dev,
                           unsigned int spoofed_nlink, long long spoofed_size,
                           long atime_sec, unsigned long atime_nsec,
                           long mtime_sec, unsigned long mtime_nsec,
                           long ctime_sec, unsigned long ctime_nsec,
                           long long blocks, long blksize, int flags);
void susfs_sus_kstat_cleanup(void);
int susfs_sus_kstat_init_hooks(void);

/* features/sus_map.c */
int susfs_add_sus_map(const char *path);
void susfs_sus_map_cleanup(void);
int susfs_sus_map_init_hooks(void);

/* features/set_uname.c */
int susfs_set_uname(const char *release, const char *version);
void susfs_set_uname_cleanup(void);
int susfs_set_uname_init_hooks(void);

/* features/set_cmdline.c */
int susfs_set_cmdline_or_bootconfig(const char *content);
void susfs_set_cmdline_cleanup(void);
int susfs_set_cmdline_init_hooks(void);

/* features/flags.c */
int susfs_set_log_enabled(int enabled);
int susfs_set_avc_log_spoofing(int enabled);
int susfs_get_log_enabled(void);
int susfs_get_avc_log_spoofing(void);
int susfs_avc_log_spoofing_init_hooks(void);
void susfs_avc_log_spoofing_cleanup(void);

/* features/show.c */
int susfs_show_version(char *out, int outlen);
int susfs_show_enabled_features(char *out, int outlen);
int susfs_show_variant(char *out, int outlen);

#endif /* SUSFS_KPM_H */
