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

/* Command codes — kept identical to upstream susfs so ksu_susfs CLI stays familiar */
#define CMD_SUSFS_ADD_SUS_PATH              0x55550
#define CMD_SUSFS_ADD_SUS_PATH_LOOP         0x55553
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU  0x55561
#define CMD_SUSFS_ADD_TRY_UMOUNT            0x55562
#define CMD_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT 0x55563
#define CMD_SUSFS_ADD_SUS_KSTAT             0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT          0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY  0x55572
#define CMD_SUSFS_SET_UNAME                 0x55590
#define CMD_SUSFS_ENABLE_LOG                0x555a0
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG 0x555b0
#define CMD_SUSFS_ADD_OPEN_REDIRECT         0x555c0
#define CMD_SUSFS_SHOW_VERSION              0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES     0x555e2
#define CMD_SUSFS_SHOW_VARIANT              0x555e3
#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING   0x60010
#define CMD_SUSFS_ADD_SUS_MAP               0x60020

#define SUSFS_MAX_LEN_PATHNAME              256
#define SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE 8192
#define SUSFS_ENABLED_FEATURES_SIZE         8192
#define SUSFS_MAX_VERSION_BUFSIZE           16
#define SUSFS_MAX_VARIANT_BUFSIZE           16
#define __NEW_UTS_LEN                       64

/* KPM identity exposed to userspace.
 * VERSION is set to "1.5.9" to satisfy the WebUI's version gates:
 *   >= 1.5.3 : kernel support status page visible
 *   >= 1.5.5 : auto_try_umount toggle
 *   >= 1.5.7 : hide_sus_mnts toggle
 *   >= 1.5.8 : umount_for_zygote_iso_service toggle
 *   >= 1.5.9 : avc_log_spoofing toggle
 * Scripts use SUSFS_DECIMAL_MAIN (the major) for branching; at 1.5.9 the
 * major is still 1, so [ $SUSFS_DECIMAL_MAIN -ge 2 ] stays false — no
 * script behavior change. */
#define SUSFS_KPM_NAME    "susfs_kpm"
#define SUSFS_KPM_VERSION "1.5.9"
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
