/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * mount_kpm - the module-mounting engine, a KernelPatch Module of its own.
 *
 * WHY THIS IS A SEPARATE PACKAGE FROM susfs_kpm
 *
 * The two engines have nothing in common except the kernel they run on:
 *
 *   susfs_kpm   hides paths/mounts/kstats and spoofs uname/cmdline.  It is a
 *               reimplementation of susfs's kernel patches and its wire
 *               protocol is susfs's own command table, so stock ksu_susfs
 *               drives it.
 *   mount_kpm   owns the *mount* half: the dcache rule store (E7) that makes
 *               a module's system/ tree visible without mounting anything.
 *
 * Until now the mount half lived inside susfs_kpm as features/mount_dcache.c
 * and was reached through the susfs command table.  Splitting them buys:
 *
 *   - independence: either engine can be absent, updated or unloaded on its
 *     own.  A device that only wants stock susfs behaviour never loads (and
 *     never pays for) the mount engine, and the mount engine never drags the
 *     susfs command table into a boot path.
 *   - a private ABI: the dcache rules are our own extension (0x55565-0x5556a
 *     in the old table), so making them a separate package stops them from
 *     occupying holes in an ABI that upstream susfs also owns.
 *   - separate versioning: mount_kpm's version says what the *mount* engine
 *     does; userspace (metamount.sh / the WebUI) can gate on it without
 *     reading it out of the security engine's version string.
 *
 * BOTH KPMs HOOK __NR_kcmp, AND THAT IS FINE
 *
 * The command channel is a hook on the kcmp syscall (see mount_kpm.c).  Two
 * KPMs hooking the same syscall is supported: the hooks chain, and each one
 * only claims the magic value in argument 0 that belongs to it.  That is why
 * each engine has its OWN magic:
 *
 *   susfs_kpm   SUSFS_CMD_MAGIC  0x5355534653595343  "SUSFSYSC"
 *   mount_kpm   MOUNT_CMD_MAGIC  0x53555346534D4E54  "SUSFSMNT"
 *
 * With one shared magic the first hook to run would answer commands addressed
 * to the other engine (it would have to guess from the command number, and the
 * two tables overlap in range), and whichever engine was not loaded would
 * break the other.  One magic per engine means a kcmp() call for one engine
 * falls through the other hook untouched.
 *
 * SYMBOL NAME REUSE (susfs_* here as well)
 *
 * This KPM resolves and stores the same kernel-function pointers under the
 * same names susfs_kpm uses (susfs_memcpy, susfs_kfree, susfs_kzalloc, ...).
 * That is deliberate: mount_dcache.c is shared source, and the names are
 * module-local anyway - the build uses -fvisibility=hidden, so every one of
 * them is GLOBAL HIDDEN in the .kpm's symtab and is never registered in any
 * namespace another KPM could see.
 */
#ifndef MOUNT_KPM_H
#define MOUNT_KPM_H

#include <ktypes.h> /* __kernel_size_t, gfp_t, size_t */

/* ===== kfunc resolvers =====
 *
 * Same rationale as susfs_kpm.h: KernelPatch's <linux/string.h> and
 * <linux/spinlock.h> inline wrappers reference kf_* pointers that a KPM cannot
 * resolve, so the bare kernel functions are looked up through
 * kallsyms_lookup_name at init and called through these pointers instead.
 * mount_kpm.c defines them; see the comment there. */

/* GFP_KERNEL = __GFP_RECLAIM | __GFP_IO | __GFP_FS = 0xC00|0x40|0x80 = 0xCC0.
 * KernelPatch's <linux/gfp.h> has the flag defines commented out. */
#define SUSFS_GFP_KERNEL ((gfp_t)0xCC0u)

extern void *(*susfs_memcpy)(void *, const void *, __kernel_size_t);
extern void *(*susfs_memset)(void *, int, __kernel_size_t);
extern int   (*susfs_strcmp)(const char *, const char *);
extern int   (*susfs_memcmp)(const void *, const void *, __kernel_size_t);
/* kzalloc is wrapped in a function because on many GKI kernels "kzalloc" is
 * not exported via kallsyms; mount_kpm.c falls back to __kmalloc + memset. */
extern void *(*susfs_kzalloc_real)(size_t, gfp_t);
extern int   susfs_kzalloc_fallback;
void *susfs_kzalloc(size_t size, gfp_t flags);
extern void  (*susfs_kfree)(const void *);
extern void  (*susfs__raw_spin_lock)(void *);
extern void  (*susfs__raw_spin_unlock)(void *);

/* printk — the only userspace-readable channel (see susfs_kpm.c for why the
 * supercall route is closed to a root shell).  metamount.sh and the WebUI
 * detect this engine with `dmesg | grep mount_kpm`. */
extern int (*susfs_printk)(const char *fmt, ...);

/* ===== version-tolerant symbol resolution (see susfs_kpm.c) ===== */
typedef unsigned long (*susfs_klns_t)(const char *);
extern susfs_klns_t susfs_kallsyms_by_suffix;
void susfs_ksym_init(void);
unsigned long susfs_ksym(const char *name);

/* ===== path length limit =====
 * Same value the dcache rules and the susfs command table use.  A rule whose
 * virtual or real path is longer than this is refused rather than truncated:
 * two rules differing only past the cut-off would otherwise collide. */
#define SUSFS_MAX_LEN_PATHNAME 256

/* ===== command codes =====
 *
 * These numbers are inherited from the susfs command table, where they occupy
 * the unused hole 0x55565-0x5556a between
 * CMD_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT (0x55563) and
 * CMD_SUSFS_ADD_SUS_KSTAT (0x55570); nothing in susfs_def.h is assigned there,
 * so there is nothing to collide with upstream.  They are kept identical to
 * the values the in-tree client (tools/mctl.c) and the already-shipped
 * mctl binaries send, so a device that has an older mctl deployed keeps
 * working after the split.
 *
 * The command text protocol is unchanged:
 *   "<CMD_HEX_UPPER>|<arg1>|<arg2>|..."
 *
 * The two SHOW_* codes are deliberately the susfs ones rather than new values:
 * the payloads are engine identity, and keeping the numbers means a debugging
 * `mctl raw 555E1` reads back whichever engine answers.
 */
#define CMD_SUSFS_SHOW_VERSION      0x555e1
#define CMD_SUSFS_SHOW_VARIANT      0x555e3

#define CMD_SUSFS_KPM_DC_RULE_ADD   0x55565 /* path|virtual|real */
#define CMD_SUSFS_KPM_DC_RULE_CLEAR 0x55566 /* no args */
#define CMD_SUSFS_KPM_DC_RULE_COUNT 0x55567 /* returns the count as the rc */
#define CMD_SUSFS_KPM_DC_RULE_LIST  0x55568 /* out_msg: "virtual=real\n"... */
#define CMD_SUSFS_KPM_DC_CAPS       0x55569 /* out_msg: comma-separated caps */
#define CMD_SUSFS_KPM_DC_STATUS     0x5556a /* out_msg: one status line */

/* ===== engine identity =====
 *
 * VERSION is the *mount engine's* own version, not susfs's: userspace gates
 * "does this engine have feature X" on it (mount_engine_up() in metamount.sh
 * still prefers the capability string for that, but the version is what a
 * support report needs).  Bump it whenever the rule ABI or the capability
 * string changes. */
#define MOUNT_KPM_NAME    "mount_kpm"
#define MOUNT_KPM_VERSION "0.2.0"
#define MOUNT_KPM_VARIANT "GKI-APATCH"

#define MOUNT_KPM_ENABLED_FEATURES "MOUNT_DCACHE_RULE_STORE"

#define SUSFS_MAX_VERSION_BUFSIZE 16
#define SUSFS_MAX_VARIANT_BUFSIZE 16

/* ===== the E7 dcache engine =====
 *
 * Advertised capabilities.  metamount.sh refuses to choose E7 until the engine
 * advertises "readdir", because lookups that succeed while the directory
 * listing does not show the file is exactly the anomaly a root-hiding setup
 * cannot have - so a capability must only be listed once the code behind it is
 * actually in the module:
 *
 *   rule-store   the rule table + the ABI above (always present)
 *   dentry       synthetic dentry/inode pairs are installed, so lookups of a
 *                rule's virtual path land on the module's file
 *   readdir      directory listings include the synthetic entries, i.e. `ls`
 *                agrees with `stat`
 *
 * This string is a new package's *own* constant - it is deliberately NOT
 * shared with susfs_kpm any more, because the two packages now version and
 * ship separately.  It is the single place to edit as the later slices land. */
#define SUSFS_DC_CAPS_STRING "rule-store"

/* features/mount_dcache.c */
int susfs_dc_rule_add(const char *virt, const char *real);
int susfs_dc_rule_clear(void);
int susfs_dc_rule_count(void);
int susfs_dc_rule_list(char *out, int outlen);
int susfs_dc_caps(char *out, int outlen);
int susfs_dc_status(char *out, int outlen);
int susfs_dc_init(void);
void susfs_dc_cleanup(void);

#endif /* MOUNT_KPM_H */
