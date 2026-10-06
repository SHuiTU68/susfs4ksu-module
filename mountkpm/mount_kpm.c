// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mount_kpm - the module-mounting engine, a KernelPatch Module of its own.
 *
 * Target: android15-6.6 GKI kernel.
 *
 * WHAT IT IS
 *
 * The kernel half of the mount bridge: the E7 dcache rule store (see
 * features/mount_dcache.c) plus the userspace ABI that drives it.  It is the
 * mount counterpart of susfs_kpm, which stays the security engine - the two
 * are separate KPM packages, loaded from separate autoload slots, versioned
 * and updated independently.  mountkpm/include/mount_kpm.h has the full
 * rationale, including why each engine has its own channel magic.
 *
 * USER-SPACE PROTOCOL
 *
 * Via ctl0 (KernelPatch's SUPERCALL_KPM_CONTROL) the argument is the same
 * NUL-terminated text protocol the rest of this project speaks:
 *
 *   "<CMD_HEX_UPPER>|<arg1>|<arg2>|..."
 *
 * but that route requires is_authed (APatch manager signature or superkey) and
 * a root shell is neither, so the channel userspace actually uses is a hook on
 * the kcmp syscall - see before_cmd_channel() below.  The command set is ours
 * alone: the dcache rule ABI (0x55565-0x5556a) and the two SHOW_* identity
 * codes, all in mountkpm/include/mount_kpm.h.  Anything else answers -ENOSYS,
 * which is what makes the engines distinguishable from userspace: a susfs
 * command sent to this engine fails, and vice versa.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/stddef.h>
/* spinlocks: the dcache rule table and the out_msg listing buffer each take
 * one (see mount_dc_emit and features/mount_dcache.c) */
#include <linux/spinlock.h>
#include <uapi/asm-generic/errno.h>
#include <kputils.h>
#include <log.h>
#include <syscall.h>
#include <linux/uaccess.h>

#include "include/mount_kpm.h"

KPM_NAME(MOUNT_KPM_NAME);
KPM_VERSION(MOUNT_KPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("susfs4ap");
KPM_DESCRIPTION("module mount engine for APatch via KPM (android15-6.6)");

/* ===== kfunc resolvers — definitions =====
 *
 * The storage behind mountkpm/include/mount_kpm.h.  Same approach as
 * susfs_kpm.c and for the same reason: KernelPatch's <linux/string.h> /
 * <linux/spinlock.h> inline wrappers call the extern kf_* pointers, which a
 * KPM cannot resolve (they are not in KernelPatch's KP_EXPORT_SYMBOL table),
 * so the bare kernel functions are looked up through kallsyms_lookup_name at
 * init and called through these pointers.
 *
 * The names are identical to susfs_kpm's on purpose (shared features/ source)
 * and collision-free because the build is -fvisibility=hidden: every one of
 * these is GLOBAL HIDDEN in the .kpm, i.e. module-local.
 */
void *(*susfs_memcpy)(void *, const void *, __kernel_size_t);
void *(*susfs_memset)(void *, int, __kernel_size_t);
int   (*susfs_strcmp)(const char *, const char *);
int   (*susfs_memcmp)(const void *, const void *, __kernel_size_t);
void *(*susfs_kzalloc_real)(size_t, gfp_t);
int   susfs_kzalloc_fallback = 0;
void  (*susfs_kfree)(const void *);
void  (*susfs__raw_spin_lock)(void *);
void  (*susfs__raw_spin_unlock)(void *);
int (*susfs_printk)(const char *fmt, ...);

/* kzalloc wrapper — kzalloc/kzalloc.cfi_jt/__kzalloc when available, otherwise
 * __kmalloc + memset.  Needed because on many GKI kernels "kzalloc" is not in
 * kallsyms (inlined or renamed). */
void *susfs_kzalloc(size_t size, gfp_t flags)
{
    if (susfs_kzalloc_real) {
        if (susfs_kzalloc_fallback && susfs_memset) {
            void *p = susfs_kzalloc_real(size, flags);
            if (p) susfs_memset(p, 0, size);
            return p;
        }
        return susfs_kzalloc_real(size, flags);
    }
    return NULL;
}

/* ===== version-tolerant symbol resolution — see susfs_kpm.c =====
 *
 * Kept byte-for-byte compatible with the security engine's implementation so
 * that a lookup that works there works here too (the kernels this project runs
 * on rename symbols through LTO/CFI cloning, and an exact-match-only lookup
 * would silently return NULL). */

extern unsigned long symbol_lookup_name(const char *name);
extern uint32_t kpver;

susfs_klns_t susfs_kallsyms_by_suffix;

static const char *const susfs_ksym_suffixes[] = {
    ".cfi_jt", ".cold", ".constprop.0", ".isra.0",
};
#define SUSFS_KSYM_SUFFIX_COUNT \
    (sizeof(susfs_ksym_suffixes) / sizeof(susfs_ksym_suffixes[0]))
#define SUSFS_KSYM_BUF 96

static unsigned long susfs_ksym_try_suffixes(const char *name)
{
    char buf[SUSFS_KSYM_BUF];
    unsigned int i, j;
    size_t n = 0;

    /* Plain byte loops: this runs before susfs_strcmp/susfs_memcpy are
     * resolved, and -fno-builtin keeps clang from turning them back into
     * memcpy() calls. */
    while (name[n]) {
        if (n + 1 >= SUSFS_KSYM_BUF) return 0;
        buf[n] = name[n];
        n++;
    }

    for (i = 0; i < SUSFS_KSYM_SUFFIX_COUNT; i++) {
        const char *sfx = susfs_ksym_suffixes[i];
        size_t k = n;

        for (j = 0; sfx[j]; j++) {
            if (k + 1 >= SUSFS_KSYM_BUF) break;
            buf[k++] = sfx[j];
        }
        if (sfx[j]) continue;
        buf[k] = '\0';
        if (kallsyms_lookup_name) {
            unsigned long addr = kallsyms_lookup_name(buf);
            if (addr) return addr;
        }
    }
    return 0;
}

unsigned long susfs_ksym(const char *name)
{
    unsigned long addr;

    if (!name || !*name) return 0;

    if (kallsyms_lookup_name) {
        addr = kallsyms_lookup_name(name);
        if (addr) return addr;
    }
    if (susfs_kallsyms_by_suffix) {
        addr = susfs_kallsyms_by_suffix(name);
        if (addr) return addr;
    }
    return susfs_ksym_try_suffixes(name);
}

void susfs_ksym_init(void)
{
    /* Imported, not probed (see susfs_kpm.c): the result is what may be NULL
     * when the running KernelPatch predates kallsyms_lookup_name_by_suffix. */
    unsigned long p = symbol_lookup_name("kallsyms_lookup_name_by_suffix");
    if (p) susfs_kallsyms_by_suffix = (susfs_klns_t)p;
}

/* ===== text-protocol helpers ===== */

static int hex_to_uint(const char *s, unsigned int *out) {
    unsigned int v = 0;
    if (!s || !*s) return -1;
    while (*s) {
        char c = *s;
        unsigned int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return -1;
        v = (v << 4) | d;
        s++;
    }
    *out = v;
    return 0;
}

/* Split ctl_args on '|' into argv-like array (in place). Returns argc. */
static int split_fields(char *buf, char **fields, int max_fields) {
    int n = 0;
    char *p = buf;
    if (n < max_fields) fields[n++] = p;
    while (*p) {
        if (*p == '|') {
            *p = '\0';
            if (n < max_fields) {
                fields[n++] = p + 1;
            } else {
                return -1;
            }
        }
        p++;
    }
    return n;
}

static long parse_long(const char *s, long def) {
    long v = 0;
    int neg = 0;
    if (!s || !*s) return def;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    if (*s != '\0') return def;
    return neg ? -v : v;
}

/* Copy a NUL-terminated string to the caller's reply buffer.  Used by the
 * identity commands, whose payloads are always short. */
static void mk_copy_out(char *__user out_msg, int outlen, const char *s)
{
    char tmp[SUSFS_MAX_VERSION_BUFSIZE > SUSFS_MAX_VARIANT_BUFSIZE
             ? SUSFS_MAX_VERSION_BUFSIZE : SUSFS_MAX_VARIANT_BUFSIZE];
    int len = 0;

    if (!out_msg || outlen <= 0 || !s) return;
    while (s[len] && len < (int)sizeof(tmp) - 1) {
        tmp[len] = s[len];
        len++;
    }
    tmp[len] = '\0';
    if (len > outlen - 1) len = outlen - 1;
    compat_copy_to_user(out_msg, tmp, len + 1);
}

/* ===== init / exit ===== */

static void mount_nop_spin_lock(void *lock) { (void)lock; }
static void mount_nop_spin_unlock(void *lock) { (void)lock; }

/* Set when the mandatory core symbols resolved; otherwise ctl0 answers -ENOSYS
 * so userspace sees a clean error instead of a NULL deref. */
static int mount_core_symbols_ok = 0;

static void before_cmd_channel(hook_fargs5_t *args, void *udata);

static long mount_kpm_init(const char *args, const char *event, void *reserved)
{
    int rc = 0;

    logki("mount_kpm: init, event=%s args=%s\n", event ? event : "(null)",
          args ? args : "(null)");

    /* Bind KernelPatch's kallsyms scan (when present) before resolving. */
    susfs_ksym_init();

    susfs_memcpy = (typeof(susfs_memcpy))susfs_ksym("memcpy");
    susfs_memset = (typeof(susfs_memset))susfs_ksym("memset");
    susfs_strcmp = (typeof(susfs_strcmp))susfs_ksym("strcmp");
    susfs_memcmp = (typeof(susfs_memcmp))susfs_ksym("memcmp");
    susfs_kzalloc_real = (typeof(susfs_kzalloc_real))susfs_ksym("kzalloc");
    susfs_kfree = (typeof(susfs_kfree))susfs_ksym("kfree");
    susfs__raw_spin_lock =
        (typeof(susfs__raw_spin_lock))susfs_ksym("_raw_spin_lock");
    susfs__raw_spin_unlock =
        (typeof(susfs__raw_spin_unlock))susfs_ksym("_raw_spin_unlock");

    /* CFI fallback: on CFI-enabled GKI kernels some functions only exist as
     * "<name>.cfi_jt". */
    if (!susfs_memcpy)
        susfs_memcpy = (typeof(susfs_memcpy))susfs_ksym("memcpy.cfi_jt");
    if (!susfs_memset)
        susfs_memset = (typeof(susfs_memset))susfs_ksym("memset.cfi_jt");
    if (!susfs_strcmp)
        susfs_strcmp = (typeof(susfs_strcmp))susfs_ksym("strcmp.cfi_jt");
    if (!susfs_memcmp)
        susfs_memcmp = (typeof(susfs_memcmp))susfs_ksym("memcmp.cfi_jt");
    if (!susfs_kfree)
        susfs_kfree = (typeof(susfs_kfree))susfs_ksym("kfree.cfi_jt");
    if (!susfs__raw_spin_lock)
        susfs__raw_spin_lock =
            (typeof(susfs__raw_spin_lock))susfs_ksym("_raw_spin_lock.cfi_jt");
    if (!susfs__raw_spin_unlock)
        susfs__raw_spin_unlock =
            (typeof(susfs__raw_spin_unlock))susfs_ksym("_raw_spin_unlock.cfi_jt");

    if (!susfs_kzalloc_real)
        susfs_kzalloc_real = (typeof(susfs_kzalloc_real))susfs_ksym("kzalloc.cfi_jt");
    if (!susfs_kzalloc_real)
        susfs_kzalloc_real = (typeof(susfs_kzalloc_real))susfs_ksym("__kzalloc");
    if (!susfs_kzalloc_real) {
        void *(*kmalloc_fn)(size_t, gfp_t) =
            (typeof(kmalloc_fn))susfs_ksym("__kmalloc");
        if (!kmalloc_fn)
            kmalloc_fn = (typeof(kmalloc_fn))susfs_ksym("__kmalloc.cfi_jt");
        if (kmalloc_fn && susfs_memset) {
            susfs_kzalloc_real = kmalloc_fn;
            susfs_kzalloc_fallback = 1;
            logkw("mount_kpm: kzalloc not found, using __kmalloc+memset fallback\n");
        }
    }
    if (!susfs_kfree)
        susfs_kfree = (typeof(susfs_kfree))susfs_ksym("__kfree");

    if (!susfs__raw_spin_lock) {
        logkw("mount_kpm: _raw_spin_lock not found, using no-op\n");
        susfs__raw_spin_lock = mount_nop_spin_lock;
    }
    if (!susfs__raw_spin_unlock) {
        logkw("mount_kpm: _raw_spin_unlock not found, using no-op\n");
        susfs__raw_spin_unlock = mount_nop_spin_unlock;
    }

    /* printk so userspace can detect the engine through dmesg - the supercall
     * route is closed to a root shell (see susfs_kpm.c for the full argument). */
    susfs_printk = (typeof(susfs_printk))susfs_ksym("printk");
    if (!susfs_printk)
        susfs_printk = (typeof(susfs_printk))susfs_ksym("printk.cfi_jt");
    if (!susfs_printk)
        susfs_printk = (typeof(susfs_printk))susfs_ksym("_printk");
    if (!susfs_printk)
        susfs_printk = (typeof(susfs_printk))susfs_ksym("_printk.cfi_jt");

    if (!susfs_memcpy || !susfs_memset || !susfs_strcmp || !susfs_memcmp ||
        !susfs_kzalloc_real || !susfs_kfree) {
        logke("mount_kpm: failed to resolve core kernel symbols "
              "(memcpy=%px memset=%px strcmp=%px memcmp=%px "
              "kzalloc_real=%px kfree=%px)\n",
              susfs_memcpy, susfs_memset, susfs_strcmp, susfs_memcmp,
              susfs_kzalloc_real, susfs_kfree);
        mount_core_symbols_ok = 0;
    } else {
        mount_core_symbols_ok = 1;
    }

    /* NEVER return non-zero: the KP loader treats an init() failure as a fatal
     * "KPM load failed", and a mount engine that cannot resolve its symbols
     * should still load and answer -ENOSYS per command (that is how userspace
     * tells "engine present but broken" from "engine absent"). */
    rc |= susfs_dc_init();
    if (rc)
        logke("mount_kpm: dcache engine init failed (rc=%d)\n", rc);

    logki("mount_kpm: init complete (core_symbols=%d)\n", mount_core_symbols_ok);

    /* Machine-parseable dmesg banner.  metamount.sh / the WebUI / a support
     * report read these key=value lines; they are why this engine can be
     * detected without any supercall. */
    if (susfs_printk) {
        susfs_printk("mount_kpm: version=%s variant=%s core_symbols=%d\n",
                     MOUNT_KPM_VERSION, MOUNT_KPM_VARIANT,
                     mount_core_symbols_ok);
        susfs_printk("mount_kpm: features=%s\n", MOUNT_KPM_ENABLED_FEATURES);
        susfs_printk("mount_kpm: caps=%s\n", SUSFS_DC_CAPS_STRING);
        susfs_printk("mount_kpm: ksym by_suffix=%d kpver=%u.%u.%u\n",
                     susfs_kallsyms_by_suffix ? 1 : 0,
                     (kpver >> 16) & 0xff, (kpver >> 8) & 0xff, kpver & 0xff);
    }

    /* The command channel.  hook_syscalln_override() is mandatory: only a slot
     * registered with allow_skip=1 may suppress the real syscall, and without
     * suppression the kernel still runs kcmp(pid1=<magic>,...) and returns
     * -ESRCH to userspace, making every command look failed (see the long note
     * in susfs_kpm.c - this exact bug is why the option exists). */
    {
        hook_err_t hook_rc =
            hook_syscalln_override(__NR_kcmp, 5, before_cmd_channel, 0, 0);
        if (hook_rc != HOOK_NO_ERR) {
            logke("mount_kpm: failed to hook __NR_kcmp (rc=%d)\n", hook_rc);
            if (susfs_printk)
                susfs_printk("mount_kpm: WARNING: cmd channel hook failed "
                             "(rc=%d)\n", hook_rc);
        } else {
            logki("mount_kpm: cmd channel hooked on __NR_kcmp (override mode)\n");
            if (susfs_printk)
                susfs_printk("mount_kpm: cmd_channel=enabled mode=override\n");
        }
    }

    if (susfs_printk)
        susfs_printk("mount_kpm: loaded\n");

    return 0;
}

static long mount_kpm_exit(void *reserved)
{
    logki("mount_kpm: exit, unhooking everything\n");
    unhook_syscalln(__NR_kcmp, before_cmd_channel, 0);
    /* Frees the rule store.  Slice 2+ also has to drop the dentries built from
     * those rules before the strings behind them go away; that teardown lives
     * behind susfs_dc_rule_clear() so this stays a single call. */
    susfs_dc_cleanup();
    return 0;
}

/* ===== ctl0: dispatch text-protocol commands ===== */

#define ARG(i) ((i) < argc ? fields[(i)] : "")

/* ===== out_msg plumbing =====
 *
 * The rule listing is the one response that cannot use a stack buffer: 16k
 * rules of "virtual=real\n" is around 1 MB, and a kernel stack is 16 KB, so
 * the text is formatted into a single static buffer and copied out under a
 * spinlock.  The lock is needed because the kcmp hook runs in the *caller's*
 * context, so two processes can be inside mount_kpm_ctl0 at the same time. */
#define MOUNT_DC_OUTBUFSIZE 65536
static char mount_dc_outbuf[MOUNT_DC_OUTBUFSIZE];
static DEFINE_SPINLOCK(mount_dc_outbuf_lock);

/* Formatting happens into the shared buffer, so the caller must hold the lock.
 * Returns whatever fn() returned (a count, or a negative errno) so userspace
 * can tell a complete listing from a truncated one. */
static long mount_dc_emit(int (*fn)(char *, int), char *__user out_msg,
                          int outlen)
{
    long rc;
    int len = 0;

    if (!out_msg || outlen <= 0) return -EINVAL;

    susfs__raw_spin_lock(&mount_dc_outbuf_lock);
    rc = fn(mount_dc_outbuf, MOUNT_DC_OUTBUFSIZE);
    while (mount_dc_outbuf[len] && len < MOUNT_DC_OUTBUFSIZE - 1) len++;
    if (len > 0) {
        if (len > outlen - 1) len = outlen - 1;
        compat_copy_to_user(out_msg, mount_dc_outbuf, len + 1);
    }
    susfs__raw_spin_unlock(&mount_dc_outbuf_lock);
    return rc;
}

static long mount_kpm_ctl0(const char *ctl_args, char *__user out_msg, int outlen)
{
    /* ctl_args is read-only — copy to a local mutable buffer.  2048 matches
     * the userspace kpm_send() buffer so messages are never truncated. */
    static char buf[2048];
    char *fields[8];
    int argc, n = 0;
    unsigned int cmd;

    if (!ctl_args || !*ctl_args) return -EINVAL;

    while (ctl_args[n] && n < (int)sizeof(buf) - 1) {
        buf[n] = ctl_args[n];
        n++;
    }
    buf[n] = '\0';

    argc = split_fields(buf, fields, 8);
    if (argc < 1) return -EINVAL;

    if (hex_to_uint(fields[0], &cmd) != 0) return -EINVAL;

    /* The identity commands touch no kernel memory, so they answer even when
     * the string/alloc symbols failed to resolve - that is what lets userspace
     * distinguish "engine loaded but crippled" from "engine not loaded". */
    if (!mount_core_symbols_ok &&
        cmd != CMD_SUSFS_SHOW_VERSION &&
        cmd != CMD_SUSFS_SHOW_VARIANT) {
        return -ENOSYS;
    }

    switch (cmd) {
    /* ===== identity ===== */
    case CMD_SUSFS_SHOW_VERSION:
        mk_copy_out(out_msg, outlen, MOUNT_KPM_VERSION);
        return 0;
    case CMD_SUSFS_SHOW_VARIANT:
        mk_copy_out(out_msg, outlen, MOUNT_KPM_VARIANT);
        return 0;

    /* ===== E7 dcache engine =====
     *
     * The whole rule set is rebuilt from userspace on every boot and on demand
     * (Action button), so clear-then-add is the normal sequence and both are
     * cheap: only the string copies happen per rule.  metamount.sh sends the
     * pairs itself with mctl, so nothing here walks the module set. */
    case CMD_SUSFS_KPM_DC_RULE_ADD:
        if (argc < 3) return -EINVAL;
        return susfs_dc_rule_add(ARG(1), ARG(2));
    case CMD_SUSFS_KPM_DC_RULE_CLEAR:
        return susfs_dc_rule_clear();
    case CMD_SUSFS_KPM_DC_RULE_COUNT:
        /* The count is the return value, so no out_msg is needed. */
        return susfs_dc_rule_count();
    case CMD_SUSFS_KPM_DC_RULE_LIST:
        return mount_dc_emit(susfs_dc_rule_list, out_msg, outlen);
    case CMD_SUSFS_KPM_DC_CAPS:
        return mount_dc_emit(susfs_dc_caps, out_msg, outlen);
    case CMD_SUSFS_KPM_DC_STATUS:
        return mount_dc_emit(susfs_dc_status, out_msg, outlen);
    default:
        /* Deliberately -ENOSYS, not -EINVAL: this engine does not implement
         * the susfs table at all, and "no such command" is exactly what
         * userspace should conclude when a security-engine command lands here
         * (or the other way round). */
        logke("mount_kpm: unknown cmd 0x%x\n", cmd);
        return -ENOSYS;
    }
}

KPM_INIT(mount_kpm_init);
KPM_CTL0(mount_kpm_ctl0);
KPM_EXIT(mount_kpm_exit);

/* ===== syscall command channel =====
 *
 * Same mechanism as susfs_kpm (see the long comment there): SUPERCALL_KPM_CONTROL
 * requires is_authed, which a root shell never has, so the channel is a hook on
 * __NR_kcmp (syscall 272 on arm64):
 *
 *   syscall(272, MOUNT_CMD_MAGIC, cmd_buf_ptr, out_buf_ptr, out_buf_len,
 *           rc_out_ptr)
 *
 * The before callback claims the call only when argument 0 is OUR magic, so a
 * command addressed to susfs_kpm (or any ordinary kcmp user) passes through
 * untouched - that is the whole point of the per-engine magic.  See
 * mountkpm/include/mount_kpm.h.
 *
 * rc_out_ptr is the opt-in 5th argument: it must already hold
 * MOUNT_RC_SENTINEL, which is how an old client passing four arguments cannot
 * have the kernel poke a stale register value into its address space.
 */

#define __NR_kcmp 272
#define MOUNT_CMD_MAGIC 0x53555346534D4E54ULL /* "SUSFSMNT" */

/* Largest plausible user-space address (arm64 48-bit VA). */
#define MOUNT_USER_ADDR_MAX (1UL << 48)

#define MOUNT_RC_SENTINEL 0x7fffffff

/* 1 only when *p holds MOUNT_RC_SENTINEL, i.e. the caller opted in. */
static int mount_rc_out_is_armed(int __user *p)
{
    int probe;
    long n;

    if (!p) return 0;
    if ((unsigned long)p >= MOUNT_USER_ADDR_MAX) return 0;
    if (((unsigned long)p & (sizeof(int) - 1)) != 0) return 0;
    /* compat_strncpy_from_user stops at NUL; the sentinel has no NUL byte, so
     * only a full 4-byte read means the value really is the sentinel. */
    n = compat_strncpy_from_user((char *)&probe, (const char __user *)p,
                                 sizeof(probe));
    if (n != (long)sizeof(probe)) return 0;
    return probe == MOUNT_RC_SENTINEL;
}

static void before_cmd_channel(hook_fargs5_t *args, void *udata)
{
    uint64_t magic = syscall_argn(args, 0);
    const char __user *cmd_buf;
    char __user *out_buf;
    int out_len, rc_out_ok;
    int __user *rc_out;
    char cmd[2048];
    int n;
    long rc;

    /* Not ours — pass through to the next hook / the real kcmp. */
    if (magic != MOUNT_CMD_MAGIC) return;

    /* On arm64 GKI has_syscall_wrapper=1 so arg0 is pt_regs*; syscall_argn()
     * unwraps it. */
    cmd_buf = (const char __user *)syscall_argn(args, 1);
    out_buf = (char __user *)syscall_argn(args, 2);
    out_len = (int)syscall_argn(args, 3);
    rc_out = (int __user *)syscall_argn(args, 4);
    rc_out_ok = mount_rc_out_is_armed(rc_out);

    n = compat_strncpy_from_user(cmd, cmd_buf, sizeof(cmd) - 1);
    if (n <= 0) {
        if (rc_out_ok) {
            int e = -EINVAL;
            compat_copy_to_user(rc_out, &e, sizeof(e));
        }
        args->skip_origin = 1;
        args->ret = (uint64_t)(long)-EINVAL;
        return;
    }
    cmd[n] = '\0';

    rc = mount_kpm_ctl0(cmd, out_buf, out_len);

    /* Publish the real rc where skip_origin cannot be relied upon. */
    if (rc_out_ok) {
        int rv = (int)rc;
        compat_copy_to_user(rc_out, &rv, sizeof(rv));
    }

    args->skip_origin = 1;
    args->ret = (uint64_t)(long)rc;
}