/*
 * kpm_call.h - userspace bridge to susfs_kpm via APatch SuperCall.
 *
 * Replaces the upstream `syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC,
 * CMD_xxx, &info)` pattern with `sc_kpm_control("su", "susfs_kpm", ...)`.
 *
 * Text protocol on the wire:
 *   "<CMD_HEX_UPPER>|<arg1>|<arg2>|..."
 * The KPM parses this string and dispatches to feature handlers.
 *
 * Auth: when ksu_susfs is invoked as root via APatch's su, it can pass "su"
 * as the superkey.  See KernelPatch/user/supercall.h:sc_kpm_control().
 *
 * Note on version_code: as of KernelPatch 0.13.x the kernel does NOT enforce
 * the version_code field (it's parsed but unused — see kernel/patch/common/
 * supercall.c before()).  We hardcode the version we target; if a future KP
 * release starts enforcing it, bump MAJOR/MINOR/PATCH here.
 */
#ifndef KPM_CALL_H
#define KPM_CALL_H

#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

/* Mirror of KernelPatch/kernel/patch/include/uapi/scdefs.h (subset) */
#define __NR_supercall          45
#define SUPERCALL_KPM_CONTROL   0x1022
#define SUPERCALL_KEY_MAX_LEN   0x40

/* KernelPatch version we target (must match the running kpimg). Bump if a
 * future KP release starts enforcing this field. */
#define KP_MAJOR 0
#define KP_MINOR 13
#define KP_PATCH 2

/* Module name registered by the KPM (must match KPM_NAME in susfs_kpm.c) */
#define SUSFS_KPM_NAME "susfs_kpm"

/* Auth key: "su" works if the caller's uid is in APatch's su allowlist,
 * which is the case when ksu_susfs is launched via `su -c`. */
#define SUSFS_KPM_KEY "su"

static inline long _kpm_ver_and_cmd(long cmd)
{
    unsigned int version_code = (KP_MAJOR << 16) + (KP_MINOR << 8) + KP_PATCH;
    return ((long)version_code << 32) | (0x1158L << 16) | (cmd & 0xFFFF);
}

/* Issue sc_kpm_control("su", "susfs_kpm", ctl_args, out, outlen).
 * Returns the kernel-side return value (0 on success, negative errno on
 * failure).  out_msg / outlen may be 0 / 0 if no response is expected. */
static inline long kpm_control(const char *ctl_args,
                               char *out_msg, long outlen)
{
    if (!ctl_args || !*ctl_args) return -EINVAL;
    return syscall(__NR_supercall, SUSFS_KPM_KEY,
                   _kpm_ver_and_cmd(SUPERCALL_KPM_CONTROL),
                   SUSFS_KPM_NAME, ctl_args, out_msg, outlen);
}

/* Build a text-protocol message from a printf-style format and send it.
 *
 * Example:
 *   kpm_send(0x55550, "%s", "/data/adb/ksu");
 *   kpm_send(0x555a0, "%d", 1);
 *   kpm_send(0x555e1, NULL);            // show version, no args
 *
 * The first field is always the cmd hex (uppercase, no 0x prefix); the
 * remaining fields are whatever the format produces, joined by '|'.  If
 * `fmt` is NULL or empty, only the cmd is sent.
 *
 * `out_msg` / `outlen` let the caller receive KPM output (used by `show`
 * subcommands); pass NULL/0 to ignore. */
static inline int kpm_send(unsigned int cmd, const char *fmt, ...)
{
    char buf[2048];
    int off = 0;

    /* cmd field */
    off = snprintf(buf, sizeof(buf), "%X", cmd);
    if (off < 0 || off >= (int)sizeof(buf)) return -EINVAL;

    /* optional args */
    if (fmt && *fmt) {
        if (off >= (int)sizeof(buf) - 2) return -ENAMETOOLONG;
        buf[off++] = '|';
        va_list ap;
        va_start(ap, fmt);
        int n = vsnprintf(buf + off, sizeof(buf) - off, fmt, ap);
        va_end(ap);
        if (n < 0) return -EINVAL;
        off += n;
        if (off >= (int)sizeof(buf)) return -ENAMETOOLONG;
    }

    return (int)kpm_control(buf, NULL, 0);
}

/* Variant that also retrieves a response string from the KPM (for `show`
 * subcommands).  Returns 0 on success, negative errno on failure. */
static inline int kpm_send_recv(unsigned int cmd, const char *fmt,
                                char *out_msg, long outlen)
{
    char buf[2048];
    int off = snprintf(buf, sizeof(buf), "%X", cmd);
    if (off < 0 || off >= (int)sizeof(buf)) return -EINVAL;
    if (fmt && *fmt) {
        if (off >= (int)sizeof(buf) - 2) return -ENAMETOOLONG;
        buf[off++] = '|';
        va_list ap;
        va_start(ap, fmt);
        int n = vsnprintf(buf + off, sizeof(buf) - off, fmt, ap);
        va_end(ap);
        if (n < 0) return -EINVAL;
        off += n;
        if (off >= (int)sizeof(buf)) return -ENAMETOOLONG;
    }
    return (int)kpm_control(buf, out_msg, outlen);
}

#endif /* KPM_CALL_H */
