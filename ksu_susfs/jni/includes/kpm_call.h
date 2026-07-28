/*
 * kpm_call.h - userspace bridge to susfs_kpm via APatch SuperCall.
 *
 * Replaces the upstream `syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC,
 * CMD_xxx, &info)` pattern with `sc_kpm_control(key, "susfs_kpm", ...)`.
 *
 * Text protocol on the wire:
 *   "<CMD_HEX_UPPER>|<arg1>|<arg2>|..."
 * The KPM parses this string and dispatches to feature handlers.
 *
 * Auth: SUPERCALL_KPM_CONTROL sits behind `if (!is_authed) return -EPERM;`
 * in KP's supercall dispatch.  is_authed is granted only by (a) a correct
 * superkey via auth_superkey(), or (b) being the trusted manager UID (APK
 * signature SHA256 match in userd.c).  ksu_susfs is a third-party binary —
 * it is NOT the trusted manager, so the ONLY way to get is_authed is to
 * pass the real superkey.  SU-allowed UIDs (including root) only get
 * is_trusted_caller, which is NOT enough for KPM_CONTROL.
 *
 * The superkey is not stored in any file — apd receives it via its
 * `--superkey`/`-k` command-line argument.  Since ksu_susfs runs as root,
 * it can read `/proc/<apd_pid>/cmdline` to extract the real superkey.
 * get_supercall_key() does exactly this, falling back to "su" (which works
 * only on KP configs where no superkey has been preset) if apd is not found.
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
#include <fcntl.h>

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

static inline long _kpm_ver_and_cmd(long cmd)
{
    unsigned int version_code = (KP_MAJOR << 16) + (KP_MINOR << 8) + KP_PATCH;
    return ((long)version_code << 32) | (0x1158L << 16) | (cmd & 0xFFFF);
}

/* Auto-detect the superkey from apd's process cmdline.
 *
 * apd is started by APatch's init scripts with `apd --superkey <KEY> ...`
 * (or `-k <KEY>`).  The superkey is not persisted to any file, but it IS
 * visible in /proc/<apd_pid>/cmdline as a null-separated argument list.
 * ksu_susfs runs as root, so it can read that file.
 *
 * Returns a pointer to a static buffer containing the key, or "su" as a
 * fallback (which only works when no superkey has been preset in KP). */
static inline const char *get_supercall_key(void)
{
    static char key_buf[SUPERCALL_KEY_MAX_LEN];
    static int initialized = 0;
    if (initialized) return key_buf;
    initialized = 1;

    /* Default fallback */
    strcpy(key_buf, "su");

    /* Get apd's PID via pidof (returns space-separated PIDs, take first) */
    FILE *fp = popen("pidof apd 2>/dev/null", "r");
    if (!fp) return key_buf;
    char pid_str[32];
    if (!fgets(pid_str, sizeof(pid_str), fp)) { pclose(fp); return key_buf; }
    pclose(fp);
    pid_str[strcspn(pid_str, " \n")] = '\0';
    if (!pid_str[0]) return key_buf;

    /* Read /proc/<pid>/cmdline — null-separated argv */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return key_buf;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return key_buf;
    buf[n] = '\0';

    /* Walk null-separated args looking for --superkey <KEY> or -k <KEY> */
    char *p = buf;
    char *end = buf + n;
    while (p < end) {
        size_t len = strnlen(p, (size_t)(end - p));
        if (len == 0) break;
        if (strcmp(p, "--superkey") == 0 || strcmp(p, "-k") == 0) {
            char *val = p + len + 1;
            if (val < end && val[0]) {
                strncpy(key_buf, val, sizeof(key_buf) - 1);
                key_buf[sizeof(key_buf) - 1] = '\0';
                break;
            }
        }
        p += len + 1;
    }

    return key_buf;
}

/* Issue sc_kpm_control(key, "susfs_kpm", ctl_args, out, outlen).
 * Returns the kernel-side return value (0 on success, negative errno on
 * failure).  out_msg / outlen may be 0 / 0 if no response is expected. */
static inline long kpm_control(const char *ctl_args,
                               char *out_msg, long outlen)
{
    if (!ctl_args || !*ctl_args) return -EINVAL;
    return syscall(__NR_supercall, get_supercall_key(),
                   _kpm_ver_and_cmd(SUPERCALL_KPM_CONTROL),
                   SUSFS_KPM_NAME, ctl_args, out_msg, outlen);
}

/* Build a text-protocol message from a printf-style format and send it.
 *
 * Example:
 *   kpm_send(0x55550, "%s", "/data/adb/ap");
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
 * subcommands).  Returns 0 on success, negative errno on failure.
 * Declared variadic (with a trailing `...`) so va_start() is well-formed;
 * callers that only need the response pass fmt=NULL and no extra args. */
static inline int kpm_send_recv(unsigned int cmd, const char *fmt,
                                char *out_msg, long outlen, ...)
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
