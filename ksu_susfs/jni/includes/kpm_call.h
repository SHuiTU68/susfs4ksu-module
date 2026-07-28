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
 * The superkey is NOT stored in any file.  APatch app itself uses "su" as
 * its superKey (hardcoded in APatchApp.kt:271) because it runs as the
 * trusted-manager UID and gets is_authed automatically.  But ksu_susfs runs
 * in a root shell (uid 0) — NOT the trusted manager — so "su" doesn't work
 * for KPM_CONTROL.
 *
 * To obtain the real superkey we try, in order:
 *   1. kptools -l -i <boot_partition>  (APatch ships kptools at
 *      /data/adb/ap/bin/kptools; it prints "superkey=<plaintext>")
 *   2. Scan the active boot partition for the "KP1158" magic and read the
 *      superkey field at offset 0xE8 from the magic (preset layout from
 *      KernelPatch/kernel/include/preset.h).
 *   3. Read /proc/<apd_pid>/cmdline looking for -s/--superkey <KEY> — this
 *      only works during the brief boot window when the stage apd (post-fs-
 *      data / services / boot-completed) is still running; the persistent
 *      `apd uid-listener` does NOT carry the key.
 *   4. Fall back to "su" (works only when no superkey has been preset).
 *
 * Note: methods 1-2 only work when kpimg was patched with `-s <key>` (the
 * common APatch case).  If `-S <root_skey>` was used, the preset contains
 * only a SHA256 hash and the real key is generated randomly at boot — in
 * that case all three extraction methods fail and we fall back to "su".
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
#include <sys/stat.h>

/* Mirror of KernelPatch/kernel/patch/include/uapi/scdefs.h (subset) */
#define __NR_supercall          45
#define SUPERCALL_KPM_CONTROL   0x1022
#define SUPERCALL_KEY_MAX_LEN   0x40

/* Syscall command channel — the KPM hooks __NR_kcmp (272) to provide a
 * command path that bypasses the supercall is_authed gate.  This lets
 * ksu_susfs (running as root, uid 0) control the KPM without needing a
 * superkey or trusted-manager UID.  See kpm/susfs_kpm.c:before_cmd_channel.
 * MUST match the KPM-side definition. */
#define __NR_kcmp_channel       272
#define SUSFS_CMD_MAGIC         0x5355534653595343ULL /* "SUSFSYSC" */

/* KernelPatch version we target (must match the running kpimg). Bump if a
 * future KP release starts enforcing this field. */
#define KP_MAJOR 0
#define KP_MINOR 13
#define KP_PATCH 2

/* Module name registered by the KPM (must match KPM_NAME in susfs_kpm.c) */
#define SUSFS_KPM_NAME "susfs_kpm"

/* KP preset magic and superkey offset (see KernelPatch/kernel/include/preset.h).
 * superkey[64] sits at offset 0xE8 from the start of the "KP1158" magic. */
#define KP_MAGIC                "KP1158"
#define KP_MAGIC_LEN            8
#define KP_SUPERKEY_OFFSET      0xE8

static inline long _kpm_ver_and_cmd(long cmd)
{
    unsigned int version_code = (KP_MAJOR << 16) + (KP_MINOR << 8) + KP_PATCH;
    return ((long)version_code << 32) | (0x1158L << 16) | (cmd & 0xFFFF);
}

/* Try to extract the superkey from apd's process cmdline.
 * Only stage apd processes (post-fs-data/services/boot-completed) carry
 * -s <key>; the persistent uid-listener does not.  Returns 0 on success. */
static inline int _try_key_from_apd_cmdline(char *out, size_t outlen)
{
    FILE *fp = popen("pidof apd 2>/dev/null", "r");
    if (!fp) return -1;
    char pid_str[32];
    if (!fgets(pid_str, sizeof(pid_str), fp)) { pclose(fp); return -1; }
    pclose(fp);
    pid_str[strcspn(pid_str, " \n")] = '\0';
    if (!pid_str[0]) return -1;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    char *p = buf;
    char *end = buf + n;
    while (p < end) {
        size_t len = strnlen(p, (size_t)(end - p));
        if (len == 0) break;
        if ((strcmp(p, "--superkey") == 0 || strcmp(p, "-k") == 0 ||
             strcmp(p, "-s") == 0) && len + 1 < (size_t)(end - p)) {
            char *val = p + len + 1;
            if (val[0] && strcmp(val, "su") != 0) {
                strncpy(out, val, outlen - 1);
                out[outlen - 1] = '\0';
                return 0;
            }
        }
        p += len + 1;
    }
    return -1;
}

/* Try to extract the superkey by running kptools on the active boot slot.
 * kptools -l -i <image> prints "superkey=<plaintext>" to stdout. */
static inline int _try_key_from_kptools(char *out, size_t outlen)
{
    /* kptools is shipped by APatch at /data/adb/ap/bin/kptools */
    const char *kptools = "/data/adb/ap/bin/kptools";
    if (access(kptools, X_OK) != 0) return -1;

    /* Determine the active boot partition (A/B or legacy) */
    FILE *fp = popen(
        "slot=$(getprop ro.boot.slot_suffix 2>/dev/null); "
        "if [ -n \"$slot\" ]; then "
        "  p=/dev/block/by-name/boot$slot; "
        "else "
        "  p=/dev/block/by-name/boot; "
        "fi; "
        "[ -b \"$p\" ] && echo \"$p\"",
        "r");
    if (!fp) return -1;
    char part[128];
    if (!fgets(part, sizeof(part), fp)) { pclose(fp); return -1; }
    pclose(fp);
    part[strcspn(part, "\n")] = '\0';
    if (!part[0]) return -1;

    /* Run kptools and parse "superkey=<value>" */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s -l -i %s 2>/dev/null", kptools, part);
    fp = popen(cmd, "r");
    if (!fp) return -1;
    char line[512];
    int found = -1;
    while (fgets(line, sizeof(line), fp)) {
        const char *prefix = "superkey=";
        size_t plen = strlen(prefix);
        if (strncmp(line, prefix, plen) == 0) {
            char *val = line + plen;
            /* trim trailing whitespace */
            val[strcspn(val, "\r\n")] = '\0';
            if (val[0] && strcmp(val, "su") != 0) {
                strncpy(out, val, outlen - 1);
                out[outlen - 1] = '\0';
                found = 0;
                break;
            }
        }
    }
    pclose(fp);
    return found;
}

/* Try to extract the superkey by scanning the boot partition for the
 * "KP1158" magic and reading the superkey field at offset 0xE8. */
static inline int _try_key_from_boot_scan(char *out, size_t outlen)
{
    /* Determine the active boot partition */
    FILE *fp = popen(
        "slot=$(getprop ro.boot.slot_suffix 2>/dev/null); "
        "if [ -n \"$slot\" ]; then "
        "  p=/dev/block/by-name/boot$slot; "
        "else "
        "  p=/dev/block/by-name/boot; "
        "fi; "
        "[ -b \"$p\" ] && echo \"$p\"",
        "r");
    if (!fp) return -1;
    char part[128];
    if (!fgets(part, sizeof(part), fp)) { pclose(fp); return -1; }
    pclose(fp);
    part[strcspn(part, "\n")] = '\0';
    if (!part[0]) return -1;

    int fd = open(part, O_RDONLY);
    if (fd < 0) return -1;

    /* Scan in 1MB chunks with overlap for magic straddling boundaries.
     * The kernel image is typically 16-64MB; we cap at 128MB to avoid
     * scanning forever on huge images. */
    char chunk[1024 * 1024 + KP_MAGIC_LEN];
    off_t pos = 0;
    int found = -1;
    while (pos < 128L * 1024 * 1024) {
        ssize_t n = pread(fd, chunk, sizeof(chunk), pos);
        if (n <= 0) break;
        /* Search for KP_MAGIC in this chunk */
        void *hit = memmem(chunk, (size_t)n, KP_MAGIC, KP_MAGIC_LEN);
        if (hit) {
            /* Offset of magic within the file */
            off_t magic_off = pos + (off_t)((char *)hit - chunk);
            /* Read superkey at magic_off + KP_SUPERKEY_OFFSET */
            char key[SUPERCALL_KEY_MAX_LEN];
            ssize_t kr = pread(fd, key, sizeof(key) - 1,
                               magic_off + KP_SUPERKEY_OFFSET);
            if (kr > 0) {
                key[kr] = '\0';
                /* Ensure null-terminated (preset field is 64 bytes) */
                key[sizeof(key) - 1] = '\0';
                if (key[0] && strcmp(key, "su") != 0) {
                    strncpy(out, key, outlen - 1);
                    out[outlen - 1] = '\0';
                    found = 0;
                    break;
                }
            }
        }
        /* Advance, leaving overlap in case magic straddles boundary */
        pos += n - KP_MAGIC_LEN;
        if (pos < 0) pos = 0;
    }
    close(fd);
    return found;
}

/* Path to the superkey cache file.  Once the key is extracted (via kptools
 * or boot scan — both are slow), it's cached here so subsequent calls are
 * instant.  The file is root-readable only and lives in APatch's data dir. */
#define SUPERKEY_CACHE_PATH "/data/adb/ap/susfs4ksu/.superkey"

/* Auto-detect the superkey using multiple extraction strategies.
 *
 * Tries, in order:
 *   0. Cache file (instant — avoids re-running kptools/boot scan)
 *   1. kptools -l on the active boot partition
 *   2. Raw scan of the boot partition for KP_MAGIC + superkey offset
 *   3. apd cmdline (only works during early boot stages)
 *   4. Fallback to "su" (works only when no superkey has been preset)
 *
 * On successful extraction (strategies 1-3), the key is cached to
 * SUPERKEY_CACHE_PATH so subsequent calls skip the slow extraction.
 *
 * Returns a pointer to a static buffer containing the key. */
static inline const char *get_supercall_key(void)
{
    static char key_buf[SUPERCALL_KEY_MAX_LEN];
    static int initialized = 0;
    if (initialized) return key_buf;
    initialized = 1;

    /* Default fallback */
    strcpy(key_buf, "su");

    /* Strategy 0: read from cache file (instant) */
    int fd = open(SUPERKEY_CACHE_PATH, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, key_buf, sizeof(key_buf) - 1);
        close(fd);
        if (n > 0) {
            key_buf[n] = '\0';
            /* Trim trailing whitespace */
            key_buf[strcspn(key_buf, "\r\n")] = '\0';
            if (key_buf[0]) return key_buf;
        }
        /* Cache read failed or empty — fall through to extraction */
        strcpy(key_buf, "su");
    }

    /* Try extraction strategies; cache on success */
    const char *cache_val = NULL;

    /* Strategy 1: kptools (most reliable, but requires the binary) */
    if (_try_key_from_kptools(key_buf, sizeof(key_buf)) == 0) {
        cache_val = key_buf;
    } else {
        strcpy(key_buf, "su");
        /* Strategy 2: scan boot partition for KP magic */
        if (_try_key_from_boot_scan(key_buf, sizeof(key_buf)) == 0) {
            cache_val = key_buf;
        } else {
            strcpy(key_buf, "su");
            /* Strategy 3: apd cmdline (only works during boot stages) */
            if (_try_key_from_apd_cmdline(key_buf, sizeof(key_buf)) == 0) {
                cache_val = key_buf;
            }
        }
    }

    /* Cache the extracted key for next time (only if not "su" fallback) */
    if (cache_val && strcmp(cache_val, "su") != 0) {
        /* Ensure parent dir exists (best-effort) */
        mkdir("/data/adb/ap/susfs4ksu", 0755);
        fd = open(SUPERKEY_CACHE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            write(fd, cache_val, strlen(cache_val));
            close(fd);
        }
    }

    return key_buf;
}

/* Issue a KPM control command.
 *
 * PRIMARY path: syscall command channel (hook on __NR_kcmp).
 *   The KPM hooks __NR_kcmp (272) and checks for SUSFS_CMD_MAGIC in arg0.
 *   If it matches, the KPM reads the command string from arg1, dispatches
 *   it via susfs_ctl0(), writes any response to arg2, and short-circuits
 *   the original syscall.  This bypasses the supercall is_authed gate
 *   entirely — no superkey needed, works for root shell (uid 0).
 *
 * FALLBACK path: SUPERCALL_KPM_CONTROL.
 *   Used only if the syscall channel returns -ENOSYS (KPM not loaded or
 *   hook not installed).  Requires is_authed (superkey or trusted-manager
 *   UID), so it typically fails for root shell — but we try anyway for
 *   the case where a superkey WAS preset and get_supercall_key() found it.
 *
 * Returns the kernel-side return value (0 on success, negative errno on
 * failure).  out_msg / outlen may be 0 / 0 if no response is expected. */
static inline long kpm_control(const char *ctl_args,
                               char *out_msg, long outlen)
{
    if (!ctl_args || !*ctl_args) return -EINVAL;

    /* Primary: syscall command channel via __NR_kcmp hook */
    long rc = syscall(__NR_kcmp_channel, SUSFS_CMD_MAGIC,
                      ctl_args, out_msg, outlen);
    if (rc != -ENOSYS) return rc;

    /* Fallback: supercall (only works with is_authed) */
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
