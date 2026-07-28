// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * flags - global KPM toggles: enable_log, enable_avc_log_spoofing.
 *
 * enable_log toggles susfs debug output (pure state).
 *
 * avc_log_spoofing: REAL implementation following AuditPatch-KPM
 * (https://github.com/brunoanc/AuditPatch-KPM).  We hook the kernel's
 * audit_log_format() function and, when the format string contains
 * "tcontext=%s" and the tcontext argument contains ":su:" or ":magisk:",
 * replace the tcontext pointer with a fake "u:r:priv_app:s0:c512,c768".
 * This makes AVC audit logs (visible in dmesg/logcat) show a benign
 * priv_app context instead of the root-manager's su context, defeating
 * detection via /proc/<pid> enumeration and AVC log scanning.
 *
 * The hook is installed at KPM init and always active; the before callback
 * checks avc_log_spoofing_enabled (a plain int read, atomic on arm64) and
 * returns immediately when the feature is off, so the runtime overhead is
 * negligible.  Toggling is instant — no hook install/uninstall needed.
 *
 * No struct audit_buffer internals are needed: audit_log_format takes
 * (ab, fmt, ...) and we only inspect fmt and the first vararg (the
 * tcontext string), rewriting the pointer in place.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <log.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <uapi/asm-generic/errno.h>

#include "../include/susfs_kpm.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

static int log_enabled = 0;
static int avc_log_spoofing_enabled = 0;
static DEFINE_SPINLOCK(flags_lock);

/* ===== AVC log spoofing hook ===== */

/* audit_log_format(struct audit_buffer *ab, const char *fmt, ...)
 * Resolved via kallsyms at init.  May be NULL on kernels that don't
 * export it (unlikely on GKI 6.6). */
static void *audit_log_format_addr;

/* Fake tcontext that replaces "u:r:su:s0" etc. in AVC logs.
 * Points to a string literal in .rodata — stable for the KPM lifetime. */
static const char *fake_tcontext = "u:r:priv_app:s0:c512,c768";

/* Local strchr/strstr — no dependency on kf_strchr/kf_strstr (which aren't
 * exported by KernelPatch).  These are tiny and self-contained. */
static const char *local_strchr(const char *s, char c)
{
    while (*s) {
        if (*s == c) return s;
        s++;
    }
    return 0;
}

static const char *local_strstr(const char *hay, const char *needle)
{
    if (!*needle) return hay;
    for (; *hay; hay++) {
        const char *h = hay;
        const char *n = needle;
        while (*h && *n && *h == *n) { h++; n++; }
        if (!*n) return hay;
    }
    return 0;
}

/* Hook callback for audit_log_format — runs before the real function.
 *
 * audit_log_format(ab, fmt, ...) is called by the audit subsystem to
 * format each field of an AVC message.  When the kernel logs a denied
 * permission it calls:
 *   audit_log_format(ab, "tcontext=%s", tcontext_string);
 * We intercept this: if fmt matches the "tcontext=%s" pattern and the
 * tcontext contains ":su:" or ":magisk:", we replace args->arg2 (the
 * tcontext pointer) with our fake priv_app string.
 *
 * arg0 = struct audit_buffer *ab  (opaque, passed through untouched)
 * arg1 = const char *fmt          (the format string)
 * arg2 = first vararg             (the tcontext string when fmt is "tcontext=%s")
 */
static void before_audit_log_format(hook_fargs3_t *args, void *udata)
{
    /* Fast path: feature disabled — one int read, then return.
     * No lock needed: int reads are atomic on aarch64; the worst case
     * of a race is one log line slipping through during toggle. */
    if (!avc_log_spoofing_enabled) return;

    const char *fmt = (const char *)args->arg1;
    if (!fmt) return;

    /* Check that fmt contains "tcontext=" and exactly one "%s" after it.
     * This matches the kernel's standard audit_log_format call for
     * tcontext.  We avoid false positives on other format strings by
     * requiring both "tcontext=" and a lone "%s". */
    const char *tc = local_strstr(fmt, "tcontext=");
    if (!tc) return;

    const char *percent = local_strchr(tc, '%');
    if (!percent || percent[1] != 's') return;

    /* Ensure there's no second format specifier (e.g. "tcontext=%s foo=%d")
     * — we only rewrite when %s is the sole conversion, matching the
     * kernel's "tcontext=%s" call exactly. */
    const char *rest = local_strchr(percent + 2, '%');
    if (rest) return;

    /* arg2 is the tcontext string passed as the first vararg. */
    const char *tcontext = (const char *)args->arg2;
    if (!tcontext) return;

    /* Only spoof if the tcontext actually contains a root-manager
     * context marker.  ":su:" matches "u:r:su:s0" etc.; ":magisk:"
     * matches "u:r:magisk:s0".  Other contexts (e.g. "u:r:untrusted_app")
     * pass through unchanged. */
    if (local_strstr(tcontext, ":su:") || local_strstr(tcontext, ":magisk:")) {
        args->arg2 = (uintptr_t)fake_tcontext;
    }

    (void)udata;
}

/* ===== flag state management ===== */

int susfs_set_log_enabled(int enabled)
{
    susfs__raw_spin_lock(&flags_lock);
    log_enabled = enabled ? 1 : 0;
    susfs__raw_spin_unlock(&flags_lock);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: enable_log=%d\n", log_enabled);
    }
    return 0;
}

int susfs_set_avc_log_spoofing(int enabled)
{
    susfs__raw_spin_lock(&flags_lock);
    avc_log_spoofing_enabled = enabled ? 1 : 0;
    susfs__raw_spin_unlock(&flags_lock);
    logki("susfs_kpm: avc_log_spoofing = %d\n", avc_log_spoofing_enabled);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: avc_log_spoofing=%d\n",
                     avc_log_spoofing_enabled);
    }
    return 0;
}

int susfs_get_log_enabled(void)
{
    int v;
    susfs__raw_spin_lock(&flags_lock);
    v = log_enabled;
    susfs__raw_spin_unlock(&flags_lock);
    return v;
}

int susfs_get_avc_log_spoofing(void)
{
    int v;
    susfs__raw_spin_lock(&flags_lock);
    v = avc_log_spoofing_enabled;
    susfs__raw_spin_unlock(&flags_lock);
    return v;
}

/* ===== hook lifecycle ===== */

int susfs_avc_log_spoofing_init_hooks(void)
{
    /* Resolve audit_log_format — the kernel function that formats each
     * field of an AVC audit message.  On GKI 6.6 it's exported via
     * kallsyms.  Try the bare name and the .cfi_jt CFI jump-table variant. */
    audit_log_format_addr =
        (void *)kallsyms_lookup_name("audit_log_format");
    if (!audit_log_format_addr)
        audit_log_format_addr =
            (void *)kallsyms_lookup_name("audit_log_format.cfi_jt");

    if (!audit_log_format_addr) {
        logke("susfs_kpm: audit_log_format not found, "
              "avc_log_spoofing will be inert\n");
        if (susfs_printk) {
            susfs_printk("susfs_kpm: avc_log_spoofing=unavailable "
                         "(audit_log_format not in kallsyms)\n");
        }
        return 0;  /* not fatal — toggle still works, just no-op */
    }

    hook_err_t (*wrap)(void *, int32_t, void *, void *, void *) = hook_wrap;
    HIDE_PTR(wrap);
    hook_err_t err = wrap(audit_log_format_addr, 3,
                          (void *)before_audit_log_format, 0, 0);
    if (err != HOOK_NO_ERR) {
        logke("susfs_kpm: hook audit_log_format failed: %d\n", err);
        if (susfs_printk) {
            susfs_printk("susfs_kpm: avc_log_spoofing=hook_failed(%d)\n",
                         err);
        }
        audit_log_format_addr = 0;
        return (int)err;
    }

    logki("susfs_kpm: hooked audit_log_format @ %px\n",
          audit_log_format_addr);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: avc_log_spoofing=hooked "
                     "(audit_log_format @ %px)\n",
                     audit_log_format_addr);
    }
    return 0;
}

void susfs_avc_log_spoofing_cleanup(void)
{
    if (audit_log_format_addr) {
        void (*un)(void *, void *, void *, int) = hook_unwrap_remove;
        HIDE_PTR(un);
        un(audit_log_format_addr, (void *)before_audit_log_format, 0, 1);
        audit_log_format_addr = 0;
    }
}
