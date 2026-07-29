// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * selinux_hook - hide Magisk-injected SELinux rules from apps.
 *
 * 6.6-only port of the Admirepowered/741afb7 selinux_hook KPM
 * (originally "selinux_MAF_fork" v1.1.3), merged as a susfs_kpm feature.
 *
 * Original author: Admire, 741afb7.
 *
 * The safe point for transaction queries is the selinuxfs write_op table,
 * where /sys/fs/selinux/access and /sys/fs/selinux/context still have the
 * original query text.  procattr writes are filtered at security_setprocattr().
 * Returning -EINVAL for Magisk contexts matches the clean-policy behavior
 * where the Magisk type/context does not exist.
 *
 * This port keeps only the android15-6.6 code paths.  All 4.9/4.14 compat,
 * legacy 5-arg AV, write_op[] hotpatch, status-freeze and dirtysepolicy
 * string-match paths have been removed (they are dead on 6.6).
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <kputils.h>
#include <syscall.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm/current.h>
#include <asm-generic/rwonce.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/fcntl.h>
#include <uapi/linux/fs.h>
#include <security.h>

#include "../include/susfs_kpm.h"

/*
 * Route all logging through susfs_printk (resolved by susfs_kpm.c via
 * kallsyms) instead of the bare pr_info/printk macro, so we never emit an
 * unresolved kf_printk / printk relocation and we honor the susfs_kpm
 * logging convention.  When susfs_printk is NULL the call is skipped.
 */
#undef pr_info
#undef pr_warn
#undef pr_err
#define pr_info(fmt, ...)  do { if (susfs_printk) susfs_printk(KERN_INFO  fmt, ##__VA_ARGS__); } while (0)
#define pr_warn(fmt, ...)  do { if (susfs_printk) susfs_printk(KERN_WARNING fmt, ##__VA_ARGS__); } while (0)
#define pr_err(fmt, ...)   do { if (susfs_printk) susfs_printk(KERN_ERR fmt, ##__VA_ARGS__); } while (0)

#define ACCESS_SAMPLE_MAX 256
#define ACCESS_PROBE_SLOTS 32
#define SELINUX_POLICYDB_FALLBACK_OFFSET sizeof(void *)
#define CLEAN_POLICYDB_ALLOC_SIZE 0x4000
#define contains_case_literal(s, len, lit) contains_case_lit((s), (len), (lit), sizeof(lit) - 1)

#define MAGISK_POLICY_PATH "/.magisk/selinux/load"
#define MAGISK_POLICY_REL_PATH ".magisk/selinux/load"
#define MAGISK_POLICY_MAX_SIZE (8 * 1024 * 1024)
#define CLEAN_EVAL_SCOPE_SLOTS 8
#define STATUS_READ_SCOPE_SLOTS 8
#define SELINUX_STATUS_SIZE 20
#define SELINUX_STATUS_CLEAN_SEQUENCE 4
#define SELINUX_STATUS_CLEAN_POLICYLOAD 1

#define selinux_hook_dbg(fmt, ...) pr_info(fmt, ##__VA_ARGS__)

typedef enum {
    SEL_HOOK_STATE_FULL_FALLBACK = 0,
    SEL_HOOK_STATE_PARTIAL_FALLBACK,
    SEL_HOOK_STATE_NORMAL_K
} sel_hook_state_t;

struct file;
struct policydb;
struct sidtab;

struct policy_file {
    char *data;
    size_t len;
};

/* Function pointers resolved at init through the symbol cache / kallsyms. */
static long (*copy_from_kernel_nofault_fn)(void *dst, const void *src, size_t size);
static long (*copy_to_user_nofault_fn)(void __user *dst, const void *src, size_t size);
static int (*security_read_policy_fn)(void **data, size_t *len);
static int (*security_load_policy_fn)(void *data, size_t len, struct selinux_load_state *load_state);
static int (*security_context_to_sid_fn)(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp);
static int (*policydb_read_fn)(struct policydb *policydb, struct policy_file *fp);
static void (*policydb_destroy_fn)(struct policydb *policydb);
static void (*selinux_policy_cancel_fn)(struct selinux_load_state *load_state);
static void (*sidtab_cancel_convert_fn)(struct sidtab *sidtab);
static struct file *(*filp_open_fn)(const char *filename, int flags, umode_t mode);
static int (*filp_close_fn)(struct file *filp, fl_owner_t id);
static ssize_t (*kernel_read_fn)(struct file *file, void *buf, size_t count, loff_t *pos);
static loff_t (*vfs_llseek_fn)(struct file *file, loff_t offset, int whence);

/* Track successfully hooked functions for clean unhook on exit.  6.6 installs
 * up to 13 hooks; 24 slots is ample headroom. */
static void *g_funcs[24];
static int g_hooks;

static bool g_selinux_ready;
static bool g_dirty_policy_seen;
static void *g_first_policydb;
static u32 g_clean_access_count;
static u32 g_policy_read_count;
static void *g_clean_policy_blob;
static size_t g_clean_policy_len;
static bool g_clean_policy_has_magisk;
static struct selinux_load_state g_clean_load_state;
static bool g_clean_load_state_ready;
static bool g_clean_policydb_direct;
static bool g_clean_sidtab_convert_canceled;
static void *g_clean_policydb;
static void *g_first_policy;
static size_t g_policydb_offset;
static u32 g_clean_eval_depth;
static u32 g_bypass_access_log_count;
static u32 g_bypass_context_log_count;

/* Cached vmalloc copy of g_clean_policy_blob shared by every reader.
 * Snapshot runs once at module init, so the source pointer is effectively
 * immutable.  Guarded by g_policy_cache_lock. */
static void *g_policy_read_cache;
static size_t g_policy_read_cache_len;
static void *g_policy_read_cache_src;
static raw_spinlock_t g_policy_cache_lock = { .raw_lock = ATOMIC_INIT(0) };
static u32 g_bypass_policy_log_count;
static u32 g_internal_policy_load_depth;
static u32 g_procattr_current_count;
static u32 g_setprocattr_probe_count;
static u32 g_selinux_setprocattr_probe_count;
static u32 g_status_read_count;
static u32 g_status_probe_count;
static u32 g_status_redirect_count;
static bool g_simple_read_from_buffer_hooked;
static bool g_policy_capture_in_progress;

struct access_probe {
    u32 id;
    uid_t uid;
    const char *node;
    char query[ACCESS_SAMPLE_MAX];
};

struct clean_eval_scope {
    void *task;
    u32 depth;
};

struct status_read_scope {
    void *task;
    u32 depth;
    u32 patched;
};

static struct access_probe g_probes[ACCESS_PROBE_SLOTS];
static struct clean_eval_scope g_clean_eval_scopes[CLEAN_EVAL_SCOPE_SLOTS];
static struct status_read_scope g_status_read_scopes[STATUS_READ_SCOPE_SLOTS];
static unsigned char g_clean_status_bytes[SELINUX_STATUS_SIZE];

/* Scope arrays are guarded by g_scopes_lock.  We use the susfs-resolved
 * _raw_spin_lock / _raw_spin_unlock helpers (always non-NULL: susfs_kpm.c
 * falls back to no-ops if the symbols are missing). */
static raw_spinlock_t g_scopes_lock = { .raw_lock = ATOMIC_INIT(0) };

/* ---- forward declarations ---- */
static bool contains_magisk(const char *s, size_t len);
static bool contains_case_lit(const char *s, size_t len, const char *lit, size_t lit_len);
static bool clean_context_exists(const char *query);
static bool legacy_clean_query_should_block(const char *query, size_t len, bool access_query);
static bool legacy_should_block_access_query(const char *query, size_t len);
static int clean_policy_context_to_sid(const char *query, u32 *out_sid);
static void refresh_clean_policydb(const char *reason, bool allow_fallback);
static const char *current_comm(void);
static bool current_is_policy_manager(void);
static bool should_log_live_bypass(uid_t uid);
static void log_bypass_once(const char *node, uid_t uid, const char *query);
static void cancel_clean_sidtab_convert(const char *reason);
static bool security_load_policy_has_load_state(void);
static void resolve_required_symbols_once(void);
static void *lookup_name_optional_suffix(const char *base);
static void log_symbol_addr(const char *name, const void *addr);
static void zero_bytes(void *dst, size_t len);
static int call_security_load_policy(void *data, size_t len, struct selinux_load_state *load_state);
static void call_selinux_policy_cancel(struct selinux_load_state *load_state);
static int call_security_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp);
static bool snapshot_magisk_policy_file(const char *reason, bool try_relative);
static bool finish_deferred_policy_capture(hook_fargs4_t *a, const char *stage, bool allow_fallback);
static void before_security_load_policy(hook_fargs4_t *a, void *u);
static void after_security_load_policy(hook_fargs4_t *a, void *u);
static void before_sel_read_handle_status(hook_fargs4_t *a, void *u);
static void after_sel_read_handle_status(hook_fargs4_t *a, void *u);
static void before_simple_read_from_buffer(hook_fargs5_t *a, void *u);
static void after_simple_read_from_buffer(hook_fargs5_t *a, void *u);
static bool enter_status_read_scope(void);
static void leave_status_read_scope(void);
static bool current_in_status_read_scope(void);
static void mark_status_read_scope_patched(void);
static bool current_status_read_scope_patched(void);
static bool enter_clean_eval_scope(void);
static void leave_clean_eval_scope(void);
static bool current_in_clean_eval_scope(void);
static int install_write_op_hooks(void);
static void uninstall_inline_hooks(void);
static void after_sel_mmap_handle_status(hook_fargs2_t *a, void *u);

/*
 * Patch the seqno field (5th whitespace-separated token, formatted as "%u")
 * in a /sys/fs/selinux/access response buffer to new_seqno.
 * Format: "%x %x %x %x %u %x"
 * Returns the new length (may differ if decimal widths differ).
 */
static ssize_t patch_response_seqno(char *buf, ssize_t ret, u32 new_seqno)
{
    char *p = buf;
    char *end = buf + ret;
    char *tok_start;
    char new_str[12];
    int ns_len;
    int tok;
    ssize_t diff;

    if (ret <= 0 || !buf)
        return ret;

    for (tok = 0; tok < 4; tok++) {
        while (p < end && *p == ' ') p++;
        while (p < end && *p != ' ') p++;
    }
    while (p < end && *p == ' ') p++;
    tok_start = p;
    while (p < end && *p != ' ' && *p != '\0' && *p != '\n') p++;

    if (tok_start >= p)
        return ret;

    {
        u32 v = new_seqno;
        int i = 0;
        char tmp[12];
        if (v == 0) {
            new_str[0] = '0';
            ns_len = 1;
        } else {
            while (v > 0) { tmp[i++] = '0' + (v % 10); v /= 10; }
            for (ns_len = 0; ns_len < i; ns_len++)
                new_str[ns_len] = tmp[i - 1 - ns_len];
        }
    }

    diff = (ssize_t)ns_len - (ssize_t)(p - tok_start);
    if (diff != 0) {
        char *dst = tok_start + ns_len;
        char *src = p;
        size_t move = (size_t)(end - src);
        int j;
        if (diff < 0) {
            for (j = 0; j < (int)move; j++) dst[j] = src[j];
        } else {
            for (j = (int)move - 1; j >= 0; j--) dst[j] = src[j];
        }
        ret += diff;
    }

    {
        int k;
        for (k = 0; k < ns_len; k++)
            tok_start[k] = new_str[k];
    }
    return ret;
}

static void copy_bytes(void *dst, const void *src, size_t len)
{
    size_t i;
    char *d = (char *)dst;
    const char *s = (const char *)src;

    if (!d || !s)
        return;

    for (i = 0; i < len; i++)
        d[i] = s[i];
}

static void zero_bytes(void *dst, size_t len)
{
    size_t i;
    volatile char *d = (volatile char *)dst;

    if (!d)
        return;

    for (i = 0; i < len; i++)
        d[i] = 0;
}

static int copy_status_to_user(void __user *dst, const void *src, size_t len)
{
    int copied;

    if (copy_to_user_nofault_fn)
        return copy_to_user_nofault_fn(dst, src, len) ? -EFAULT : 0;

    copied = compat_copy_to_user(dst, src, (int)len);
    return copied == (int)len ? 0 : -EFAULT;
}

static void put_u32_le(unsigned char *dst, u32 value)
{
    if (!dst)
        return;

    dst[0] = (unsigned char)(value & 0xff);
    dst[1] = (unsigned char)((value >> 8) & 0xff);
    dst[2] = (unsigned char)((value >> 16) & 0xff);
    dst[3] = (unsigned char)((value >> 24) & 0xff);
}

static u32 get_u32_le(const unsigned char *src)
{
    if (!src)
        return 0;

    return (u32)src[0] |
           ((u32)src[1] << 8) |
           ((u32)src[2] << 16) |
           ((u32)src[3] << 24);
}

static void fill_clean_status_bytes(unsigned char *status)
{
    u32 seq, pload;

    if (!status)
        return;

    /* kernel >= 6.7: detection expects sequence=4 policyload=1
     * kernel <  6.7: detection expects sequence=0 policyload=0
     * (android15-6.6 is < 6.7, so the clean values are 0/0 here.) */
    if (kver >= VERSION(6, 7, 0)) {
        seq   = SELINUX_STATUS_CLEAN_SEQUENCE;
        pload = SELINUX_STATUS_CLEAN_POLICYLOAD;
    } else {
        seq   = 0;
        pload = 0;
    }

    zero_bytes(status, SELINUX_STATUS_SIZE);
    put_u32_le(status + 0,  1);
    put_u32_le(status + 4,  seq);
    put_u32_le(status + 8,  1);    /* enforcing — always 1 */
    put_u32_le(status + 12, pload);
    put_u32_le(status + 16, 1);
}

static bool buffer_contains_magisk(const char *buf, size_t len)
{
    return contains_magisk(buf, len);
}

static bool ascii_lower_eq(char a, char b)
{
    if (a >= 'A' && a <= 'Z')
        a = a - 'A' + 'a';
    if (b >= 'A' && b <= 'Z')
        b = b - 'A' + 'a';
    return a == b;
}

static bool str_eq_lit(const char *s, const char *lit)
{
    size_t i;

    if (!s || !lit)
        return false;

    for (i = 0; lit[i]; i++) {
        if (s[i] != lit[i])
            return false;
    }

    return s[i] == '\0';
}

static const char *current_comm(void)
{
    if (task_struct_offset.comm_offset <= 0)
        return "?";

    return get_task_comm(current) ?: "?";
}

static bool should_bypass_clean_filter(uid_t uid)
{
    if (uid < 10000)
        return true;

    return false;
}

static bool should_log_live_bypass(uid_t uid)
{
    return uid >= 10000;
}

static bool security_load_policy_has_load_state(void)
{
    /* 6.6 security_load_policy() uses the staged load_state/cancel helpers;
     * the presence of selinux_policy_cancel is the runtime signal. */
    return selinux_policy_cancel_fn != NULL;
}

static bool current_is_policy_manager(void)
{
    /* Reserved hook for future policy-manager bypass; currently unused. */
    return false;
}

static u32 *bypass_counter_for_node(const char *node)
{
    if (str_eq_lit(node, "access"))
        return &g_bypass_access_log_count;
    if (str_eq_lit(node, "context"))
        return &g_bypass_context_log_count;
    return &g_bypass_policy_log_count;
}

static void log_bypass_once(const char *node, uid_t uid, const char *query)
{
    u32 *counter = bypass_counter_for_node(node);
    u32 n = READ_ONCE(*counter);

    n++;
    WRITE_ONCE(*counter, n);

    if (query)
        selinux_hook_dbg("[selinux_hook] LIVE bypass /sys/fs/selinux/%s #%u uid=%d comm=%s query=\"%s\"\n",
                         node ?: "?", n, uid, current_comm(), query);
    else
        selinux_hook_dbg("[selinux_hook] LIVE bypass /sys/fs/selinux/%s #%u uid=%d comm=%s\n",
                         node ?: "?", n, uid, current_comm());
}

/* ===== symbol cache (one-pass kallsyms_on_each_symbol resolution) ===== */

struct symbol_cache_entry {
    const char *base;
    size_t len;
    unsigned long addr;
    bool exact;
    bool suffixed;
};

/* android15-6.6's kallsyms_on_each_symbol() invokes the callback with the
 * 4-argument signature  int (*)(void *, const char *, struct module *,
 * unsigned long)  — the "nomod" 3-arg variant only landed in 6.7.  KP's
 * <kallsyms.h> declares the pointer with this 4-arg callback type, so we
 * match it exactly (no cast) to avoid receiving the module pointer where
 * the address is expected. */
#define SYMBOL_CACHE_ENTRY(name) { name, 0, 0, false, false }

static struct symbol_cache_entry g_symbol_cache[] = {
    SYMBOL_CACHE_ENTRY("copy_from_kernel_nofault"),
    SYMBOL_CACHE_ENTRY("copy_to_user_nofault"),
    SYMBOL_CACHE_ENTRY("filp_open"),
    SYMBOL_CACHE_ENTRY("filp_close"),
    SYMBOL_CACHE_ENTRY("kernel_read"),
    SYMBOL_CACHE_ENTRY("vfs_llseek"),
    SYMBOL_CACHE_ENTRY("security_load_policy"),
    SYMBOL_CACHE_ENTRY("security_context_to_sid"),
    SYMBOL_CACHE_ENTRY("policydb_read"),
    SYMBOL_CACHE_ENTRY("policydb_destroy"),
    SYMBOL_CACHE_ENTRY("selinux_policy_cancel"),
    SYMBOL_CACHE_ENTRY("sidtab_cancel_convert"),
    SYMBOL_CACHE_ENTRY("security_read_policy"),
    SYMBOL_CACHE_ENTRY("simple_read_from_buffer"),
    SYMBOL_CACHE_ENTRY("sel_read_handle_status"),
    SYMBOL_CACHE_ENTRY("sel_mmap_handle_status"),
    SYMBOL_CACHE_ENTRY("security_setprocattr"),
    SYMBOL_CACHE_ENTRY("selinux_setprocattr"),
    SYMBOL_CACHE_ENTRY("sel_write_access"),
    SYMBOL_CACHE_ENTRY("sel_write_context"),
    SYMBOL_CACHE_ENTRY("context_struct_compute_av"),
    SYMBOL_CACHE_ENTRY("string_to_context_struct"),
    SYMBOL_CACHE_ENTRY("selinux_complete_init"),
    SYMBOL_CACHE_ENTRY("selinux_policy_commit"),
};

#define SYMBOL_CACHE_COUNT (sizeof(g_symbol_cache) / sizeof(g_symbol_cache[0]))

static bool g_symbol_cache_resolved;

static size_t str_len_safe(const char *s)
{
    const volatile char *p;
    size_t len = 0;

    if (!s)
        return 0;

    /* Explicit byte walk so clang/gcc does not fold this into an out-of-line
     * strlen() libcall, which is unavailable in the KPM loader. */
    p = (const volatile char *)s;
    while (p[len])
        len++;
    return len;
}

static bool suffix_contains_cfi(const char *suffix)
{
    size_t i;

    if (!suffix)
        return false;

    for (i = 0; suffix[i]; i++) {
        if (suffix[i] == 'c' && suffix[i + 1] == 'f' && suffix[i + 2] == 'i' &&
            (i == 0 || suffix[i - 1] == '.' || suffix[i - 1] == '$') &&
            (!suffix[i + 3] || suffix[i + 3] == '.' || suffix[i + 3] == '$'))
            return true;
    }
    return false;
}

static bool symbol_name_matches(const char *name, const char *base, size_t len)
{
    size_t i;

    if (!name || !base)
        return false;

    for (i = 0; i < len; i++) {
        if (name[i] != base[i])
            return false;
    }

    return name[len] == '\0';
}

static bool symbol_has_compiler_suffix(const char *name, const char *base, size_t len)
{
    size_t i;

    if (!name || !base || !len)
        return false;

    for (i = 0; i < len; i++) {
        if (name[i] != base[i])
            return false;
    }

    if (!(name[len] == '.' || name[len] == '$') || !name[len + 1])
        return false;

    /* Skip CFI stub variants; they redirect to the real function */
    if (suffix_contains_cfi(name + len + 1))
        return false;

    return true;
}

static void prepare_symbol_cache(void)
{
    size_t i;

    for (i = 0; i < SYMBOL_CACHE_COUNT; i++)
        g_symbol_cache[i].len = str_len_safe(g_symbol_cache[i].base);
}

static void cache_symbol_match(const char *name, unsigned long addr)
{
    size_t i;

    if (!name || !addr)
        return;

    for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
        struct symbol_cache_entry *entry = &g_symbol_cache[i];

        if (!entry->base || !entry->len || entry->exact)
            continue;

        if (symbol_name_matches(name, entry->base, entry->len)) {
            entry->addr = addr;
            entry->exact = true;
            entry->suffixed = false;
            continue;
        }

        if (!entry->addr &&
            symbol_has_compiler_suffix(name, entry->base, entry->len)) {
            entry->addr = addr;
            entry->suffixed = true;
        }
    }
}

static int cache_symbol_cb(void *data, const char *name,
                           struct module *module, unsigned long addr)
{
    (void)data;
    (void)module;

    cache_symbol_match(name, addr);
    return 0;
}

static void resolve_required_symbols_once(void)
{
    size_t i;
    u32 found = 0;
    u32 suffixed = 0;

    if (READ_ONCE(g_symbol_cache_resolved))
        return;

    prepare_symbol_cache();

    /* android15-6.6 uses the 4-arg kallsyms_on_each_symbol callback
     * (with struct module *).  The 3-arg "nomod" variant is 6.7+ only.
     * If the pointer is unavailable, fall back to per-symbol
     * kallsyms_lookup_name. */
    if (!kallsyms_on_each_symbol) {
        pr_warn("[selinux_hook] kallsyms_on_each_symbol missing; falling back to exact symbol lookups only\n");
        for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
            unsigned long addr = (unsigned long)kallsyms_lookup_name(g_symbol_cache[i].base);
            if (addr) {
                g_symbol_cache[i].addr = addr;
                g_symbol_cache[i].exact = true;
            }
        }
    } else {
        kallsyms_on_each_symbol(cache_symbol_cb, NULL);
    }

    for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
        if (g_symbol_cache[i].addr) {
            found++;
            if (g_symbol_cache[i].suffixed)
                suffixed++;
        }
    }

    if (found == 0 && kallsyms_on_each_symbol) {
        pr_warn("[selinux_hook] kallsyms_on_each_symbol returned no symbols, falling back to kallsyms_lookup_name\n");
        for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
            unsigned long addr = (unsigned long)kallsyms_lookup_name(g_symbol_cache[i].base);
            if (addr) {
                g_symbol_cache[i].addr = addr;
                g_symbol_cache[i].exact = true;
            }
        }
    }

    WRITE_ONCE(g_symbol_cache_resolved, true);
    pr_info("[selinux_hook] symbol cache resolved: found=%u suffixed=%u\n",
            found, suffixed);
}

static struct symbol_cache_entry *find_cached_symbol(const char *base)
{
    size_t i;

    if (!base)
        return NULL;

    for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
        if (str_eq_lit(base, g_symbol_cache[i].base))
            return &g_symbol_cache[i];
    }

    return NULL;
}

static void *lookup_name_optional_suffix(const char *base)
{
    struct symbol_cache_entry *entry;
    unsigned long addr;

    if (!base)
        return NULL;

    resolve_required_symbols_once();

    entry = find_cached_symbol(base);
    if (entry && entry->addr)
        return (void *)entry->addr;

    addr = (unsigned long)kallsyms_lookup_name(base);
    if (addr) {
        if (entry) {
            entry->addr = addr;
            entry->exact = true;
            entry->suffixed = false;
        }
        return (void *)addr;
    }

    return NULL;
}

/*
 * Some LTO kernels expose context_struct_compute_av only as a numbered local
 * symbol (for example context_struct_compute_av.72).  Keep this expensive
 * fallback out of the generic lookup path.
 */
static void *lookup_name_numbered_suffix(const char *base)
{
    struct symbol_cache_entry *entry;
    unsigned long addr;
    char name[64];
    volatile char *name_bytes = (volatile char *)name;
    const volatile char *base_bytes = (const volatile char *)base;
    size_t base_len;
    size_t i;
    size_t pos;
    u32 n;

    if (!base)
        return NULL;

    base_len = str_len_safe(base);
    if (!base_len || base_len + 5 > sizeof(name))
        return NULL;

    for (i = 0; i < base_len; i++)
        name_bytes[i] = base_bytes[i];

    for (n = 0; n < 256; n++) {
        pos = base_len;
        name[pos++] = '.';
        if (n >= 100)
            name[pos++] = '0' + (n / 100) % 10;
        if (n >= 10)
            name[pos++] = '0' + (n / 10) % 10;
        name[pos++] = '0' + n % 10;
        name[pos] = '\0';

        addr = (unsigned long)kallsyms_lookup_name(name);
        if (addr) {
            entry = find_cached_symbol(base);
            if (entry) {
                entry->addr = addr;
                entry->exact = false;
                entry->suffixed = true;
            }
            pr_info("[selinux_hook] resolved %s as %s addr=%px\n",
                    base, name, (void *)addr);
            return (void *)addr;
        }
    }

    return NULL;
}

static void log_symbol_addr(const char *name, const void *addr)
{
    pr_info("[selinux_hook] symbol %-36s %s addr=%px\n",
            name ?: "(null)", addr ? "found" : "missing", addr);
}

static int call_security_load_policy(void *data, size_t len, struct selinux_load_state *load_state)
{
    if (!security_load_policy_has_load_state())
        return -EOPNOTSUPP;
    if (security_load_policy_fn)
        return security_load_policy_fn(data, len, load_state);
    return -ENOENT;
}

static void call_selinux_policy_cancel(struct selinux_load_state *load_state)
{
    if (selinux_policy_cancel_fn)
        selinux_policy_cancel_fn(load_state);
}

static int call_security_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp)
{
    if (security_context_to_sid_fn)
        return security_context_to_sid_fn(scontext, scontext_len, out_sid, gfp);
    return -ENOENT;
}

static void *read_load_state_policy(void *load_state)
{
    void *policy = NULL;

    if (!load_state)
        return NULL;

    if (copy_from_kernel_nofault_fn &&
        copy_from_kernel_nofault_fn(&policy, load_state, sizeof(policy)) == 0)
        return policy;

    return *(void **)load_state;
}

static struct sidtab *read_policy_sidtab(void *policy)
{
    struct sidtab *sidtab = NULL;

    if (!policy)
        return NULL;

    if (copy_from_kernel_nofault_fn &&
        copy_from_kernel_nofault_fn(&sidtab, policy, sizeof(sidtab)) == 0)
        return sidtab;

    return *(struct sidtab **)policy;
}

static void cancel_clean_sidtab_convert(const char *reason)
{
    void *policy;
    struct sidtab *sidtab;

    if (!READ_ONCE(g_clean_load_state_ready))
        return;
    if (READ_ONCE(g_clean_sidtab_convert_canceled))
        return;

    policy = READ_ONCE(g_first_policy);
    if (!policy)
        return;

    if (!sidtab_cancel_convert_fn) {
        pr_warn("[selinux_hook] CLEAN cannot cancel live sidtab convert reason=%s: missing sidtab_cancel_convert\n",
                reason ?: "(null)");
        return;
    }

    sidtab = read_policy_sidtab(policy);
    if (!sidtab) {
        pr_warn("[selinux_hook] CLEAN cannot cancel live sidtab convert reason=%s policy=%px sidtab=NULL\n",
                reason ?: "(null)", policy);
        return;
    }

    sidtab_cancel_convert_fn(sidtab);
    WRITE_ONCE(g_clean_sidtab_convert_canceled, true);
    selinux_hook_dbg("[selinux_hook] CLEAN canceled live sidtab convert reason=%s policy=%px sidtab=%px clean_policy=%px\n",
                     reason ?: "(null)", policy, sidtab, g_clean_load_state.policy);
}

static bool snapshot_policy_file_path(const char *path, const char *source,
                                      const char *reason)
{
    struct file *filp;
    void *data;
    loff_t len;
    loff_t pos;
    ssize_t nread;

    if (!susfs_vmalloc)
        return false;
    if (!filp_open_fn || !filp_close_fn || !kernel_read_fn || !vfs_llseek_fn) {
        pr_warn("[selinux_hook] CLEAN Magisk policy file read disabled reason=%s open=%px close=%px read=%px llseek=%px\n",
                reason ?: "(null)", filp_open_fn, filp_close_fn,
                kernel_read_fn, vfs_llseek_fn);
        return false;
    }

    filp = filp_open_fn(path, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
        pr_warn("[selinux_hook] CLEAN Magisk policy open failed reason=%s source=%s path=%s rc=%ld\n",
                reason ?: "(null)", source ?: "unknown", path,
                filp ? PTR_ERR(filp) : -ENOENT);
        return false;
    }

    len = vfs_llseek_fn(filp, 0, SEEK_END);
    if (len <= 0 || len > MAGISK_POLICY_MAX_SIZE) {
        pr_warn("[selinux_hook] CLEAN Magisk policy bad len reason=%s source=%s path=%s len=%lld\n",
                reason ?: "(null)", source ?: "unknown", path, len);
        filp_close_fn(filp, 0);
        return false;
    }
    vfs_llseek_fn(filp, 0, SEEK_SET);

    data = susfs_vmalloc((unsigned long)len);
    if (!data) {
        pr_warn("[selinux_hook] CLEAN Magisk policy alloc failed reason=%s source=%s len=%lld\n",
                reason ?: "(null)", source ?: "unknown", len);
        filp_close_fn(filp, 0);
        return false;
    }

    pos = 0;
    nread = kernel_read_fn(filp, data, (size_t)len, &pos);
    filp_close_fn(filp, 0);
    if (nread != len || pos != len) {
        pr_warn("[selinux_hook] CLEAN Magisk policy read failed reason=%s source=%s read=%ld pos=%lld len=%lld\n",
                reason ?: "(null)", source ?: "unknown", (long)nread, pos, len);
        susfs_vfree(data);
        return false;
    }

    WRITE_ONCE(g_clean_policy_has_magisk, buffer_contains_magisk(data, (size_t)len));
    WRITE_ONCE(g_clean_policy_len, (size_t)len);
    WRITE_ONCE(g_clean_policy_blob, data);
    pr_info("[selinux_hook] CLEAN Magisk policy snapshot saved reason=%s source=%s path=%s blob=%px len=%zu has_magisk=%d\n",
            reason ?: "(null)", source ?: "unknown", path, data,
            READ_ONCE(g_clean_policy_len), READ_ONCE(g_clean_policy_has_magisk));
    return true;
}

static bool snapshot_magisk_policy_file(const char *reason, bool try_relative)
{
    if (snapshot_policy_file_path(MAGISK_POLICY_PATH, "magisk_file_abs", reason))
        return true;
    if (try_relative &&
        snapshot_policy_file_path(MAGISK_POLICY_REL_PATH, "magisk_file_rel", reason))
        return true;
    return false;
}

static void refresh_policydb_offset(const char *reason, bool allow_fallback)
{
    void *policy = READ_ONCE(g_first_policy);
    void *policydb = READ_ONCE(g_first_policydb);
    unsigned long diff;

    if (READ_ONCE(g_policydb_offset))
        return;

    if (policy && policydb && policydb > policy) {
        diff = (unsigned long)policydb - (unsigned long)policy;
        if (diff < 0x100000) {
            WRITE_ONCE(g_policydb_offset, (size_t)diff);
            selinux_hook_dbg("[selinux_hook] policydb offset learned reason=%s policy=%px policydb=%px off=%zu\n",
                             reason ?: "(null)", policy, policydb,
                             READ_ONCE(g_policydb_offset));
            return;
        }
    }

    if (!allow_fallback)
        return;

    /* On 6.6 the sizeof(void*) fallback is always acceptable (non-legacy
     * kernel). */
    WRITE_ONCE(g_policydb_offset, (size_t)SELINUX_POLICYDB_FALLBACK_OFFSET);
    selinux_hook_dbg("[selinux_hook] policydb offset fallback reason=%s policy=%px policydb=%px off=%zu\n",
                     reason ?: "(null)", policy, policydb, READ_ONCE(g_policydb_offset));
}

static void refresh_clean_policydb(const char *reason, bool allow_fallback)
{
    void *policy;
    size_t off;

    /* On 6.6 clean_policydb_redirect_supported() is always true. */
    if (READ_ONCE(g_clean_policydb_direct))
        return;

    if (!READ_ONCE(g_clean_load_state_ready) || !g_clean_load_state.policy)
        return;

    refresh_policydb_offset(reason, allow_fallback);
    off = READ_ONCE(g_policydb_offset);
    if (!off)
        return;

    policy = g_clean_load_state.policy;
    WRITE_ONCE(g_clean_policydb, (void *)((char *)policy + off));
}

static void try_load_clean_policydb_from_blob(const char *reason)
{
    struct policy_file fp;
    struct policydb *policydb;
    void *blob = READ_ONCE(g_clean_policy_blob);
    size_t len = READ_ONCE(g_clean_policy_len);
    int rc;

    if (READ_ONCE(g_clean_policydb))
        return;
    if (!blob || !len)
        return;
    if (!policydb_read_fn || !policydb_destroy_fn || !susfs_vmalloc)
        return;

    policydb = (struct policydb *)susfs_vmalloc(CLEAN_POLICYDB_ALLOC_SIZE);
    if (!policydb) {
        pr_warn("[selinux_hook] CLEAN policydb_read alloc failed reason=%s size=%u\n",
                reason ?: "(null)", CLEAN_POLICYDB_ALLOC_SIZE);
        return;
    }
    zero_bytes(policydb, CLEAN_POLICYDB_ALLOC_SIZE);

    fp.data = (char *)blob;
    fp.len = len;
    rc = policydb_read_fn(policydb, &fp);
    if (rc) {
        pr_warn("[selinux_hook] CLEAN policydb_read failed reason=%s rc=%d policydb=%px blob=%px len=%zu\n",
                reason ?: "(null)", rc, policydb, blob, len);
        if (policydb_destroy_fn)
            policydb_destroy_fn(policydb);
        susfs_vfree(policydb);
        return;
    }

    WRITE_ONCE(g_clean_policydb, policydb);
    WRITE_ONCE(g_clean_policydb_direct, true);
    pr_info("[selinux_hook] CLEAN policydb_read saved reason=%s policydb=%px blob=%px len=%zu alloc=%u\n",
            reason ?: "(null)", policydb, blob, len, CLEAN_POLICYDB_ALLOC_SIZE);
}

static void activate_clean_policy_blob(const char *reason)
{
    void *data = READ_ONCE(g_clean_policy_blob);
    size_t len = READ_ONCE(g_clean_policy_len);
    int rc;

    if (!data || !len)
        return;

    /* On 6.6 redirect is supported and security_load_policy has load_state.
     * Fall back to policydb_read only if the load_state helpers are missing. */
    if (!security_load_policy_has_load_state()) {
        try_load_clean_policydb_from_blob(reason);
        pr_info("[selinux_hook] CLEAN policy blob route reason=%s: blob=%px len=%zu policydb=%px\n",
                reason ?: "(null)", data, len, READ_ONCE(g_clean_policydb));
        return;
    }

    if (security_load_policy_fn && !READ_ONCE(g_clean_load_state_ready)) {
        WRITE_ONCE(g_internal_policy_load_depth,
                   READ_ONCE(g_internal_policy_load_depth) + 1);
        rc = call_security_load_policy(data, len, &g_clean_load_state);
        if (READ_ONCE(g_internal_policy_load_depth))
            WRITE_ONCE(g_internal_policy_load_depth,
                       READ_ONCE(g_internal_policy_load_depth) - 1);
        if (!rc && g_clean_load_state.policy) {
            WRITE_ONCE(g_clean_load_state_ready, true);
            refresh_clean_policydb("clean_load", false);
            cancel_clean_sidtab_convert("clean_load");
            selinux_hook_dbg("[selinux_hook] CLEAN policy loaded policy=%px policydb=%px convert=%px\n",
                             g_clean_load_state.policy, READ_ONCE(g_clean_policydb),
                             g_clean_load_state.convert_data);
        } else {
            pr_warn("[selinux_hook] CLEAN policy load failed rc=%d policy=%px\n",
                    rc, g_clean_load_state.policy);
        }
    }
}

static void snapshot_clean_policy(const char *reason)
{
    if (READ_ONCE(g_clean_policy_blob))
        return;
    if (READ_ONCE(g_dirty_policy_seen))
        return;

    if (!snapshot_magisk_policy_file(reason, true))
        return;

    activate_clean_policy_blob(reason);
}

static bool finish_deferred_policy_capture(hook_fargs4_t *a, const char *stage,
                                           bool allow_fallback)
{
    void *data = NULL;
    size_t len = 0;

    if (READ_ONCE(g_clean_policy_blob))
        return true;
    if (READ_ONCE(g_dirty_policy_seen))
        return false;

    if (snapshot_magisk_policy_file(stage, true)) {
        activate_clean_policy_blob(stage);
        return READ_ONCE(g_clean_policy_blob) != NULL;
    }

    if (!allow_fallback) {
        selinux_hook_dbg("[selinux_hook] CLEAN Magisk policy unavailable during %s; waiting for after security_load_policy\n",
                         stage ?: "before");
        return false;
    }

    if (!a)
        return false;

    /* 6.6 (non-compat) security_load_policy(data, len, load_state):
     * arg0=data, arg1=len. */
    data = (void *)a->arg0;
    len = (size_t)a->arg1;

    if (!data || !len || len > MAGISK_POLICY_MAX_SIZE || !susfs_vmalloc) {
        pr_warn("[selinux_hook] CLEAN security_load_policy fallback rejected stage=%s data=%px len=%zu vmalloc=%px\n",
                stage ?: "after", data, len, susfs_vmalloc);
        return false;
    }

    {
        void *src = data;
        void *copy = susfs_vmalloc((unsigned long)len);

        if (!copy) {
            pr_warn("[selinux_hook] CLEAN security_load_policy fallback alloc failed stage=%s len=%zu\n",
                    stage ?: "after", len);
            return false;
        }
        copy_bytes(copy, src, len);
        data = copy;
    }
    if (!data) {
        pr_warn("[selinux_hook] CLEAN security_load_policy fallback alloc failed stage=%s len=%zu\n",
                stage ?: "after", len);
        return false;
    }

    WRITE_ONCE(g_clean_policy_has_magisk, buffer_contains_magisk(data, len));
    WRITE_ONCE(g_clean_policy_len, len);
    WRITE_ONCE(g_clean_policy_blob, data);
    pr_warn("[selinux_hook] CLEAN policy captured from security_load_policy args stage=%s blob=%px len=%zu has_magisk=%d\n",
            stage ?: "after", data, len, READ_ONCE(g_clean_policy_has_magisk));
    activate_clean_policy_blob(stage ?: "security_load_policy");
    return true;
}

static void before_security_load_policy(hook_fargs4_t *a, void *u)
{
    if (READ_ONCE(g_clean_policy_blob) || g_policy_capture_in_progress)
        return;

    g_policy_capture_in_progress = true;
    finish_deferred_policy_capture(a, "before_security_load_policy", false);
    g_policy_capture_in_progress = false;
}

static void after_security_load_policy(hook_fargs4_t *a, void *u)
{
    if (READ_ONCE(g_clean_policy_blob) || g_policy_capture_in_progress)
        return;
    if (a && (long)a->ret)
        return;

    g_policy_capture_in_progress = true;
    finish_deferred_policy_capture(a, "after_security_load_policy", true);
    g_policy_capture_in_progress = false;
}

static bool contains_magisk(const char *s, size_t len)
{
    return contains_case_literal(s, len, "magisk");
}

static bool contains_case_lit(const char *s, size_t len, const char *lit, size_t lit_len)
{
    size_t i;
    size_t j;

    if (!s || !lit || !lit_len || len < lit_len)
        return false;

    for (i = 0; i + lit_len <= len; i++) {
        for (j = 0; j < lit_len; j++) {
            if (!ascii_lower_eq(s[i + j], lit[j]))
                break;
        }
        if (j == lit_len)
            return true;
    }

    return false;
}

static size_t sanitize_query_sample(char *dst, size_t size)
{
    size_t i;

    if (!dst)
        return 0;

    for (i = 0; i < size && i < ACCESS_SAMPLE_MAX - 1; i++) {
        char c = dst[i];

        if (!c)
            break;
        if (c == '\n' || c == '\r' || c == '\t')
            c = ' ';
        dst[i] = c;
    }

    dst[i] = '\0';
    return i;
}

static size_t copy_query_sample(char *dst, const char *src, size_t size)
{
    size_t limit;
    long copied;

    if (!dst || !src)
        return 0;

    limit = size;
    if (!limit || limit > ACCESS_SAMPLE_MAX - 1)
        limit = ACCESS_SAMPLE_MAX - 1;

    dst[0] = '\0';

    if (copy_from_kernel_nofault_fn &&
        copy_from_kernel_nofault_fn(dst, src, limit) == 0) {
        dst[limit] = '\0';
        return sanitize_query_sample(dst, limit);
    }

    copied = compat_strncpy_from_user(dst, (const char __user *)src, limit + 1);
    if (copied <= 0) {
        dst[0] = '\0';
        return 0;
    }

    if ((size_t)copied > limit)
        copied = limit;
    return sanitize_query_sample(dst, (size_t)copied);
}

static size_t token_len(const char *s)
{
    size_t i = 0;

    if (!s)
        return 0;

    while (s[i] && s[i] != ' ' && s[i] != '\n' && s[i] != '\r' && s[i] != '\t')
        i++;
    return i;
}

static const char *skip_spaces(const char *s)
{
    while (s && (*s == ' ' || *s == '\n' || *s == '\r' || *s == '\t'))
        s++;
    return s;
}

static const char *next_token(const char *s)
{
    s = skip_spaces(s);
    while (s && *s && *s != ' ' && *s != '\n' && *s != '\r' && *s != '\t')
        s++;
    return skip_spaces(s);
}

static bool clean_blob_has_name(const char *name, size_t len)
{
    const char *blob = (const char *)READ_ONCE(g_clean_policy_blob);
    size_t blob_len = READ_ONCE(g_clean_policy_len);
    size_t i;

    if (!blob || !blob_len || !name || !len)
        return true;

    for (i = 0; i + len <= blob_len; i++) {
        size_t j;

        for (j = 0; j < len; j++) {
            if (blob[i + j] != name[j])
                break;
        }
        if (j == len)
            return true;
    }

    return false;
}

static bool clean_context_token_exists(const char *ctx, size_t len)
{
    size_t i;
    size_t first = (size_t)-1;
    size_t second = (size_t)-1;
    size_t third = (size_t)-1;

    if (!ctx || !len)
        return true;

    for (i = 0; i < len; i++) {
        if (ctx[i] != ':')
            continue;
        if (first == (size_t)-1)
            first = i;
        else if (second == (size_t)-1)
            second = i;
        else {
            third = i;
            break;
        }
    }

    if (second == (size_t)-1)
        return true;

    if (third == (size_t)-1)
        third = len;

    if (third <= second + 1)
        return false;

    return clean_blob_has_name(ctx + second + 1, third - second - 1);
}

static bool clean_context_exists(const char *query)
{
    query = skip_spaces(query);
    return clean_context_token_exists(query, token_len(query));
}

static bool token_eq_lit(const char *token, size_t len, const char *lit)
{
    size_t i;

    if (!token || !lit)
        return false;

    for (i = 0; i < len; i++) {
        if (!lit[i] || !ascii_lower_eq(token[i], lit[i]))
            return false;
    }

    return lit[i] == '\0';
}

static bool access_query_matches3(const char *query, const char *src_lit,
                                  const char *dst_lit, const char *class_lit)
{
    const char *src;
    const char *dst;
    const char *tclass;

    src = skip_spaces(query);
    dst = next_token(src);
    tclass = next_token(dst);

    return token_eq_lit(src, token_len(src), src_lit) &&
           token_eq_lit(dst, token_len(dst), dst_lit) &&
           token_eq_lit(tclass, token_len(tclass), class_lit);
}

static bool dirtysepolicy_avd_seqno_probe(const char *query, size_t len)
{
    if (!query || !len)
        return false;

    /*
     * AppZygote.java checks avd[4] from:
     *   SELinux.access("u:r:untrusted_app:s0",
     *                  "u:r:untrusted_app:s0", 0)
     *
     * This reads /sys/fs/selinux/access returning av_decision.seqno.  Only
     * patching /sys/fs/selinux/status is not enough; recognize the fixed
     * query and return a clean seqno so the live policy seqno is not leaked.
     */
    return access_query_matches3(query, "u:r:untrusted_app:s0",
                                 "u:r:untrusted_app:s0", "0");
}

static long write_clean_access_seqno_response(char *buf, size_t size)
{
    static const char response[] = "0 0 0 0 1 0";
    size_t len = sizeof(response) - 1;

    if (!buf || size < len)
        return -EINVAL;

    copy_bytes(buf, response, len);
    if (size > len)
        buf[len] = '\0';

    return (long)len;
}

static bool clean_access_contexts_exist(const char *query)
{
    const char *src;
    const char *dst;
    size_t src_len;
    size_t dst_len;

    src = skip_spaces(query);
    src_len = token_len(src);
    if (!clean_context_token_exists(src, src_len))
        return false;

    dst = next_token(src);
    dst_len = token_len(dst);
    if (!clean_context_token_exists(dst, dst_len))
        return false;

    return true;
}

static bool access_contexts_match(const char *query, const char *src_lit,
                                  const char *dst_lit)
{
    const char *src;
    const char *dst;

    src = skip_spaces(query);
    dst = next_token(src);

    return token_eq_lit(src, token_len(src), src_lit) &&
           token_eq_lit(dst, token_len(dst), dst_lit);
}

static bool legacy_should_block_access_query(const char *query, size_t len)
{
    if (!query || !len)
        return false;

    if (contains_case_literal(query, len, "magisk"))
        return true;
    if (contains_case_literal(query, len, "ksu_file"))
        return true;
    if (contains_case_literal(query, len, "lsposed_file"))
        return true;
    if (contains_case_literal(query, len, "xposed_data"))
        return true;
    if (contains_case_literal(query, len, "adbroot"))
        return true;

    return false;
}

static bool legacy_clean_query_should_block(const char *query, size_t len, bool access_query)
{
    if (legacy_should_block_access_query(query, len))
        return true;
    if (!READ_ONCE(g_clean_policy_blob))
        return false;

    if (access_query)
        return !clean_access_contexts_exist(query);

    return !clean_context_exists(query);
}

/* ===== scope management (clean-eval and status-read) ===== */

static bool enter_clean_eval_scope(void)
{
    void *task = current;
    int empty = -1;
    int i;
    u32 depth;
    bool entered = false;

    if (!READ_ONCE(g_clean_policydb))
        return false;

    susfs__raw_spin_lock(&g_scopes_lock);
    for (i = 0; i < CLEAN_EVAL_SCOPE_SLOTS; i++) {
        if (g_clean_eval_scopes[i].task == task) {
            depth = g_clean_eval_scopes[i].depth + 1;
            g_clean_eval_scopes[i].depth = depth;
            WRITE_ONCE(g_clean_eval_depth, READ_ONCE(g_clean_eval_depth) + 1);
            entered = true;
            break;
        }
        if (empty < 0 && !g_clean_eval_scopes[i].task)
            empty = i;
    }

    if (!entered) {
        if (empty < 0) {
            susfs__raw_spin_unlock(&g_scopes_lock);
            pr_warn("[selinux_hook] clean eval scope slots exhausted task=%px comm=%s\n",
                    task, current_comm());
            return false;
        }
        g_clean_eval_scopes[empty].task = task;
        g_clean_eval_scopes[empty].depth = 1;
        WRITE_ONCE(g_clean_eval_depth, READ_ONCE(g_clean_eval_depth) + 1);
        entered = true;
    }
    susfs__raw_spin_unlock(&g_scopes_lock);
    return entered;
}

static void leave_clean_eval_scope(void)
{
    void *task = current;
    int i;
    u32 depth;

    susfs__raw_spin_lock(&g_scopes_lock);
    for (i = 0; i < CLEAN_EVAL_SCOPE_SLOTS; i++) {
        if (g_clean_eval_scopes[i].task != task)
            continue;

        depth = g_clean_eval_scopes[i].depth;
        if (depth > 1) {
            g_clean_eval_scopes[i].depth = depth - 1;
        } else {
            g_clean_eval_scopes[i].depth = 0;
            g_clean_eval_scopes[i].task = NULL;
        }
        if (READ_ONCE(g_clean_eval_depth))
            WRITE_ONCE(g_clean_eval_depth, READ_ONCE(g_clean_eval_depth) - 1);
        susfs__raw_spin_unlock(&g_scopes_lock);
        return;
    }
    susfs__raw_spin_unlock(&g_scopes_lock);
}

static bool current_in_clean_eval_scope(void)
{
    void *task = current;
    int i;
    bool in_scope = false;

    susfs__raw_spin_lock(&g_scopes_lock);
    for (i = 0; i < CLEAN_EVAL_SCOPE_SLOTS; i++) {
        if (g_clean_eval_scopes[i].task == task &&
            g_clean_eval_scopes[i].depth) {
            in_scope = true;
            break;
        }
    }
    susfs__raw_spin_unlock(&g_scopes_lock);
    return in_scope;
}

static bool enter_status_read_scope(void)
{
    void *task = current;
    int empty = -1;
    int i;
    u32 depth;
    bool entered = false;

    susfs__raw_spin_lock(&g_scopes_lock);
    for (i = 0; i < STATUS_READ_SCOPE_SLOTS; i++) {
        if (g_status_read_scopes[i].task == task) {
            depth = g_status_read_scopes[i].depth + 1;
            g_status_read_scopes[i].depth = depth;
            entered = true;
            break;
        }
        if (empty < 0 && !g_status_read_scopes[i].task)
            empty = i;
    }

    if (!entered) {
        if (empty < 0) {
            susfs__raw_spin_unlock(&g_scopes_lock);
            pr_warn("[selinux_hook] status read scope slots exhausted task=%px comm=%s\n",
                    task, current_comm());
            return false;
        }
        g_status_read_scopes[empty].task = task;
        g_status_read_scopes[empty].depth = 1;
        g_status_read_scopes[empty].patched = 0;
        entered = true;
    }
    susfs__raw_spin_unlock(&g_scopes_lock);
    return true;
}

static void leave_status_read_scope(void)
{
    void *task = current;
    int i;
    u32 depth;

    susfs__raw_spin_lock(&g_scopes_lock);
    for (i = 0; i < STATUS_READ_SCOPE_SLOTS; i++) {
        if (g_status_read_scopes[i].task != task)
            continue;

        depth = g_status_read_scopes[i].depth;
        if (depth > 1) {
            g_status_read_scopes[i].depth = depth - 1;
        } else {
            g_status_read_scopes[i].depth = 0;
            g_status_read_scopes[i].patched = 0;
            g_status_read_scopes[i].task = NULL;
        }
        susfs__raw_spin_unlock(&g_scopes_lock);
        return;
    }
    susfs__raw_spin_unlock(&g_scopes_lock);
}

static bool current_in_status_read_scope(void)
{
    void *task = current;
    int i;
    bool in_scope = false;

    susfs__raw_spin_lock(&g_scopes_lock);
    for (i = 0; i < STATUS_READ_SCOPE_SLOTS; i++) {
        if (g_status_read_scopes[i].task == task &&
            g_status_read_scopes[i].depth) {
            in_scope = true;
            break;
        }
    }
    susfs__raw_spin_unlock(&g_scopes_lock);
    return in_scope;
}

static void mark_status_read_scope_patched(void)
{
    void *task = current;
    int i;

    susfs__raw_spin_lock(&g_scopes_lock);
    for (i = 0; i < STATUS_READ_SCOPE_SLOTS; i++) {
        if (g_status_read_scopes[i].task == task &&
            g_status_read_scopes[i].depth) {
            g_status_read_scopes[i].patched = 1;
            susfs__raw_spin_unlock(&g_scopes_lock);
            return;
        }
    }
    susfs__raw_spin_unlock(&g_scopes_lock);
}

static bool current_status_read_scope_patched(void)
{
    void *task = current;
    int i;
    bool patched = false;

    susfs__raw_spin_lock(&g_scopes_lock);
    for (i = 0; i < STATUS_READ_SCOPE_SLOTS; i++) {
        if (g_status_read_scopes[i].task == task &&
            g_status_read_scopes[i].depth) {
            patched = g_status_read_scopes[i].patched != 0;
            break;
        }
    }
    susfs__raw_spin_unlock(&g_scopes_lock);
    return patched;
}

static int clean_policy_context_to_sid(const char *query, u32 *out_sid)
{
    const char *ctx;
    size_t len;
    int rc;

    if (!query || !out_sid)
        return -EINVAL;

    refresh_clean_policydb("procattr_current", true);
    if (!READ_ONCE(g_clean_policydb) || !security_context_to_sid_fn)
        return 1;
    /* clean_policydb_redirect_supported() is always true on 6.6 */

    ctx = skip_spaces(query);
    len = token_len(ctx);
    if (!len)
        return -EINVAL;

    if (!enter_clean_eval_scope())
        return -EAGAIN;

    rc = call_security_context_to_sid(ctx, (u32)len, out_sid, (gfp_t)0);
    leave_clean_eval_scope();

    return rc;
}

/* ===== deferred capture + policydb redirect hooks ===== */

/* Hook: selinux_complete_init */
static void after_selinux_complete_init(hook_fargs0_t *a, void *u)
{
    WRITE_ONCE(g_selinux_ready, true);
    selinux_hook_dbg("[selinux_hook] SELinux complete_init done\n");
    snapshot_clean_policy("complete_init");
}

/* Hook: selinux_policy_commit */
static void after_selinux_policy_commit(hook_fargs1_t *a, void *u)
{
    void *policy = read_load_state_policy((void *)a->arg0);

    WRITE_ONCE(g_selinux_ready, true);
    if (policy && !READ_ONCE(g_first_policy))
        WRITE_ONCE(g_first_policy, policy);
    refresh_clean_policydb("policy_commit", false);
    cancel_clean_sidtab_convert("policy_commit");
    selinux_hook_dbg("[selinux_hook] SELinux policy committed, first policy=%px first policydb=%px clean policydb=%px\n",
                     g_first_policy, g_first_policydb, READ_ONCE(g_clean_policydb));
    snapshot_clean_policy("policy_commit");
}

static void before_policydb_arg0(hook_fargs6_t *a, void *u)
{
    void *policydb = (void *)a->arg0;
    void *clean_policydb = READ_ONCE(g_clean_policydb);
    bool bypass = should_bypass_clean_filter(current_uid());

    /* Skip redirect for internal policy loads or privileged callers. */
    if (READ_ONCE(g_internal_policy_load_depth) || bypass)
        return;

    /*
     * Only calls running in an explicit clean-eval scope may redirect policydb
     * input.  The scope is tied to current so unrelated callers on other tasks
     * remain observational and keep using the live policydb.
     */
    if (current_in_clean_eval_scope() && clean_policydb && !bypass) {
        a->arg0 = (uint64_t)clean_policydb;
        return;
    }

    if (!policydb)
        return;

    if (!READ_ONCE(g_selinux_ready)) {
        WRITE_ONCE(g_selinux_ready, true);
        selinux_hook_dbg("[selinux_hook] SELinux ready inferred from context_struct_compute_av\n");
    }

    if (!READ_ONCE(g_first_policydb)) {
        WRITE_ONCE(g_first_policydb, policydb);
        selinux_hook_dbg("[selinux_hook] SAVED first policydb @ %px\n", g_first_policydb);
        refresh_clean_policydb("first_compute_av", false);
        snapshot_clean_policy("first_compute_av");
        return;
    }

    if (!READ_ONCE(g_dirty_policy_seen) &&
        policydb != READ_ONCE(g_first_policydb) &&
        policydb != READ_ONCE(g_clean_policydb)) {
        WRITE_ONCE(g_dirty_policy_seen, true);
        selinux_hook_dbg("[selinux_hook] policydb changed %px -> %px, Magisk access probes will hit clean-policy EINVAL\n",
                         g_first_policydb, policydb);
    }
}

static void before_context_struct_compute_av_policydb(hook_fargs6_t *a, void *u)
{
    struct av_decision *avd;
    void *clean_policydb;

    a->local.data0 = 0;

    before_policydb_arg0(a, u);

    clean_policydb = READ_ONCE(g_clean_policydb);
    if (!clean_policydb || (void *)a->arg0 != clean_policydb ||
        !current_in_clean_eval_scope())
        return;

    avd = (struct av_decision *)a->arg4;
    if (!avd)
        return;

    a->local.data0 = 1;
    a->local.data1 = (uint64_t)avd;
    a->local.data2 = READ_ONCE(avd->seqno);
    a->local.data3 = READ_ONCE(avd->flags);
}

static void after_context_struct_compute_av_policydb(hook_fargs6_t *a, void *u)
{
    struct av_decision *avd;

    if (!a->local.data0)
        return;

    avd = (struct av_decision *)a->local.data1;
    if (!avd)
        return;

    WRITE_ONCE(avd->seqno, SELINUX_STATUS_CLEAN_SEQUENCE);
    WRITE_ONCE(avd->flags, (u32)a->local.data3);
}

/* ===== selinuxfs access/context write hooks (direct symbol path) ===== */

/* Hook: /sys/fs/selinux/access write handler */
static void before_sel_write_access(hook_fargs4_t *a, void *u)
{
    const char *query = (const char *)a->arg1;
    size_t size = (size_t)a->arg2;
    size_t sample_len;
    char sample[ACCESS_SAMPLE_MAX];
    u32 slot;
    u32 n;
    uid_t uid;

    a->local.data0 = 0;
    a->local.data1 = 0;
    a->local.data2 = 0;

    uid = current_uid();
    sample_len = copy_query_sample(sample, query, size);

    if (should_bypass_clean_filter(uid)) {
        if (should_log_live_bypass(uid))
            log_bypass_once("access", uid, sample);
        return;
    }

    if (dirtysepolicy_avd_seqno_probe(sample, sample_len)) {
        long ret;

        n = READ_ONCE(g_clean_access_count) + 1;
        WRITE_ONCE(g_clean_access_count, n);
        a->local.data0 = 5;
        a->local.data1 = n;
        slot = n & (ACCESS_PROBE_SLOTS - 1);
        a->local.data2 = slot;
        g_probes[slot].id = n;
        g_probes[slot].uid = uid;
        g_probes[slot].node = "access";
        copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);

        ret = write_clean_access_seqno_response((char *)a->arg1, size);
        pr_info("[selinux_hook] DIRTYSEPOLICY clean avd seqno /sys/fs/selinux/access #%u uid=%d comm=%s ret=%ld query=\"%s\"\n",
                n, uid, current_comm(), ret, sample);
        a->skip_origin = 1;
        a->ret = (ret > 0) ? (uint64_t)ret : (uint64_t)-EINVAL;
        return;
    }

    refresh_clean_policydb("access", true);

    n = READ_ONCE(g_clean_access_count) + 1;
    WRITE_ONCE(g_clean_access_count, n);

    if (!READ_ONCE(g_clean_policydb) && READ_ONCE(g_clean_policy_blob) &&
        legacy_should_block_access_query(sample, sample_len)) {
        a->local.data0 = 2;
        a->local.data1 = n;
        slot = n & (ACCESS_PROBE_SLOTS - 1);
        a->local.data2 = slot;
        g_probes[slot].id = n;
        g_probes[slot].uid = uid;
        g_probes[slot].node = "access";
        copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);
        a->skip_origin = 1;
        a->ret = -EINVAL;
        return;
    }

    /* Run the original selinuxfs write_op under the current task's clean scope. */
    a->local.data0 = 3;
    a->local.data1 = n;
    slot = n & (ACCESS_PROBE_SLOTS - 1);
    a->local.data2 = slot;
    g_probes[slot].id = n;
    g_probes[slot].uid = uid;
    g_probes[slot].node = "access";
    copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);
    if (enter_clean_eval_scope()) {
        a->local.data3 = 1;
    } else {
        a->local.data0 = 0;
    }
}

/* Hook: /sys/fs/selinux/context write handler */
static void before_sel_write_context(hook_fargs4_t *a, void *u)
{
    const char *query = (const char *)a->arg1;
    size_t size = (size_t)a->arg2;
    char sample[ACCESS_SAMPLE_MAX];
    u32 slot;
    u32 n;
    uid_t uid;

    a->local.data0 = 0;
    a->local.data1 = 0;
    a->local.data2 = 0;

    uid = current_uid();
    (void)copy_query_sample(sample, query, size);

    if (should_bypass_clean_filter(uid)) {
        if (should_log_live_bypass(uid))
            log_bypass_once("context", uid, sample);
        return;
    }

    refresh_clean_policydb("context", true);

    n = READ_ONCE(g_clean_access_count) + 1;
    WRITE_ONCE(g_clean_access_count, n);

    a->local.data1 = n;
    slot = n & (ACCESS_PROBE_SLOTS - 1);
    a->local.data2 = slot;
    g_probes[slot].id = n;
    g_probes[slot].uid = uid;
    g_probes[slot].node = "context";
    copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);

    a->local.data0 = 3;
    if (enter_clean_eval_scope()) {
        a->local.data3 = 1;
    } else {
        a->local.data0 = 0;
    }
}

static void after_sel_write_common(hook_fargs4_t *a, void *u)
{
    long live_ret;
    struct access_probe *probe;
    u32 id;
    u32 slot;
    u32 mode;

    if (!a->local.data0)
        return;

    mode = (u32)a->local.data0;
    id = (u32)a->local.data1;
    slot = (u32)a->local.data2;
    if (a->local.data3)
        leave_clean_eval_scope();

    probe = &g_probes[slot];
    if (probe->id != id)
        return;

    live_ret = (long)a->ret;

    /* Patch seqno in the access response buffer to match /sys/fs/selinux/status */
    if (live_ret > 0 && probe->node && probe->node[0] == 'a') {
        char *rbuf = (char *)a->arg1;
        ssize_t new_ret = patch_response_seqno(rbuf, live_ret, 1);
        if (new_ret > 0) {
            live_ret = new_ret;
            a->ret = (uint64_t)new_ret;
        }
    }

    if (mode == 2) {
        selinux_hook_dbg("[selinux_hook] CLEAN /sys/fs/selinux/%s #%u uid=%d comm=%s clean_ret=%ld clean_policy=%px clean_policydb=%px blob=%px len=%zu query=\"%s\"\n",
                         probe->node ?: "?", id, probe->uid, current_comm(), live_ret,
                         g_clean_load_state.policy, READ_ONCE(g_clean_policydb),
                         READ_ONCE(g_clean_policy_blob), READ_ONCE(g_clean_policy_len),
                         probe->query);
        return;
    }

    selinux_hook_dbg("[selinux_hook] CLEAN /sys/fs/selinux/%s #%u uid=%d comm=%s clean_ret=%ld clean_policy=%px clean_policydb=%px blob=%px len=%zu query=\"%s\"\n",
                     probe->node ?: "?", id, probe->uid, current_comm(), live_ret,
                     g_clean_load_state.policy, READ_ONCE(g_clean_policydb),
                     READ_ONCE(g_clean_policy_blob), READ_ONCE(g_clean_policy_len),
                     probe->query);
}

/* ===== procattr filter ===== */

static bool filter_procattr_current(const char *hook, const char *lsm,
                                    const char *name, const void *value,
                                    size_t size)
{
    char sample[ACCESS_SAMPLE_MAX];
    size_t sample_len;
    uid_t uid;
    u32 n;
    bool clean_checked = false;
    bool blocked;
    bool manager;
    int clean_ret = 0;
    u32 clean_sid = 0;

    if (!str_eq_lit(name, "current"))
        return false;

    sample[0] = '\0';
    sample_len = value && size ? copy_query_sample(sample, (const char *)value, size) : 0;

    uid = current_uid();
    manager = should_bypass_clean_filter(uid);

    if (!manager) {
        if (!READ_ONCE(g_clean_policydb) && READ_ONCE(g_clean_policy_blob) &&
            legacy_should_block_access_query(sample, sample_len)) {
            clean_checked = true;
            clean_ret = -EINVAL;
        } else {
            clean_ret = clean_policy_context_to_sid(sample, &clean_sid);
            clean_checked = clean_ret <= 0;
        }
        if (clean_ret == 1 && READ_ONCE(g_clean_policy_blob)) {
            clean_checked = true;
            clean_ret = clean_context_exists(sample) ? 0 : -EINVAL;
        } else if (clean_ret == 1) {
            clean_ret = 0;
        }
    }
    blocked = !manager && clean_ret == -EINVAL;

    n = READ_ONCE(g_procattr_current_count) + 1;
    WRITE_ONCE(g_procattr_current_count, n);

    pr_info("[selinux_hook] AUDIT /proc/self/attr/current #%u hook=%s lsm=%s uid=%d comm=%s name_ptr=%px value=%px size=%zu sample_len=%zu manager=%d clean_checked=%d clean_ret=%d clean_sid=%u clean_policydb=%px action=%s forced_ret=%d query=\"%s\"\n",
            n, hook ?: "?", lsm ?: "-", uid, current_comm(), name, value, size,
            sample_len, manager, clean_checked,
            clean_ret, clean_sid, READ_ONCE(g_clean_policydb),
            blocked ? "block" : "pass", blocked ? -EINVAL : 0, sample);
    return blocked;
}

/* Hook: security_setprocattr(lsm, name, value, size) — 4 args on 6.6 (>= 5.4). */
static void before_security_setprocattr(hook_fargs4_t *a, void *u)
{
    const char *lsm = (const char *)a->arg0;
    const char *name = (const char *)a->arg1;
    const void *value = (const void *)a->arg2;
    size_t size = (size_t)a->arg3;
    u32 n;

    n = READ_ONCE(g_setprocattr_probe_count);
    if (n < 16) {
        n++;
        WRITE_ONCE(g_setprocattr_probe_count, n);
        pr_info("[selinux_hook] PROBE security_setprocattr4 #%u uid=%d comm=%s arg0=%px arg1=%px arg2=%px arg3=%zu\n",
                n, current_uid(), current_comm(), (void *)a->arg0,
                (void *)a->arg1, (void *)a->arg2, size);
    }

    if (str_eq_lit(lsm, "current")) {
        if (!filter_procattr_current("security_setprocattr_compat3", NULL,
                                     lsm, (const void *)a->arg1,
                                     (size_t)a->arg2))
            return;

        a->skip_origin = 1;
        a->ret = -EINVAL;
        return;
    }

    if (lsm && !str_eq_lit(lsm, "selinux"))
        return;

    if (!filter_procattr_current("security_setprocattr", lsm, name, value, size))
        return;

    a->skip_origin = 1;
    a->ret = -EINVAL;
}

/* Hook fallback: selinux_setprocattr(name, value, size) — 3 args. */
static void before_selinux_setprocattr(hook_fargs3_t *a, void *u)
{
    const char *name = (const char *)a->arg0;
    const void *value = (const void *)a->arg1;
    size_t size = (size_t)a->arg2;
    u32 n;

    n = READ_ONCE(g_selinux_setprocattr_probe_count);
    if (n < 16) {
        n++;
        WRITE_ONCE(g_selinux_setprocattr_probe_count, n);
        pr_info("[selinux_hook] PROBE selinux_setprocattr #%u uid=%d comm=%s arg0=%px arg1=%px arg2=%zu\n",
                n, current_uid(), current_comm(), (void *)a->arg0,
                (void *)a->arg1, size);
    }

    if (!filter_procattr_current("selinux_setprocattr", NULL, name, value, size))
        return;

    a->skip_origin = 1;
    a->ret = -EINVAL;
}

/* ===== status read / mmap patches ===== */

static ssize_t copy_clean_status_to_user(char __user *buf, size_t count,
                                         loff_t *ppos)
{
    unsigned char status[SELINUX_STATUS_SIZE];
    loff_t pos;
    size_t avail;
    int rc;

    if (!buf || !ppos)
        return -EINVAL;

    pos = *ppos;
    if (pos < 0)
        return -EINVAL;
    if (!count || pos >= (loff_t)sizeof(status))
        return 0;

    fill_clean_status_bytes(status);

    avail = sizeof(status) - (size_t)pos;
    if (count > avail)
        count = avail;

    rc = copy_status_to_user(buf, ((char *)&status) + pos, count);
    if (rc)
        return -EFAULT;

    *ppos = pos + (loff_t)count;
    return (ssize_t)count;
}

/*
 * Hook: /sys/fs/selinux/status mmap handler.
 *
 * Android libselinux and detection tools access the status page via mmap(),
 * not read(). sel_read_handle_status is therefore never called. We hook
 * sel_mmap_handle_status instead and patch the sequence field in the mapped
 * page to keep it consistent with our spoofed read() path.
 *
 * struct vm_area_struct vm_start offset:
 *   kernel >= 6.1 (CONFIG_PER_VMA_LOCK): int(4)+pad(4)+ptr(8) = offset 16
 */
static void after_sel_mmap_handle_status(hook_fargs2_t *a, void *u)
{
    void *vma;
    unsigned long vm_start = 0;
    unsigned long vm_start_off;
    u32 n;

    if ((int)a->ret != 0)
        return;

    vma = (void *)a->arg1;
    if (!vma)
        return;

    vm_start_off = (kver >= VERSION(6, 1, 0)) ? 16 : 0;

    if (!copy_from_kernel_nofault_fn ||
        copy_from_kernel_nofault_fn(&vm_start, (char *)vma + vm_start_off,
                                    sizeof(vm_start)) != 0)
        return;

    /* Sanity check: must look like a user virtual address */
    if (!vm_start || vm_start < 0x10000UL || vm_start >= 0xffffff0000000000UL)
        return;

    /* Patch sequence (offset 4) and policyload (offset 12) in struct selinux_kernel_status */
    if (copy_to_user_nofault_fn) {
        unsigned char patch_bytes[4];
        /* sequence at offset 4 */
        put_u32_le(patch_bytes, get_u32_le(g_clean_status_bytes + 4));
        copy_to_user_nofault_fn((void __user *)(vm_start + 4), patch_bytes, 4);
        /* policyload at offset 12 */
        put_u32_le(patch_bytes, get_u32_le(g_clean_status_bytes + 12));
        copy_to_user_nofault_fn((void __user *)(vm_start + 12), patch_bytes, 4);
    }

    n = READ_ONCE(g_status_read_count) + 1;
    WRITE_ONCE(g_status_read_count, n);
    selinux_hook_dbg("[selinux_hook] STATUS mmap patch #%u uid=%d comm=%s vm_start=%lx seq=%u pload=%u\n",
                     n, current_uid(), current_comm(), vm_start,
                     get_u32_le(g_clean_status_bytes + 4),
                     get_u32_le(g_clean_status_bytes + 12));
}

static void before_sel_read_handle_status(hook_fargs4_t *a, void *u)
{
    uid_t uid = current_uid();
    ssize_t ret;
    u32 n;
    u32 probe;
    loff_t pos_before = -1;
    loff_t pos_after = -1;

    a->local.data0 = 0;
    a->local.data1 = 0;
    a->local.data2 = 0;
    a->local.data3 = 0;

    if (should_bypass_clean_filter(uid))
        return;

    probe = READ_ONCE(g_status_probe_count) + 1;
    WRITE_ONCE(g_status_probe_count, probe);
    if (a->arg3) {
        if (copy_from_kernel_nofault_fn &&
            copy_from_kernel_nofault_fn(&pos_before, (void *)a->arg3,
                                        sizeof(pos_before)) != 0)
            pos_before = -2;
        else if (!copy_from_kernel_nofault_fn)
            pos_before = *(loff_t *)a->arg3;
    }

    if (READ_ONCE(g_simple_read_from_buffer_hooked) && enter_status_read_scope()) {
        a->local.data0 = 1;
        a->local.data1 = probe;
        a->local.data2 = (uint64_t)pos_before;
        a->local.data3 = uid;
        return;
    }

    ret = copy_clean_status_to_user((char __user *)a->arg1,
                                    (size_t)a->arg2,
                                    (loff_t *)a->arg3);
    if (a->arg3) {
        if (copy_from_kernel_nofault_fn &&
            copy_from_kernel_nofault_fn(&pos_after, (void *)a->arg3,
                                        sizeof(pos_after)) != 0)
            pos_after = -2;
        else if (!copy_from_kernel_nofault_fn)
            pos_after = *(loff_t *)a->arg3;
    }

    if (probe <= 16)
        pr_info("[selinux_hook] STATUS probe #%u uid=%d comm=%s file=%px buf=%px count=%zu ppos=%px pos_before=%lld ret=%zd pos_after=%lld copy=%s clean_version=%u clean_sequence=%u clean_policyload=%u\n",
                probe, uid, current_comm(), (void *)a->arg0,
                (void *)a->arg1, (size_t)a->arg2, (void *)a->arg3,
                pos_before, ret, pos_after, "copy_to_user",
                SELINUX_KERNEL_STATUS_VERSION,
                SELINUX_STATUS_CLEAN_SEQUENCE,
                SELINUX_STATUS_CLEAN_POLICYLOAD);

    if (ret < 0)
        return;

    n = READ_ONCE(g_status_read_count) + 1;
    WRITE_ONCE(g_status_read_count, n);

    a->skip_origin = 1;
    a->ret = (uint64_t)ret;
    selinux_hook_dbg("[selinux_hook] CLEAN /sys/fs/selinux/status #%u uid=%d comm=%s ret=%zd sequence=%u policyload=%u copy=%s\n",
                     n, uid, current_comm(), ret,
                     SELINUX_STATUS_CLEAN_SEQUENCE,
                     SELINUX_STATUS_CLEAN_POLICYLOAD,
                     "copy_to_user");
}

static void after_sel_read_handle_status(hook_fargs4_t *a, void *u)
{
    loff_t pos_after = -1;
    u32 probe;
    u32 n;
    bool patched;

    if (!a->local.data0)
        return;

    if (a->arg3) {
        if (copy_from_kernel_nofault_fn &&
            copy_from_kernel_nofault_fn(&pos_after, (void *)a->arg3,
                                        sizeof(pos_after)) != 0)
            pos_after = -2;
        else if (!copy_from_kernel_nofault_fn)
            pos_after = *(loff_t *)a->arg3;
    }

    patched = current_status_read_scope_patched();
    leave_status_read_scope();

    probe = (u32)a->local.data1;
    if (probe <= 16)
        pr_info("[selinux_hook] STATUS probe #%u uid=%u comm=%s mode=simple_read ret=%ld pos_before=%lld pos_after=%lld\n",
                probe, (u32)a->local.data3, current_comm(), (long)a->ret,
                (loff_t)a->local.data2, pos_after);

    if (!patched || (long)a->ret < 0)
        return;

    n = READ_ONCE(g_status_read_count) + 1;
    WRITE_ONCE(g_status_read_count, n);
    selinux_hook_dbg("[selinux_hook] CLEAN /sys/fs/selinux/status #%u uid=%u comm=%s mode=simple_read ret=%ld sequence=%u policyload=%u\n",
                     n, (u32)a->local.data3, current_comm(), (long)a->ret,
                     SELINUX_STATUS_CLEAN_SEQUENCE,
                     SELINUX_STATUS_CLEAN_POLICYLOAD);
}

static void before_simple_read_from_buffer(hook_fargs5_t *a, void *u)
{
    unsigned char *from;
    u32 n;

    a->local.data0 = 0;

    if (!current_in_status_read_scope())
        return;
    if ((size_t)a->arg4 != sizeof(g_clean_status_bytes))
        return;

    from = (unsigned char *)a->arg3;
    if (!from)
        return;

    copy_bytes(&a->local.data2, from, sizeof(g_clean_status_bytes));
    copy_bytes(from, g_clean_status_bytes, sizeof(g_clean_status_bytes));
    mark_status_read_scope_patched();

    a->local.data0 = 1;
    a->local.data1 = (uint64_t)from;

    n = READ_ONCE(g_status_redirect_count) + 1;
    WRITE_ONCE(g_status_redirect_count, n);
    if (n <= 16)
        pr_info("[selinux_hook] STATUS v3 simple_read patch #%u uid=%d comm=%s to=%px count=%zu ppos=%px from=%px available=%zu old=%u,%u,%u,%u,%u clean=%u,%u,%u,%u,%u bytes=%02x %02x %02x %02x\n",
                n, current_uid(), current_comm(), (void *)a->arg0,
                (size_t)a->arg1, (void *)a->arg2, from,
                (size_t)a->arg4,
                get_u32_le((unsigned char *)&a->local.data2 + 0),
                get_u32_le((unsigned char *)&a->local.data2 + 4),
                get_u32_le((unsigned char *)&a->local.data2 + 8),
                get_u32_le((unsigned char *)&a->local.data2 + 12),
                get_u32_le((unsigned char *)&a->local.data2 + 16),
                get_u32_le(g_clean_status_bytes + 0),
                get_u32_le(g_clean_status_bytes + 4),
                get_u32_le(g_clean_status_bytes + 8),
                get_u32_le(g_clean_status_bytes + 12),
                get_u32_le(g_clean_status_bytes + 16),
                g_clean_status_bytes[0], g_clean_status_bytes[1],
                g_clean_status_bytes[2], g_clean_status_bytes[3]);
}

static void after_simple_read_from_buffer(hook_fargs5_t *a, void *u)
{
    unsigned char *from;

    if (!a->local.data0)
        return;

    from = (unsigned char *)a->local.data1;
    if (!from)
        return;

    copy_bytes(from, &a->local.data2, sizeof(g_clean_status_bytes));
}

/* ===== /sys/fs/selinux/policy read backend ===== */

static void before_security_read_policy_common(hook_fargs2_t *a, void **out_data,
                                               size_t *out_len)
{
    void *snapshot = READ_ONCE(g_clean_policy_blob);
    size_t len = READ_ONCE(g_clean_policy_len);
    void *copy;
    u32 n;

    if (!snapshot || !len || !out_data || !out_len)
        return;
    if (should_bypass_clean_filter(current_uid())) {
        log_bypass_once("policy", current_uid(), NULL);
        return;
    }

    if (!susfs_vmalloc) {
        pr_warn("[selinux_hook] CLEAN policy read copy disabled: vmalloc unavailable\n");
        return;
    }

    /* Cache hit: a previous reader already vfree'd-into-cache for this
     * exact source pointer.  Reuse the cached vmalloc buffer. */
    susfs__raw_spin_lock(&g_policy_cache_lock);
    if (g_policy_read_cache && g_policy_read_cache_src == snapshot &&
        g_policy_read_cache_len == len) {
        copy = g_policy_read_cache;
        susfs__raw_spin_unlock(&g_policy_cache_lock);
    } else {
        void *stale = g_policy_read_cache;

        susfs__raw_spin_unlock(&g_policy_cache_lock);

        copy = susfs_vmalloc(len);
        if (!copy) {
            pr_warn("[selinux_hook] CLEAN policy read copy alloc failed len=%zu\n", len);
            return;
        }
        copy_bytes(copy, snapshot, len);

        susfs__raw_spin_lock(&g_policy_cache_lock);
        g_policy_read_cache = copy;
        g_policy_read_cache_len = len;
        g_policy_read_cache_src = snapshot;
        susfs__raw_spin_unlock(&g_policy_cache_lock);

        if (stale)
            susfs_vfree(stale);
    }

    *out_data = copy;
    *out_len = len;

    n = READ_ONCE(g_policy_read_count) + 1;
    WRITE_ONCE(g_policy_read_count, n);

    a->skip_origin = 1;
    a->ret = 0;
    selinux_hook_dbg("[selinux_hook] CLEAN /sys/fs/selinux/policy read #%u uid=%d comm=%s blob=%px copy=%px len=%zu\n",
                     n, current_uid(), current_comm(), snapshot, copy, len);
}

/* Hook: security_read_policy(data, len) — 2 args on 6.6. */
static void before_security_read_policy(hook_fargs2_t *a, void *u)
{
    before_security_read_policy_common(a, (void **)a->arg0, (size_t *)a->arg1);
}

/* ===== write_op hooks (direct symbol path only; no hotpatch on 6.6) ===== */

static int install_write_op_hooks(void)
{
    unsigned long addr_access, addr_context;

    addr_access = (unsigned long)lookup_name_optional_suffix("sel_write_access");
    addr_context = (unsigned long)lookup_name_optional_suffix("sel_write_context");
    log_symbol_addr("sel_write_access", (void *)addr_access);
    log_symbol_addr("sel_write_context", (void *)addr_context);

    if (addr_access) {
        g_funcs[g_hooks++] = (void *)addr_access;
        pr_info("[selinux_hook] hook sel_write_access argc=3 mode=direct\n");
        hook_wrap((void *)addr_access, 3, before_sel_write_access,
                  after_sel_write_common, NULL);
        selinux_hook_dbg("[selinux_hook] inline hook sel_write_access @ %lx\n", addr_access);
    } else {
        pr_warn("[selinux_hook] sel_write_access not found, access hook skipped\n");
    }

    if (addr_context) {
        g_funcs[g_hooks++] = (void *)addr_context;
        pr_info("[selinux_hook] hook sel_write_context argc=3 mode=direct\n");
        hook_wrap((void *)addr_context, 3, before_sel_write_context,
                  after_sel_write_common, NULL);
        selinux_hook_dbg("[selinux_hook] inline hook sel_write_context @ %lx\n", addr_context);
    } else {
        pr_warn("[selinux_hook] sel_write_context not found, context hook skipped\n");
    }

    return 0;
}

static void uninstall_inline_hooks(void)
{
    int i;

    for (i = 0; i < g_hooks; i++)
        unhook(g_funcs[i]);
    g_hooks = 0;
}

/* ===== working mode ===== */

static sel_hook_state_t module_get_working_mode(void)
{
    bool has_clean_policydb = READ_ONCE(g_clean_policydb) != NULL;
    bool has_clean_blob = READ_ONCE(g_clean_policy_blob) != NULL;

    /* NORMAL-K: clean policydb redirect active (6.6 always supports redirect). */
    if (has_clean_policydb)
        return SEL_HOOK_STATE_NORMAL_K;

    /* PARTIAL: clean blob captured but policydb not yet built. */
    if (has_clean_blob)
        return SEL_HOOK_STATE_PARTIAL_FALLBACK;

    /* FULL: nothing captured. */
    return SEL_HOOK_STATE_FULL_FALLBACK;
}

/* ===== public interface (called by susfs_kpm.c) ===== */

int susfs_selinux_hook_init(void)
{
    unsigned long addr;
    int rc;

    selinux_hook_dbg("[selinux_hook] init (6.6-only port)\n");

    /* Initialize clean status bytes based on kernel version */
    fill_clean_status_bytes(g_clean_status_bytes);
    selinux_hook_dbg("[selinux_hook] clean status: kver=%u.%u seq=%u pload=%u\n",
                     (unsigned)(kver >> 16), (unsigned)((kver >> 8) & 0xff),
                     get_u32_le(g_clean_status_bytes + 4),
                     get_u32_le(g_clean_status_bytes + 12));
    pr_info("[selinux_hook] kernel kver=%x\n", kver);
    resolve_required_symbols_once();

    copy_from_kernel_nofault_fn = (void *)lookup_name_optional_suffix("copy_from_kernel_nofault");
    copy_to_user_nofault_fn = (void *)lookup_name_optional_suffix("copy_to_user_nofault");
    if (!copy_from_kernel_nofault_fn)
        pr_warn("[selinux_hook] copy_from_kernel_nofault unresolved; kernel-pointer reads will dereference directly\n");
    if (!copy_to_user_nofault_fn)
        pr_warn("[selinux_hook] copy_to_user_nofault unresolved; status hook will use compat_copy_to_user fallback\n");

    filp_open_fn = (void *)lookup_name_optional_suffix("filp_open");
    filp_close_fn = (void *)lookup_name_optional_suffix("filp_close");
    kernel_read_fn = (void *)lookup_name_optional_suffix("kernel_read");
    vfs_llseek_fn = (void *)lookup_name_optional_suffix("vfs_llseek");
    if (!filp_open_fn || !filp_close_fn || !kernel_read_fn || !vfs_llseek_fn)
        pr_warn("[selinux_hook] cannot find file-read symbols: filp_open=%px filp_close=%px kernel_read=%px vfs_llseek=%px\n",
                filp_open_fn, filp_close_fn, kernel_read_fn, vfs_llseek_fn);

    security_load_policy_fn = (void *)lookup_name_optional_suffix("security_load_policy");
    security_context_to_sid_fn = (void *)lookup_name_optional_suffix("security_context_to_sid");
    policydb_read_fn = (void *)lookup_name_optional_suffix("policydb_read");
    policydb_destroy_fn = (void *)lookup_name_optional_suffix("policydb_destroy");
    selinux_policy_cancel_fn = (void *)lookup_name_optional_suffix("selinux_policy_cancel");
    sidtab_cancel_convert_fn = (void *)lookup_name_optional_suffix("sidtab_cancel_convert");
    security_read_policy_fn = (void *)lookup_name_optional_suffix("security_read_policy");

    log_symbol_addr("security_read_policy", (void *)security_read_policy_fn);
    log_symbol_addr("security_context_to_sid", (void *)security_context_to_sid_fn);
    log_symbol_addr("security_load_policy", (void *)security_load_policy_fn);
    log_symbol_addr("policydb_read", (void *)policydb_read_fn);
    log_symbol_addr("policydb_destroy", (void *)policydb_destroy_fn);
    log_symbol_addr("selinux_policy_cancel", (void *)selinux_policy_cancel_fn);
    log_symbol_addr("sidtab_cancel_convert", (void *)sidtab_cancel_convert_fn);

    pr_info("[selinux_hook] 6.6 route: policydb_redirect=1 load_state=%d\n",
            security_load_policy_has_load_state() ? 1 : 0);
    if (!sidtab_cancel_convert_fn)
        pr_warn("[selinux_hook] cannot find sidtab_cancel_convert, clean snapshot may leave live policy busy\n");

    if (!security_read_policy_fn) {
        pr_warn("[selinux_hook] cannot find security_read_policy, policy read hook disabled\n");
    } else {
        snapshot_clean_policy("module_init");
    }
    if (!security_context_to_sid_fn)
        pr_warn("[selinux_hook] cannot find security_context_to_sid, procattr clean policydb query will use blob fallback\n");
    if (!policydb_read_fn || !policydb_destroy_fn)
        pr_warn("[selinux_hook] cannot find policydb_read/policydb_destroy, legacy clean policydb disabled\n");

    /* ---- install hooks ---- */

    if (security_read_policy_fn) {
        g_funcs[g_hooks++] = (void *)security_read_policy_fn;
        pr_info("[selinux_hook] hook security_read_policy argc=2\n");
        hook_wrap((void *)security_read_policy_fn, 2, before_security_read_policy, NULL, NULL);
    }

    addr = (unsigned long)lookup_name_optional_suffix("simple_read_from_buffer");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        WRITE_ONCE(g_simple_read_from_buffer_hooked, true);
        selinux_hook_dbg("[selinux_hook] hook simple_read_from_buffer argc=5 for status patch\n");
        hook_wrap((void *)addr, 5, before_simple_read_from_buffer,
                  after_simple_read_from_buffer, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find simple_read_from_buffer, status hook will use direct user copy fallback\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("sel_read_handle_status");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        selinux_hook_dbg("[selinux_hook] hook sel_read_handle_status argc=4\n");
        hook_wrap((void *)addr, 4, before_sel_read_handle_status,
                  after_sel_read_handle_status, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find sel_read_handle_status, status read hook skipped\n");
    }

    /* Hook the mmap handler; Android libselinux uses mmap() not read(). */
    addr = (unsigned long)lookup_name_optional_suffix("sel_mmap_handle_status");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        selinux_hook_dbg("[selinux_hook] hook sel_mmap_handle_status argc=2\n");
        hook_wrap((void *)addr, 2, NULL, after_sel_mmap_handle_status, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find sel_mmap_handle_status, status mmap patch skipped\n");
    }

    if (!security_load_policy_fn) {
        pr_warn("[selinux_hook] cannot find security_load_policy, deferred clean policy capture disabled\n");
    } else if (!READ_ONCE(g_clean_policy_blob)) {
        g_funcs[g_hooks++] = (void *)security_load_policy_fn;
        pr_info("[selinux_hook] hook security_load_policy argc=3 for deferred Magisk policy capture\n");
        hook_wrap((void *)security_load_policy_fn, 3,
                  before_security_load_policy, after_security_load_policy, NULL);
    } else {
        selinux_hook_dbg("[selinux_hook] security_load_policy capture skipped; clean policy already loaded\n");
    }

    /* 6.6 (>= 5.4): security_setprocattr(lsm, name, value, size) — 4 args. */
    addr = (unsigned long)lookup_name_optional_suffix("security_setprocattr");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        selinux_hook_dbg("[selinux_hook] hook security_setprocattr argc=4\n");
        hook_wrap((void *)addr, 4, before_security_setprocattr, NULL, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find security_setprocattr\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("selinux_setprocattr");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        selinux_hook_dbg("[selinux_hook] hook selinux_setprocattr argc=3\n");
        hook_wrap((void *)addr, 3, before_selinux_setprocattr, NULL, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find selinux_setprocattr\n");
    }

    rc = install_write_op_hooks();
    if (rc) {
        uninstall_inline_hooks();
        return rc;
    }

    /* policydb redirect hooks (6.6 uses the 6-arg redirect path). */
    addr = (unsigned long)lookup_name_optional_suffix("context_struct_compute_av");
    if (!addr)
        addr = (unsigned long)lookup_name_numbered_suffix("context_struct_compute_av");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        pr_info("[selinux_hook] hook context_struct_compute_av argc=6\n");
        hook_wrap((void *)addr, 6, before_context_struct_compute_av_policydb,
                  after_context_struct_compute_av_policydb, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find context_struct_compute_av\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("string_to_context_struct");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        pr_info("[selinux_hook] hook string_to_context_struct argc=5\n");
        hook_wrap((void *)addr, 5, before_policydb_arg0, NULL, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find string_to_context_struct\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("selinux_complete_init");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        pr_info("[selinux_hook] hook selinux_complete_init argc=0\n");
        hook_wrap((void *)addr, 0, NULL, after_selinux_complete_init, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find selinux_complete_init\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("selinux_policy_commit");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        pr_info("[selinux_hook] hook selinux_policy_commit argc=1\n");
        hook_wrap((void *)addr, 1, NULL, after_selinux_policy_commit, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find selinux_policy_commit\n");
    }

    selinux_hook_dbg("[selinux_hook] %d hooks installed\n", g_hooks);
    return 0;
}

void susfs_selinux_hook_exit(void)
{
    uninstall_inline_hooks();
    g_policy_capture_in_progress = false;

    if (READ_ONCE(g_clean_policydb_direct) && g_clean_policydb) {
        if (policydb_destroy_fn)
            policydb_destroy_fn((struct policydb *)g_clean_policydb);
        if (susfs_vfree)
            susfs_vfree(g_clean_policydb);
        g_clean_policydb = NULL;
        g_clean_policydb_direct = false;
    }

    if (g_clean_load_state_ready && selinux_policy_cancel_fn) {
        call_selinux_policy_cancel(&g_clean_load_state);
        g_clean_load_state_ready = false;
        g_clean_load_state.policy = NULL;
        g_clean_load_state.convert_data = NULL;
        g_clean_policydb = NULL;
        g_clean_policydb_direct = false;
    }

    if (g_clean_policy_blob) {
        if (susfs_vfree)
            susfs_vfree(g_clean_policy_blob);
        g_clean_policy_blob = NULL;
        g_clean_policy_len = 0;
    }

    if (g_policy_read_cache) {
        if (susfs_vfree)
            susfs_vfree(g_policy_read_cache);
        g_policy_read_cache = NULL;
        g_policy_read_cache_len = 0;
        g_policy_read_cache_src = NULL;
    }

    selinux_hook_dbg("[selinux_hook] exited\n");
}

int susfs_selinux_hook_get_mode(char *out, int outlen)
{
    sel_hook_state_t state;
    const char *state_str;
    int copied;
    size_t len;

    if (!out || outlen <= 0)
        return -EINVAL;

    state = module_get_working_mode();
    switch (state) {
    case SEL_HOOK_STATE_NORMAL_K:
        state_str = "NORMAL-K";
        break;
    case SEL_HOOK_STATE_PARTIAL_FALLBACK:
        state_str = "PARTIAL_FALLBACK";
        break;
    case SEL_HOOK_STATE_FULL_FALLBACK:
        state_str = "FULL_FALLBACK";
        break;
    default:
        state_str = "UNKNOWN";
        break;
    }

    len = str_len_safe(state_str);
    if ((int)len >= outlen)
        return -EINVAL;

    copied = compat_copy_to_user(out, state_str, (int)len);
    if (copied != (int)len)
        return -EFAULT;

    return (int)len;
}

/* Returns 1 if the selinux hooks were successfully installed and the
 * module is actively filtering SELinux queries (any non-FULL_FALLBACK
 * mode).  Used by the ctl0 dispatcher to answer "is selinux_hook on?". */
int susfs_selinux_hook_is_active(void)
{
    sel_hook_state_t state = module_get_working_mode();
    return state != SEL_HOOK_STATE_FULL_FALLBACK;
}
