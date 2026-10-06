// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * set_cmdline - spoof /proc/cmdline (non-GKI) or /proc/bootconfig (GKI).
 *
 * WHAT NATIVE SUSFS DOES
 * ----------------------
 * kernel_patches/fs/susfs.c (v2.3.0) + patch in fs/proc/bootconfig.c:
 *   - susfs_set_cmdline_or_bootconfig() stores the fake buffer and enables
 *     susfs_is_fake_cmdline_or_bootconfig_buffer_set (a static key).
 *   - susfs_spoof_cmdline_or_bootconfig(struct seq_file *m) does
 *     seq_puts(m, fake_cmdline_or_bootconfig), and boot_config_proc_show() is
 *     patched to call it instead of seq_puts(saved_boot_config) when the key
 *     is on.  (On GKI 6.6 the file is /proc/bootconfig, backed by
 *     fs/proc/bootconfig.c:boot_config_proc_show(); /proc/cmdline is backed
 *     by fs/proc/cmdline.c:cmdline_proc_show().)
 *
 * WHAT THIS KPM DOES
 * ------------------
 * Both proc files are seq_files whose show() callback simply prints a kernel
 * string into the seq buffer:
 *
 *   static int  cmdline_proc_show(struct seq_file *m, void *v)
 *       { seq_puts(m, saved_command_line); seq_putc(m, '\n'); return 0; }
 *   static int  boot_config_proc_show(struct seq_file *m, void *v)
 *       { if (saved_boot_config) seq_puts(m, saved_boot_config); return 0; }
 *
 * So instead of calling seq_puts() (another kallsyms symbol to resolve), the
 * hook writes the fake text directly into m->buf/m->count — byte for byte
 * what seq_puts() does (fs/seq_file.c: seq_write()) — and skips the original
 * callback.  No patched kernel, no seq_puts dependency.
 *
 * If the fake content does not fit in the seq buffer, we still skip the
 * original: a truncated/empty read leaks nothing about the real cmdline,
 * whereas falling through would expose it.  (Upstream has the same outcome:
 * seq_puts() fails silently, leaving count at 0 → the read returns EOF.)
 *
 * Like upstream, the substitution applies to every reader (the feature's
 * whole point is that the *real* cmdline is never visible to anyone).
 */
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <log.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <uapi/asm-generic/errno.h>

#include "../include/susfs_kpm.h"
#include "../include/susfs_offsets.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

static char fake_content[SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE];
static int  fake_content_len;      /* 0 => feature off */
static DEFINE_SPINLOCK(set_cmdline_lock);

static void *boot_config_proc_show_addr;
static void *cmdline_proc_show_addr;

/* int boot_config_proc_show(struct seq_file *m, void *v)
 * int cmdline_proc_show(struct seq_file *m, void *v) */
static void before_cmdline_show(hook_fargs2_t *args, void *udata)
{
    void *m = (void *)args->arg0;
    int add_nl;

    if (fake_content_len <= 0) return;

    /* /proc/cmdline is a single line; /proc/bootconfig is multi-line text.
     * append a newline unless the fake string already ends with one (both
     * files are line oriented as far as readers are concerned). */
    add_nl = (fake_content[fake_content_len - 1] != '\n') ? 1 : 0;

    kpm_seq_append(m, fake_content, fake_content_len, add_nl);

    /* Own the output either way: never let the real cmdline/bootconfig
     * through.  If the append failed the read returns EOF (count == 0),
     * which is what upstream ends up doing as well. */
    args->skip_origin = 1;
    args->ret = 0;
    (void)udata;
}

int susfs_set_cmdline_or_bootconfig(const char *content)
{
    int len;

    if (!content) return -EINVAL;
    len = kpm_strlen_max(content, SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE - 1);
    if (len <= 0) return -EINVAL;

    susfs__raw_spin_lock(&set_cmdline_lock);
    susfs_memcpy(fake_content, content, len);
    fake_content[len] = '\0';
    fake_content_len = len;
    susfs__raw_spin_unlock(&set_cmdline_lock);

    logki("susfs_kpm: set_cmdline_or_bootconfig: %d bytes\n", len);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: set_cmdline_or_bootconfig len=%d\n", len);
    }
    return 0;
}

int susfs_set_cmdline_init_hooks(void)
{
    hook_err_t err;
    hook_err_t (*wrap)(void *, int32_t, void *, void *, void *) = hook_wrap;
    HIDE_PTR(wrap);

    /* GKI 6.6: /proc/bootconfig */
    boot_config_proc_show_addr =
        (void *)susfs_ksym("boot_config_proc_show");
    if (boot_config_proc_show_addr) {
        err = wrap(boot_config_proc_show_addr, 2, (void *)before_cmdline_show,
                   0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: set_cmdline: hook boot_config_proc_show "
                  "failed: %d\n", err);
            boot_config_proc_show_addr = 0;
        }
    }

    /* non-GKI: /proc/cmdline */
    cmdline_proc_show_addr = (void *)susfs_ksym("cmdline_proc_show");
    if (cmdline_proc_show_addr) {
        err = wrap(cmdline_proc_show_addr, 2, (void *)before_cmdline_show, 0, 0);
        if (err != HOOK_NO_ERR) {
            logke("susfs_kpm: set_cmdline: hook cmdline_proc_show failed: %d\n",
                  err);
            cmdline_proc_show_addr = 0;
        }
    }

    logki("susfs_kpm: set_cmdline: hookable bootconfig=%d cmdline=%d\n",
          boot_config_proc_show_addr != 0, cmdline_proc_show_addr != 0);
    if (susfs_printk) {
        susfs_printk("susfs_kpm: set_cmdline=%d (bootconfig=%d cmdline=%d)\n",
                     (boot_config_proc_show_addr != 0 ||
                      cmdline_proc_show_addr != 0),
                     boot_config_proc_show_addr != 0,
                     cmdline_proc_show_addr != 0);
    }
    return 0;
}

void susfs_set_cmdline_cleanup(void)
{
    void (*un)(void *, void *, void *, int) = hook_unwrap_remove;
    HIDE_PTR(un);

    if (boot_config_proc_show_addr) {
        un(boot_config_proc_show_addr, (void *)before_cmdline_show, 0, 1);
        boot_config_proc_show_addr = 0;
    }
    if (cmdline_proc_show_addr) {
        un(cmdline_proc_show_addr, (void *)before_cmdline_show, 0, 1);
        cmdline_proc_show_addr = 0;
    }
    fake_content_len = 0;
}