// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * set_cmdline - spoof /proc/cmdline (non-gki) or /proc/bootconfig (gki).
 *
 * Holds the fake content in kernel memory.  Hooks proc_cmdline_read /
 * proc_bootconfig_read (or whichever seq_read the procfs entry uses) and
 * returns the fake content instead.
 *
 * For android15-6.6 (GKI), the relevant file is /proc/bootconfig; on
 * non-gki it is /proc/cmdline.  We try both symbol names.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <log.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

#include "../include/susfs_kpm.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

static char *fake_content;
static int  fake_content_len;
static void *cmdline_read_addr;

static void before_cmdline_read(hook_fargs4_t *args, void *udata)
{
    /* TODO: replace copy_to_user of buf with our fake_content.  The seq_file
     * read path makes this trickier than uname — typically easier to hook
     * the seq_show callback and override the seq_printf.  Stub for now. */
    (void)args;
    (void)udata;
}

int susfs_set_cmdline_or_bootconfig(const char *content)
{
    if (!content) return -EINVAL;
    int len = 0;
    while (content[len] && len < SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE - 1)
        len++;

    if (fake_content) {
        susfs_kfree(fake_content);
        fake_content = 0;
        fake_content_len = 0;
    }
    /* kzalloc zero-initialises, so the buffer is already NUL-terminated
     * at [len] after we copy the content. */
    fake_content = (char *)susfs_kzalloc(len + 1, SUSFS_GFP_KERNEL);
    if (!fake_content) return -ENOMEM;
    susfs_memcpy(fake_content, content, len);
    fake_content[len] = '\0';
    fake_content_len = len;
    logki("susfs_kpm: set_cmdline_or_bootconfig: %d bytes\n", len);
    return 0;
}

int susfs_set_cmdline_init_hooks(void)
{
    /* before_cmdline_read is an empty stub.  Hooking cmdline_proc_show
     * (fired on every /proc/cmdline read) just to do nothing adds a
     * trampoline tax.  Skip until the real spoofing logic is implemented. */
    cmdline_read_addr = (void *)kallsyms_lookup_name("cmdline_proc_show");
    if (!cmdline_read_addr)
        cmdline_read_addr = (void *)kallsyms_lookup_name("boot_config_show");
    if (cmdline_read_addr) {
        logki("susfs_kpm: set_cmdline: show symbol found @ %px "
              "(not hooked — callback is a stub)\n", cmdline_read_addr);
    } else {
        logki("susfs_kpm: set_cmdline: no show symbol (inert)\n");
    }
    return 0;
}

void susfs_set_cmdline_cleanup(void)
{
    /* No hook installed — nothing to unhook. */
    cmdline_read_addr = 0;
    if (fake_content) {
        susfs_kfree(fake_content);
        fake_content = 0;
        fake_content_len = 0;
    }
}
