// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * set_uname - spoof uname() release/version strings globally.
 *
 * Hook __NR_uname (160 on arm64) with an AFTER callback.  After the kernel
 * fills the user struct new_utsname, we overwrite the release and version
 * fields with spoofed values via compat_copy_to_user.
 *
 * struct new_utsname layout (UAPI-stable, see <linux/utsname.h>):
 *   char sysname[65];      offset 0
 *   char nodename[65];     offset 65
 *   char release[65];      offset 130
 *   char version[65];      offset 195
 *   char machine[65];      offset 260
 *   char domainname[65];   offset 325
 */
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <log.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <syscall.h>
#include <kputils.h>

#include "../include/susfs_kpm.h"

#define HIDE_PTR(p) __asm__("" : "=r"(p) : "0"(p))

#define NEW_UTSNAME_FIELD_LEN 65
#define RELEASE_OFFSET  (NEW_UTSNAME_FIELD_LEN * 2)  /* sysname + nodename */
#define VERSION_OFFSET  (NEW_UTSNAME_FIELD_LEN * 3)  /* + release */

static char spoof_release[__NEW_UTS_LEN + 1];
static char spoof_version[__NEW_UTS_LEN + 1];
static int  spoof_release_set = 0;
static int  spoof_version_set = 0;

static void after_uname(hook_fargs1_t *args, void *udata)
{
    /* If the original syscall failed, leave the buffer alone. */
    if ((long)args->ret != 0) return;

    /* arg0 holds the user buffer pointer (under ARCH_HAS_SYSCALL_WRAPPER,
     * args->arg0 is actually the pt_regs *; use syscall_argn() to deref). */
    unsigned long user_buf = syscall_argn(args, 0);
    if (!user_buf) return;

    char __user *release_field = (char __user *)(user_buf + RELEASE_OFFSET);
    char __user *version_field = (char __user *)(user_buf + VERSION_OFFSET);

    if (spoof_release_set) {
        int len = 0;
        while (spoof_release[len] && len < __NEW_UTS_LEN) len++;
        /* write spoofed value + NUL terminator, do not overflow field */
        compat_copy_to_user(release_field, spoof_release, len + 1);
        /* zero the rest of the 65-byte field for safety */
        char zero = '\0';
        for (int i = len + 1; i < NEW_UTSNAME_FIELD_LEN; i++) {
            compat_copy_to_user(release_field + i, &zero, 1);
        }
    }
    if (spoof_version_set) {
        int len = 0;
        while (spoof_version[len] && len < __NEW_UTS_LEN) len++;
        compat_copy_to_user(version_field, spoof_version, len + 1);
        char zero = '\0';
        for (int i = len + 1; i < NEW_UTSNAME_FIELD_LEN; i++) {
            compat_copy_to_user(version_field + i, &zero, 1);
        }
    }
    (void)udata;
}

int susfs_set_uname(const char *release, const char *version)
{
    if (!release || !version) return -EINVAL;
    if (strcmp(release, "default") != 0) {
        int i = 0;
        while (release[i] && i < __NEW_UTS_LEN) {
            spoof_release[i] = release[i];
            i++;
        }
        spoof_release[i] = '\0';
        spoof_release_set = 1;
    } else {
        spoof_release_set = 0;
    }
    if (strcmp(version, "default") != 0) {
        int i = 0;
        while (version[i] && i < __NEW_UTS_LEN) {
            spoof_version[i] = version[i];
            i++;
        }
        spoof_version[i] = '\0';
        spoof_version_set = 1;
    } else {
        spoof_version_set = 0;
    }
    logki("susfs_kpm: set_uname: release=%s version=%s\n",
          spoof_release_set ? spoof_release : "(default)",
          spoof_version_set ? spoof_version : "(default)");
    return 0;
}

int susfs_set_uname_init_hooks(void)
{
    /* __NR_uname on arm64 is 160 (see <uapi/asm-generic/unistd.h>).
     * The kernel's __arm64_sys_uname takes one arg: struct new_utsname __user*. */
    hook_err_t err = hook_syscalln(__NR_uname, 1, 0, (void *)after_uname, 0);
    if (err != HOOK_NO_ERR) {
        logke("susfs_kpm: uname syscall hook failed: %d\n", err);
        return (int)err;
    }
    logki("susfs_kpm: hooked uname syscall (after)\n");
    return 0;
}

void susfs_set_uname_cleanup(void)
{
    unhook_syscalln(__NR_uname, 0, (void *)after_uname);
    spoof_release_set = 0;
    spoof_version_set = 0;
}
