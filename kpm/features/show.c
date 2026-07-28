// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * show - return KPM identity / enabled features / variant to userspace.
 *
 * These never touch the kernel — pure state, formatted into the out_msg
 * buffer the caller provided via sc_kpm_control().
 */
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

#include "../include/susfs_kpm.h"

int susfs_show_version(char *out, int outlen)
{
    if (!out || outlen <= 0) return -EINVAL;
    /* Mirror upstream susfs version string format: "v<major>.<minor>.<patch>" */
    const char *v = "v" SUSFS_KPM_VERSION;
    int i = 0;
    while (v[i] && i < outlen - 1) { out[i] = v[i]; i++; }
    out[i] = '\0';
    return 0;
}

int susfs_show_enabled_features(char *out, int outlen)
{
    if (!out || outlen <= 0) return -EINVAL;
    /* Single newline-separated feature list using the upstream CONFIG_KSU_SUSFS_*
     * names so the existing module scripts (service.sh, boot-completed.sh,
     * etc.) grep checks work unchanged.  Features not implemented by this KPM
     * (sus_su, try_umount, auto_add_try_umount_for_bind_mount) are deliberately
     * absent so the scripts correctly skip them. */
    static const char features[] =
        "CONFIG_KSU_SUSFS_SUS_PATH\n"
        "CONFIG_KSU_SUSFS_SUS_MOUNT\n"
        "CONFIG_KSU_SUSFS_SUS_KSTAT\n"
        "CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
        "CONFIG_KSU_SUSFS_SUS_MAP\n"
        "CONFIG_KSU_SUSFS_SET_UNAME\n"
        "CONFIG_KSU_SUSFS_SPOOF_CMDLINE\n"
        "CONFIG_KSU_SUSFS_ENABLE_LOG\n"
        "CONFIG_KSU_SUSFS_ENABLE_AVC_LOG_SPOOFING\n"
        "CONFIG_KSU_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS\n";
    int i = 0;
    while (features[i] && i < outlen - 1) { out[i] = features[i]; i++; }
    out[i] = '\0';
    return 0;
}

int susfs_show_variant(char *out, int outlen)
{
    if (!out || outlen <= 0) return -EINVAL;
    const char *v = SUSFS_KPM_VARIANT;
    int i = 0;
    while (v[i] && i < outlen - 1) { out[i] = v[i]; i++; }
    out[i] = '\0';
    return 0;
}
