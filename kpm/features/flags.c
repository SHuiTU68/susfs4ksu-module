// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * flags - global KPM toggles: enable_log, enable_avc_log_spoofing.
 *
 * Pure state, no hooks.  Other features consult these via the getters.
 *
 * avc_log_spoofing: the flag is recorded here and surfaced to dmesg so the
 * toggle is verifiable end-to-end (WebUI -> CLI -> KPM).  Full in-kernel
 * rewriting of AVC audit tcontext strings requires struct audit_buffer
 * internals this KPM doesn't have; the flag is honoured as advisory state
 * and logged so users can confirm it changed.  enable_log toggles susfs
 * debug output.
 */
#include <linux/spinlock.h>

#include "../include/susfs_kpm.h"

static int log_enabled = 0;
static int avc_log_spoofing_enabled = 0;
static DEFINE_SPINLOCK(flags_lock);

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
        susfs_printk("susfs_kpm: avc_log_spoofing=%d (advisory)\n",
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
