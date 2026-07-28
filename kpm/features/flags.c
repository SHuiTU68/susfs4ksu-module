// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * flags - global KPM toggles: enable_log, enable_avc_log_spoofing.
 *
 * Pure state, no hooks.  Other features consult these via the getters.
 */
#include <linux/spinlock.h>

#include "../include/susfs_kpm.h"

static int log_enabled = 0;
static int avc_log_spoofing_enabled = 0;
static DEFINE_SPINLOCK(flags_lock);

int susfs_set_log_enabled(int enabled)
{
    spin_lock(&flags_lock);
    log_enabled = enabled ? 1 : 0;
    spin_unlock(&flags_lock);
    return 0;
}

int susfs_set_avc_log_spoofing(int enabled)
{
    spin_lock(&flags_lock);
    avc_log_spoofing_enabled = enabled ? 1 : 0;
    spin_unlock(&flags_lock);
    return 0;
}

int susfs_get_log_enabled(void)
{
    int v;
    spin_lock(&flags_lock);
    v = log_enabled;
    spin_unlock(&flags_lock);
    return v;
}

int susfs_get_avc_log_spoofing(void)
{
    int v;
    spin_lock(&flags_lock);
    v = avc_log_spoofing_enabled;
    spin_unlock(&flags_lock);
    return v;
}
