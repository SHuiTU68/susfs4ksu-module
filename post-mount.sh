#!/bin/sh
MODDIR=/data/adb/modules/susfs4ksu
SUSFS_BIN=/data/adb/ap/bin/ksu_susfs
. ${MODDIR}/utils.sh
PERSISTENT_DIR=/data/adb/susfs4ksu
tmpfolder=/data/adb/ap/susfs4ksu
logfile="$tmpfolder/logs/susfs.log"
logfile1="$tmpfolder/logs/susfs1.log"

# Mount folder of susfs4ksu
[ -w /mnt ] && mntfolder=/mnt/susfs4ksu
[ -w /mnt/vendor ] && mntfolder=/mnt/vendor/susfs4ksu

post_fs_data=0
[ -f $tmpfolder/logs/boot_stage_time.sh ] && . $tmpfolder/logs/boot_stage_time.sh

# auto-hide toggles (written by the WebUI into config.sh).  Defaults here
# keep the script safe when config.sh hasn't been populated yet.
auto_mount=0
auto_bind=0
auto_umount_bind=0
auto_try_umount=0
force_hide_lsposed=0
[ -f $PERSISTENT_DIR/config.sh ] && . $PERSISTENT_DIR/config.sh

# Feature list from the KPM — needed to guard calls to features this KPM
# does NOT implement (sus_su).  try_umount / auto_add_try_umount ARE now
# supported via a hybrid approach (KPM records the list, this script does
# the actual `umount -l` in the init mount namespace).
susfs_features=$(${SUSFS_BIN} show enabled_features 2>/dev/null)
# Fallback: if show enabled_features fails (KPM not loaded, syscall channel
# not working, dmesg rotated, etc.), default to the builtin feature list.
# This ensures the try_umount and sus_mount blocks below still run, because
# this KPM always supports these features (hybrid userspace implementation).
if [ -z "$susfs_features" ] || ! echo "$susfs_features" | grep -q "CONFIG_KSU_SUSFS_SUS_MOUNT"; then
    susfs_features="CONFIG_KSU_SUSFS_SUS_PATH
CONFIG_KSU_SUSFS_SUS_MOUNT
CONFIG_KSU_SUSFS_SUS_KSTAT
CONFIG_KSU_SUSFS_OPEN_REDIRECT
CONFIG_KSU_SUSFS_SUS_MAP
CONFIG_KSU_SUSFS_SPOOF_UNAME
CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
CONFIG_KSU_SUSFS_ENABLE_LOG
CONFIG_KSU_SUSFS_ENABLE_AVC_LOG_SPOOFING
CONFIG_KSU_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS
CONFIG_KSU_SUSFS_TRY_UMOUNT
CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT"
fi

# ===== sus_mount / try_umount — umount is done in post-fs-data.sh =====
# The actual `umount -l` MUST run in post-fs-data.sh (BEFORE zygote) so apps
# never inherit the hidden mounts.  This script (late_start service, AFTER
# zygote) only re-registers paths with the KPM for /proc/mounts filtering
# and handles force_hide_lsposed (which needs apex mounts to be up first).

# force_hide_lsposed — detach LSPosed's dex2oat overlay mounts so the stock
# binary is used.  post-fs-data.sh already registered them via add_try_umount
# (KPM records for /proc/mounts filtering); here we actually umount them now
# that the apex mounts are up.
if [ "$force_hide_lsposed" = "1" ] && echo "$susfs_features" | grep -q "CONFIG_KSU_SUSFS_TRY_UMOUNT"; then
    for dex2oat in \
        /system/apex/com.android.art/bin/dex2oat \
        /system/apex/com.android.art/bin/dex2oat32 \
        /system/apex/com.android.art/bin/dex2oat64 \
        /apex/com.android.art/bin/dex2oat \
        /apex/com.android.art/bin/dex2oat32 \
        /apex/com.android.art/bin/dex2oat64
    do
        umount -l "$dex2oat" 2>/dev/null && echo "[force_hide_lsposed]: umount $dex2oat" >> "$logfile1"
    done
fi

# SUSFS Logging
dmesg_snapshot=$(dmesg)
echo "$dmesg_snapshot" | sed -n "/^\[ *$post_fs_data/,\$p" | grep -iE "susfs_auto_add|ksu_susfs|susfs:|susfs_kpm:" >> $logfile
endmsg=$(echo "$dmesg_snapshot" | grep -E '^\[ *[0-9]' | cut -d']' -f1 | sed 's/^\[ *//' | cut -d' ' -f1 | tail -n 1)
echo "post_mount=$endmsg" >> $tmpfolder/logs/boot_stage_time.sh
# EOF
