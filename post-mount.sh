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

# Reuse the dmesg cache from post-fs-data.sh instead of calling
# `ksu_susfs show enabled_features` (forks a process + parses dmesg).
dmesg_cache="$tmpfolder/logs/dmesg_cache.txt"
if [ ! -f "$dmesg_cache" ]; then
	dmesg 2>/dev/null > "$dmesg_cache"
fi
susfs_features=""
if [ -f "$dmesg_cache" ]; then
	_fline=$(grep 'susfs_kpm: features=' "$dmesg_cache" | tail -1)
	[ -n "$_fline" ] && susfs_features=$(echo "$_fline" | sed 's/.*features=//' | tr ',' '\n')
fi
# Fallback: if show enabled_features fails (KPM not loaded, syscall channel
# not working, dmesg rotated, etc.), default to the builtin feature list.
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
CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT"
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

# ===== sus_mount auto-discovery (late_start) =====
# Module bind mounts (IMS_VAROS, PUIThemeCustomized, zygisk_lsposed, ...)
# show their source path in the mountinfo *root* field, fs-relative to /data:
#     root=/adb/modules/IMS_VAROS/MODS/... point=/vendor/etc/xgf.cfg
# Detection tools grep for the "/adb/modules" token and for Magisk-style
# mount records, so every such mount point is registered with the KPM
# (hide-only: the mount stays alive for root, only the app view is filtered).
# This runs at late_start, i.e. after all other modules have mounted.
if [ "$hide_sus_mnts_for_all_or_non_su_procs" -ge 1 ] 2>/dev/null &&
   echo "$susfs_features" | grep -q "CONFIG_KSU_SUSFS_SUS_MOUNT"; then
    # (re-)arm the KPM hide hook: with config value 2 boot-completed.sh turns
    # hiding off again, and then no registered entry has any effect.
    ${SUSFS_BIN} hide_sus_mnts_for_all_procs 1 >/dev/null 2>&1 || \
        ${SUSFS_BIN} hide_sus_mnts_for_non_su_procs 1 >/dev/null 2>&1
    _sus_mp_list=$(grep -E '/adb/modules|/data/adb/(modules|ap|ksu)|lowerdir=/data/adb|upperdir=/data/adb' \
        /proc/self/mountinfo 2>/dev/null | awk '{print $5}' | sort -u)
    _sus_mp_count=0
    for _mp in $_sus_mp_list; do
        [ -z "$_mp" ] && continue
        case "$_mp" in
            /proc/*|/sys/*|/dev/*) continue ;;   # never hide core pseudo fs
        esac
        ${SUSFS_BIN} add_sus_mount "$_mp" >/dev/null 2>&1 && {
            _sus_mp_count=$((_sus_mp_count + 1))
            echo "[sus_mount]: auto(late) $_mp" >> "$logfile1"
        }
    done
    echo "[sus_mount]: late auto-discovery registered $_sus_mp_count mount point(s)" >> "$logfile1"
fi

# SUSFS Logging — reuse the dmesg cache (refreshed above if missing).
grep -iE "susfs_auto_add|ksu_susfs|susfs:|susfs_kpm:" "$dmesg_cache" >> $logfile
endmsg=$(grep -E '^\[ *[0-9]' "$dmesg_cache" | tail -n 1 | sed 's/^\[ *//; s/\].*//')
echo "post_mount=$endmsg" >> $tmpfolder/logs/boot_stage_time.sh
# EOF
