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

# to add mounts
# echo "/system" >> /data/adb/susfs4ksu/sus_mount.txt
# this'll make it easier for the webui to do stuff
# Check and process sus_mount paths
if echo "$susfs_features" | grep -q "CONFIG_KSU_SUSFS_SUS_MOUNT"; then
    if grep -v "#" "$PERSISTENT_DIR/sus_mount.txt" > /dev/null; then
        grep -v "#" "$PERSISTENT_DIR/sus_mount.txt" | while read -r i; do
            [ -z "$i" ] || { ${SUSFS_BIN} add_sus_mount "$i" && echo "[sus_mount]: susfs4ksu/post-mount $i" >> "$logfile1"; }
        done
    fi
fi

# ===== try_umount — the "another way" for APatch =====
# Upstream susfs detaches the vfsmount in-kernel; this KPM can't do that
# safely (no struct mount internals).  Instead we use a hybrid approach:
#   1. Tell the KPM about the path (add_try_umount) so it can hide it from
#      /proc/mounts for non-su readers via the show_mountinfo hook.
#   2. Actually detach the mount HERE via `umount -l` in the init mount
#      namespace, which zygote-spawned apps inherit.  This is the real
#      "sus mount hiding" effect.
# This runs in post-mount (late_start service) so the mounts are already
# up; `umount -l` (lazy) avoids EBUSY from open files.
if echo "$susfs_features" | grep -q "CONFIG_KSU_SUSFS_TRY_UMOUNT"; then
    # (a) Explicit paths from try_umount.txt
    if grep -v "#" "$PERSISTENT_DIR/try_umount.txt" > /dev/null; then
        grep -v "#" "$PERSISTENT_DIR/try_umount.txt" | while read -r i; do
            [ -z "$i" ] && continue
            ${SUSFS_BIN} add_try_umount "$i" 1 2>/dev/null
            umount -l "$i" 2>/dev/null && echo "[try_umount]: susfs4ksu/post-mount umount $i" >> "$logfile1"
        done
    fi
    # (b) Auto-add default module mounts — controlled by the WebUI toggle
    #     which creates/removes the sentinel file
    #     /data/adb/susfs_no_auto_add_sus_ksu_default_mount.
    #     When the sentinel is ABSENT (auto-add ON), we umount the standard
    #     APatch/module overlay mounts so apps can't see them.
    if [ ! -f /data/adb/susfs_no_auto_add_sus_ksu_default_mount ]; then
        echo "[auto_mount]: auto-adding default module mounts" >> "$logfile1"
        for def_mnt in \
            /data/adb/modules \
            /data/adb/ap \
            /data/adb/ksu \
            /debug_ramdisk
        do
            # umount any mount whose source is under def_mnt
            awk -v s="$def_mnt" '$1 ~ s {print $2}' /proc/mounts 2>/dev/null | while read -r mp; do
                [ -z "$mp" ] && continue
                case "$mp" in
                    /|/proc|/sys|/dev|/data|/system|/vendor|/apex|/mnt/*) continue ;;
                esac
                ${SUSFS_BIN} add_try_umount "$mp" 1 2>/dev/null
                umount -l "$mp" 2>/dev/null && echo "[auto_mount]: umount $mp" >> "$logfile1"
            done
        done
    fi
    # (c) Auto-detect suspicious bind mounts — controlled by the WebUI
    #     toggle which creates/removes the sentinel file
    #     /data/adb/susfs_no_auto_add_sus_bind_mount.
    if [ ! -f /data/adb/susfs_no_auto_add_sus_bind_mount ] || \
       [ "$auto_bind" = "1" ] || [ "$auto_umount_bind" = "1" ] || [ "$auto_try_umount" = "1" ]; then
        echo "[auto_bind]: scanning /proc/mounts for suspicious bind mounts" >> "$logfile1"
        ${SUSFS_BIN} auto_add_try_umount_for_bind_mount 2>/dev/null
        for suspect in \
            /data/adb/modules \
            /data/adb/ap \
            /data/adb/ksu \
            /debug_ramdisk \
            /sbin
        do
            grep -v "#" "$PERSISTENT_DIR/try_umount.txt" 2>/dev/null | grep -q "^${suspect}\$" && continue
            awk -v s="$suspect" '$1 ~ s {print $2}' /proc/mounts 2>/dev/null | while read -r mp; do
                [ -z "$mp" ] && continue
                case "$mp" in
                    /|/proc|/sys|/dev|/data|/system|/vendor|/apex|/mnt/*) continue ;;
                esac
                ${SUSFS_BIN} add_try_umount "$mp" 1 2>/dev/null
                umount -l "$mp" 2>/dev/null && echo "[auto_bind]: umount $mp" >> "$logfile1"
            done
        done
    fi
fi

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
