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

# Feature list from the KPM — needed to guard calls to features this KPM
# does NOT implement (try_umount, sus_su, auto_add_try_umount).  When the
# feature is absent we skip the call instead of letting ksu_susfs fail.
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

# Check and process try_umount paths
# try_umount is NOT implemented in this KPM — the grep guard skips the call
# silently.  (On susfs v2.0+ kernels with a patched apd, the fallback to
# `apd kernel umount add` would go here, but stock apd has no such command.)
if echo "$susfs_features" | grep -q "CONFIG_KSU_SUSFS_TRY_UMOUNT"; then
    if grep -v "#" "$PERSISTENT_DIR/try_umount.txt" > /dev/null; then
        grep -v "#" "$PERSISTENT_DIR/try_umount.txt" | while read -r i; do
            [ -z "$i" ] || { ${SUSFS_BIN} add_try_umount "$i" 1 && echo "[try_umount]: susfs4ksu/post-mount $i" >> "$logfile1"; }
        done
    fi
fi

# SUSFS Logging
dmesg_snapshot=$(dmesg)
echo "$dmesg_snapshot" | sed -n "/^\[ *$post_fs_data/,\$p" | grep -iE "susfs_auto_add|ksu_susfs|susfs:" >> $logfile
endmsg=$(echo "$dmesg_snapshot" | grep -E '^\[ *[0-9]' | cut -d']' -f1 | sed 's/^\[ *//' | cut -d' ' -f1 | tail -n 1)
echo "post_mount=$endmsg" >> $tmpfolder/logs/boot_stage_time.sh
# EOF
