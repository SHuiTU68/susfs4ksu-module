#!/bin/sh
MODDIR=/data/adb/modules/susfs4ksu
SUSFS_BIN=/data/adb/ap/bin/ksu_susfs
. ${MODDIR}/utils.sh
PERSISTENT_DIR=/data/adb/susfs4ksu
tmpfolder=/data/adb/ap/susfs4ksu
mkdir -p $tmpfolder/logs
mkdir -p $tmpfolder
logfile="$tmpfolder/logs/susfs.log"
logfile1="$tmpfolder/logs/susfs1.log"

# Step 1: Cache dmesg ONCE — `dmesg` reads the entire kernel ring buffer
# and can take 0.5-2s per call.  We used to call it 4+ times (once here,
# then again inside each `ksu_susfs show` call).  Now we read it once
# into a temp file and grep from that.
#
# Performance: on OEM kernels (OPPO/OnePlus/etc.) the ring buffer can be
# several MB.  Writing the entire buffer to flash causes IO contention
# during early boot.  We pipe dmesg through grep to keep ONLY susfs-
# relevant lines — the cache file is typically < 2 KB instead of MBs.
# The timestamp pattern `^\[ *[0-9]` is preserved so boot-stage
# extraction still works.
dmesg_cache="$tmpfolder/logs/dmesg_cache.txt"
dmesg 2>/dev/null | grep -iE 'susfs:|susfs_kpm:|^\[ *[0-9]' > "$dmesg_cache"

kpm_in_dmesg=0
if grep -qE "susfs:|susfs_kpm:" "$dmesg_cache" 2>/dev/null; then
	kpm_in_dmesg=1
fi

# ksu_susfs show version/features/variant parse dmesg.  To avoid 3 more
# `dmesg` calls, we parse the cached output directly here.
susfs_features=""
version=""
if [ $kpm_in_dmesg -eq 1 ]; then
	# Parse features from dmesg cache: "features=CONFIG_...,CONFIG_..."
	_features_line=$(grep 'susfs_kpm: features=' "$dmesg_cache" | tail -1)
	if [ -n "$_features_line" ]; then
		susfs_features=$(echo "$_features_line" | sed 's/.*features=//' | tr ',' '\n')
	fi
	# Parse version from dmesg cache: "version=2.2.0"
	_version_line=$(grep 'susfs_kpm: version=' "$dmesg_cache" | tail -1)
	if [ -n "$_version_line" ]; then
		version=$(echo "$_version_line" | sed 's/.*version=//;s/ .*//')
	fi
fi
# Fallback: if show enabled_features fails, default to the builtin feature
# list so feature-gated blocks below still run.
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
# Fallback version if show version fails
if [ -z "$version" ]; then
	version="v2.2.0"
fi

# Parse version "v2.2.0" → MAIN=2 SUB=2 PATCH=0 using shell parameter
# expansion (no fork to sed/cut — saves 3 process spawns per script).
_ver=${version#v}            # strip leading 'v'
SUSFS_DECIMAL_MAIN=${_ver%%.*}
_rest=${_ver#*.}
SUSFS_DECIMAL_SUB=${_rest%%.*}
SUSFS_DECIMAL_PATCH=${_rest#*.}
SUSFS_DECIMAL_PATCH=${SUSFS_DECIMAL_PATCH%%.*}

# Mount folder of susfs4ksu
[ -w /mnt ] && mntfolder=/mnt/susfs4ksu
[ -w /mnt/vendor ] && mntfolder=/mnt/vendor/susfs4ksu
mkdir -p $mntfolder

# Determine whether the susfs KPM is actually loaded and reachable.
# Step 1 (dmesg) already told us if the KPM is loaded; step 2 (supercall)
# tells us if superkey extraction succeeded.  We set susfs_active if
# EITHER succeeds — the WebUI needs the flag to not show the "unsupported
# kernel" dialog even when superkey extraction is still pending.
diag_file="$tmpfolder/logs/susfs_diag.txt"
if [ -n "$version" ] || [ -n "$susfs_features" ]; then
	touch $tmpfolder/logs/susfs_active
	# Parse variant from dmesg cache instead of calling ksu_susfs again
	susfs_variant=$(grep 'susfs_kpm: version=' "$dmesg_cache" | tail -1 | sed 's/.*variant=//;s/ .*//')
	[ -z "$susfs_variant" ] && susfs_variant="GKI-APATCH"
	{
		echo "=== susfs4ksu/post-fs-data ==="
		echo "timestamp: $(date)"
		echo "status: ACTIVE"
		echo "version: $version"
		echo "variant: $susfs_variant"
		echo "features: $susfs_features"
	} > "$diag_file" 2>&1
elif [ $kpm_in_dmesg -eq 1 ]; then
	# KPM is loaded (dmesg) but `ksu_susfs show` couldn't parse it.
	# Still mark as active so the WebUI doesn't show "unsupported kernel".
	touch $tmpfolder/logs/susfs_active
	{
		echo "=== susfs4ksu/post-fs-data ==="
		echo "timestamp: $(date)"
		echo "status: ACTIVE (dmesg only — show parse failed)"
		echo "uid: $(id -u)"
		echo "dmesg_susfs: $(grep -iE 'susfs|susfs_kpm' "$dmesg_cache" | head -5)"
	} > "$diag_file" 2>&1
else
	# KPM not found in dmesg at all — not loaded.
	rm -f $tmpfolder/logs/susfs_active
	{
		echo "=== susfs4ksu/post-fs-data ==="
		echo "timestamp: $(date)"
		echo "status: FAILED (KPM not in dmesg)"
		echo "uid: $(id -u)"
		echo "hint: the KPM is not loaded — check that the boot image"
		echo "hint: has susfs_kpm embedded and KernelPatch is active"
	} > "$diag_file" 2>&1
fi

# for people that is on legacy with broken dmesg or disabled logging
# second, heres your override
# touch /data/adb/susfs4ksu/susfs_force_override
[ -f $PERSISTENT_DIR/susfs_force_override ] && touch $tmpfolder/logs/susfs_active

force_hide_lsposed=0
spoof_uname=0
umount_for_zygote_iso_service=0
avc_log_spoofing=0
hide_sus_mnts_for_all_or_non_su_procs=0
auto_try_umount=0
auto_mount=0
auto_bind=0
auto_umount_bind=0
skip_legit_mounts=0
turn_off_after_boot_completed=0
try_umount_zygote=0
[ -f $PERSISTENT_DIR/config.sh ] && . $PERSISTENT_DIR/config.sh

echo "susfs4ksu/post-fs-data: [logging_initialized]" > $logfile1

[ "$SUSFS_DECIMAL_MAIN" -ge 2 ] && [ -f /data/adb/ap/susfs4ksu/using_old_sus_path_layout ] && {
	echo "susfs4ksu/post-fs-data: Detected old sus path layout, removing the cache file for rechecking old and new sus_path layout" >> $logfile1
	rm -f /data/adb/ap/susfs4ksu/using_old_sus_path_layout
}

# Hide sus mounts for all processes
[ "$SUSFS_DECIMAL_MAIN" -ge 2 ] && { [ $hide_sus_mnts_for_all_or_non_su_procs -ge 1 ] && {
	${SUSFS_BIN} hide_sus_mnts_for_all_procs 1 >/dev/null && echo "[hide_sus_mnts_for_all_procs = 1]: susfs4ksu/post-fs-data" || {
		${SUSFS_BIN} hide_sus_mnts_for_non_su_procs 1 >/dev/null && echo "[hide_sus_mnts_for_non_su_procs = 1]: susfs4ksu/post-fs-data";
	}
} || {
	${SUSFS_BIN} hide_sus_mnts_for_all_procs 0 >/dev/null && echo "[hide_sus_mnts_for_all_procs = 0]: susfs4ksu/post-fs-data" || {
		${SUSFS_BIN} hide_sus_mnts_for_non_su_procs 0 >/dev/null && echo "[hide_sus_mnts_for_non_su_procs = 0]: susfs4ksu/post-fs-data";
	}
}; } >> $logfile1

#### Enable avc log spoofing to bypass 'su' domain detection via /proc/<pid> enumeration ####
[ $avc_log_spoofing = 1 ] && ${SUSFS_BIN} enable_avc_log_spoofing 1

# if spoof_uname is on mode 2, set_uname will be called here
[ $spoof_uname = 2 ] && spoof_uname
#### Enable sus_su ####
enable_sus_su_mode_1(){
  ## Here we manually create an system overlay an copy the sus_su and sus_su_drv_path to ${MODDIR}/system/bin after sus_su is enabled,
  ## as ksu overlay script is executed after all post-fs-data.sh scripts are finished

  rm -rf ${MODDIR}/system 2>/dev/null
  # Enable sus_su or abort the function if sus_su is not supported #
	if ! ${SUSFS_BIN} sus_su 1; then
		sed -i "s/^sus_su=.*/sus_su=-1/" ${PERSISTENT_DIR}/config.sh
		return
	fi
	# Enable sus_su or abort the function if sus_su is not supported #
	sed -i "s/^sus_su=.*/sus_su=1/" ${PERSISTENT_DIR}/config.sh
	sed -i "s/^sus_su_active=.*/sus_su_active=1/" ${PERSISTENT_DIR}/config.sh
	mkdir -p ${MODDIR}/system/bin 2>/dev/null
	# Copy the new generated sus_su_drv_path and 'sus_su' to /system/bin/ and rename 'sus_su' to 'su' #
	# On APatch the binaries live in /data/adb/ap/bin/; fall back to the KSU
	# path for compatibility with kernels that have both installed.
	SUS_SU_DIR=/data/adb/ap/bin
	[ -f ${SUS_SU_DIR}/sus_su ] || SUS_SU_DIR=/data/adb/ksu/bin
	cp -f ${SUS_SU_DIR}/sus_su ${MODDIR}/system/bin/su
	cp -f ${SUS_SU_DIR}/sus_su_drv_path ${MODDIR}/system/bin/sus_su_drv_path
	echo 1 > ${MODDIR}/sus_su_mode
	return
}
# uncomment it below to enable sus_su with mode 1 #
#enable_sus_su_mode_1

# LSPosed
# but this is probably not needed if auto_sus_bind_mount is enabled
if [ $force_hide_lsposed = 1 ] && echo "$susfs_features" | grep -q "CONFIG_KSU_SUSFS_TRY_UMOUNT"; then
	echo "susfs4ksu/post-fs-data: [force_hide_lsposed]" >> $logfile1
	${SUSFS_BIN} add_try_umount /system/apex/com.android.art/bin/dex2oat 1
	${SUSFS_BIN} add_try_umount /system/apex/com.android.art/bin/dex2oat32 1
	${SUSFS_BIN} add_try_umount /system/apex/com.android.art/bin/dex2oat64 1
	${SUSFS_BIN} add_try_umount /apex/com.android.art/bin/dex2oat 1
	${SUSFS_BIN} add_try_umount /apex/com.android.art/bin/dex2oat32 1
	${SUSFS_BIN} add_try_umount /apex/com.android.art/bin/dex2oat64 1
fi

# ===== sus_mount / try_umount — MUST run here in post-fs-data (BEFORE zygote) =====
# This is the critical fix: `umount -l` must happen BEFORE zygote forks app
# processes.  If done in post-mount.sh (late_start service, AFTER zygote),
# apps have already inherited the init mount namespace and the umount only
# affects the service's own namespace — apps still see the mounts.
#
# Flow: post-fs-data runs after module overlays are set up but before zygote.
# Umount here → init namespace loses the mount → zygote inherits clean namespace
# → apps never see the hidden mounts.

# (1) sus_mount — register paths in KPM so the kernel hook hides them
#     from /proc/mounts for non-su processes.
#     IMPORTANT: this does NOT actually umount anything.  The KPM hook
#     intercepts /proc/mounts reads and filters out these mountpoints
#     for non-su processes.  The mounts remain active for root/APatch.
#     NOTE: APatch now uses meta-modules (like KSU) instead of overlay
#     mounts, so /proc/1/mountinfo may NOT contain /data/adb entries.
#     We register standard paths directly instead of scanning mountinfo.
if echo "$susfs_features" | grep -q "CONFIG_KSU_SUSFS_SUS_MOUNT"; then
    # (a) Explicit paths from sus_mount.txt
    if grep -v "#" "$PERSISTENT_DIR/sus_mount.txt" > /dev/null 2>&1; then
        grep -v "#" "$PERSISTENT_DIR/sus_mount.txt" | while read -r i; do
            [ -z "$i" ] && continue
            ${SUSFS_BIN} add_sus_mount "$i" 2>/dev/null && echo "[sus_mount]: susfs4ksu/post-fs-data $i" >> "$logfile1"
        done
    fi
    # (b) Auto-register: when hide_sus_mnts is enabled, register the
    #     standard module/root paths with the KPM.
    #     This runs ALWAYS when hide_sus_mnts is on — no auto_* toggle needed.
    if [ "$hide_sus_mnts_for_all_or_non_su_procs" -ge 1 ] 2>/dev/null; then
        echo "[sus_mount]: registering standard module paths" >> "$logfile1"
        for auto_mp in \
            /data/adb/modules \
            /data/adb/ap \
            /data/adb/ksu \
            /debug_ramdisk \
            /sbin
        do
            ${SUSFS_BIN} add_sus_mount "$auto_mp" 2>/dev/null && echo "[sus_mount]: auto $auto_mp" >> "$logfile1"
        done
        # Also scan /proc/1/mountinfo for any mounts referencing /data/adb
        # (some APatch versions still use overlay for specific paths)
        grep -E '/data/adb/(modules|ap|ksu)' /proc/1/mountinfo 2>/dev/null | \
            awk '{print $5}' | sort -u | while read -r mp; do
            [ -z "$mp" ] && continue
            ${SUSFS_BIN} add_sus_mount "$mp" 2>/dev/null && echo "[sus_mount]: auto $mp" >> "$logfile1"
        done
    fi
fi

# (2) try_umount — register paths in KPM so the kernel hook hides them
#     from /proc/mounts for umounted app processes (zygote-forked apps
#     that had their mounts detached).  This does NOT actually umount
#     anything — the KPM hook filters these mountpoints from the app's
#     /proc/mounts view.  The mounts remain active for root/APatch.
if echo "$susfs_features" | grep -q "CONFIG_KSU_SUSFS_TRY_UMOUNT"; then
    # (a) Explicit paths from try_umount.txt
    if grep -v "#" "$PERSISTENT_DIR/try_umount.txt" > /dev/null 2>&1; then
        grep -v "#" "$PERSISTENT_DIR/try_umount.txt" | while read -r i; do
            [ -z "$i" ] && continue
            ${SUSFS_BIN} add_try_umount "$i" 1 2>/dev/null && echo "[try_umount]: susfs4ksu/post-fs-data $i" >> "$logfile1"
        done
    fi
    # (b) Auto-register: when any auto_* toggle is on, register standard
    #     module paths with the KPM so the kernel hook hides them from
    #     umounted app processes.  APatch meta-modules don't show in
    #     mountinfo, so we register paths directly.
    if [ ! -f /data/adb/susfs_no_auto_add_try_umount_for_bind_mount ]; then
        if [ "$auto_try_umount" = "1" ] || [ "$auto_mount" = "1" ] || \
           [ "$auto_bind" = "1" ] || [ "$auto_umount_bind" = "1" ]; then
            echo "[try_umount]: registering standard module paths (auto_try_umount=$auto_try_umount auto_mount=$auto_mount auto_bind=$auto_bind auto_umount_bind=$auto_umount_bind)" >> "$logfile1"
            ${SUSFS_BIN} auto_add_try_umount_for_bind_mount 2>/dev/null
            for auto_mp in \
                /data/adb/modules \
                /data/adb/ap \
                /data/adb/ksu \
                /debug_ramdisk \
                /sbin
            do
                ${SUSFS_BIN} add_try_umount "$auto_mp" 1 2>/dev/null && echo "[try_umount]: auto $auto_mp" >> "$logfile1"
            done
            # Also scan mountinfo for any overlay mounts referencing /data/adb
            grep -E '/data/adb/(modules|ap|ksu)' /proc/1/mountinfo 2>/dev/null | \
                awk '{print $5}' | sort -u | while read -r mp; do
                [ -z "$mp" ] && continue
                ${SUSFS_BIN} add_try_umount "$mp" 1 2>/dev/null && echo "[try_umount]: auto $mp" >> "$logfile1"
            done
        fi
    fi
fi

# - set to 1 to enable umount for all zygote spawned services, but be reminded that
#   it may break some modules that overlay framework files / overlay apks. Boot into
#   KSU rescue mode if you encounter bootloop here.
[ $umount_for_zygote_iso_service = 1 ] && {
	${SUSFS_BIN} umount_for_zygote_iso_service 1 && echo "susfs4ksu/post-fs-data: [umount_for_zygote_iso_service]" >> $logfile1
}


# SUSFS Logging — reuse the dmesg cache from Step 1 instead of calling
# `dmesg` a second time (each call reads the entire ring buffer, 0.5-2s).
grep -iE "susfs_auto_add|ksu_susfs|susfs_kpm|susfs:" "$dmesg_cache" > $logfile
endmsg=$(grep -E '^\[ *[0-9]' "$dmesg_cache" | tail -n 1 | sed 's/^\[ *//; s/\].*//')
echo "post_fs_data=$endmsg" > $tmpfolder/logs/boot_stage_time.sh
