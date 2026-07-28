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

# Step 1: Fast dmesg check first (instant, no superkey needed).
# The KPM printk's "susfs_kpm: loaded ..." at init.  Only if dmesg shows
# the KPM do we try the supercall — otherwise we'd waste 10+ seconds on
# superkey extraction (kptools/boot scan) for a KPM that isn't even loaded.
kpm_in_dmesg=0
if dmesg 2>/dev/null | grep -qE "susfs:|susfs_kpm:"; then
	kpm_in_dmesg=1
fi

# ksu_susfs show version/features/variant now parse dmesg directly (no
# supercall) — see ksu_susfs/jni/features/show.c.  This is instant and
# never blocks boot.  We DON'T use `timeout` because the dmesg-based show
# is already fast and timeout itself may be unavailable in early boot.
susfs_features=""
version=""
if [ $kpm_in_dmesg -eq 1 ]; then
	susfs_features=$(${SUSFS_BIN} show enabled_features 2>/dev/null)
	version=$(${SUSFS_BIN} show version 2>/dev/null)
fi

# SUSFS_DECIMAL_MAIN = '2'
SUSFS_DECIMAL_MAIN=$(echo "$version" | sed 's/^v//;' | cut -d'.' -f1)
# SUSFS_DECIMAL_SUB = '0'
SUSFS_DECIMAL_SUB=$(echo "$version" | sed 's/^v//;' | cut -d'.' -f2)
# SUSFS_DECIMAL_PATCH = '0'
SUSFS_DECIMAL_PATCH=$(echo "$version" | sed 's/^v//;' | cut -d'.' -f3)

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
	{
		echo "=== susfs4ksu/post-fs-data ==="
		echo "timestamp: $(date)"
		echo "status: ACTIVE"
		echo "version: $version"
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
		echo "dmesg_susfs: $(dmesg 2>/dev/null | grep -iE 'susfs|susfs_kpm' | head -5)"
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

# - set to 1 to enable umount for all zygote spawned services, but be reminded that
#   it may break some modules that overlay framework files / overlay apks. Boot into
#   KSU rescue mode if you encounter bootloop here.
[ $umount_for_zygote_iso_service = 1 ] && {
	ksu_susfs umount_for_zygote_iso_service 1 && echo "susfs4ksu/post-fs-data: [umount_for_zygote_iso_service]" >> $logfile1
}


# SUSFS Logging
dmesg_snapshot=$(dmesg)
echo "$dmesg_snapshot" | grep -iE "susfs_auto_add|ksu_susfs|susfs_kpm|susfs:" > $logfile
endmsg=$(echo "$dmesg_snapshot" | grep -E '^\[ *[0-9]' | cut -d']' -f1 | sed 's/^\[ *//' | cut -d' ' -f1 | tail -n 1)
echo "post_fs_data=$endmsg" > $tmpfolder/logs/boot_stage_time.sh
