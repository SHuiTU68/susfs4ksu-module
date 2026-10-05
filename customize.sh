#!/bin/sh
# susfs4ap-module customize.sh — APatch + KPM edition.
#
# This installer ships ONE artifact:
#   tools/ksu_susfs_arm64 — userspace CLI that talks to the KPM via
#   sc_kpm_control() (APatch supercall). Installed to /data/adb/ap/bin/.
#
# The KPM itself (susfs_kpm.kpm) is NOT shipped here — the user bakes it
# into the boot image, so APatch auto-loads it on every boot. This module
# only installs the userspace tool and verifies the KPM is resident.
#
# The original susfs4ksu downloaded a generic binary from the cloud; that
# binary uses the KernelSU reboot-magic syscall and is NOT compatible with
# APatch. We therefore ship our own binary and skip the cloud update.
PATH=/data/adb/ap/bin:/data/adb/ksu/bin:/data/data/com.termux/files/usr/bin:$PATH
AP_BIN=/data/adb/ap/bin/apd
DEST_BIN_DIR=/data/adb/ap/bin

if [ -z "$APATCH" ] ; then
	abort '[!] SUSFS-KPM is for APatch only.'
fi

if [ ! -x "${AP_BIN}" ]; then
    ui_print "[!] '${AP_BIN}' not found, installation aborted."
    rm -rf ${MODPATH}
    exit 1
fi

# Ensure the APatch bin dir exists (it should, since apd lives there)
mkdir -p ${DEST_BIN_DIR}

unzip -qq ${ZIPFILE} -d ${TMPDIR}/susfs

susfs4ksu_config_check() {
  ui_print " "
  ui_print "****************************************"
  ui_print "     SUSFS4AP Config Folder exists      "
  ui_print "****************************************"
  ui_print "     Do you want to reset settings?     "
  ui_print "****************************************"
  ui_print "  Volume Up (+): Reset to default"
  ui_print "  Volume Down (-): Keep current settings"
  ui_print " "
  ui_print "  Keep current settings in 10 seconds"
  ui_print "****************************************"
  local timeout=10
  local start_time=$(date +%s)
  while true; do
    local current_time=$(date +%s)
    if [ $((current_time - start_time)) -ge $timeout ]; then
      ui_print "[-] Timeout: Selected keep current settings"
      break
    fi
    local key_event=$(timeout 0.5 getevent -l 2>/dev/null)
    if echo "$key_event" | grep -q "KEY_VOLUMEUP"; then
      ui_print "[-] Key Detected: Selected Yes, reset to default"
	  ui_print "[-] Resetting susfs4ap settings to default..."
	  rm -rf /data/adb/susfs4ksu
      break
    elif echo "$key_event" | grep -q "KEY_VOLUMEDOWN"; then
      ui_print "[-] Key Detected: Selected No, keep current settings"
      break
    fi
  done
}

# ---- Install userspace binary (with su-fallback wrapper) ----
# The real binary (ksu_susfs_real) auto-detects the superkey via multiple
# strategies (see kpm_call.h:get_supercall_key()):
#   1. kptools -l on the active boot partition
#   2. Raw scan of boot partition for "KP1158" magic + superkey at offset 0xE8
#   3. apd cmdline (-s <key> during boot stages only)
#   4. Fallback to "su" (works only when no superkey was preset)
# This is necessary because SUPERCALL_KPM_CONTROL requires is_authed, which
# is granted only by a correct superkey or by being the trusted-manager UID
# (APK signature match).  ksu_susfs runs in a root shell (uid 0), NOT as the
# trusted manager, so it must supply the real superkey.
#
# The wrapper retries via `su -c` when the real binary returns EPERM (255),
# which can happen if boot partition is unreadable or kptools is missing.
ui_print "[-] Installing ksu_susfs userspace tool"
chmod +x "${TMPDIR}/susfs/tools/ksu_susfs_arm64"
cp ${TMPDIR}/susfs/tools/ksu_susfs_arm64 ${DEST_BIN_DIR}/ksu_susfs_real
chmod 755 ${DEST_BIN_DIR}/ksu_susfs_real
cat > ${DEST_BIN_DIR}/ksu_susfs <<'WRAPPER'
#!/system/bin/sh
# ksu_susfs wrapper — retries via APatch su when supercall is rejected.
# ksu_susfs_real auto-detects the superkey from the boot partition (kptools
# or raw KP1158 scan) or apd cmdline; the su -c retry is a last resort.
REAL=/data/adb/ap/bin/ksu_susfs_real
[ -x "$REAL" ] || exit 127
"$REAL" "$@"
rc=$?
# 255 = -1 = EPERM: supercall rejected (key extraction failed).
if [ $rc -eq 255 ] && command -v su >/dev/null 2>&1; then
	exec su -c "exec '$REAL' $(printf "'%s' " "$@")" 2>/dev/null
fi
exit $rc
WRAPPER
chmod 755 ${DEST_BIN_DIR}/ksu_susfs

# ---- Install the KPM into APatch's persistent KPM store ----
# APatch loads KPMs from /data/adb/ap/kpm/<id>/<id>.kpm at the
# `post-fs-data: before` user event (see KernelPatch
# kernel/patch/android/userd.c:load_ap_kpm_modules(), called from
# kernel/patch/common/user_event.c).  A `disable` marker file inside the
# module directory skips it.  Writing the file here is byte-for-byte what the
# APatch app's KPM tab -> "Install" action does, and it means the KPM no
# longer has to be baked into the boot image as an extra item.
#
# We deliberately do NOT try to load it from the installer:
# SUPERCALL_KPM_LOAD sits behind `if (!is_authed) return -EPERM;`.  is_authed
# is granted only by (a) a matching preset superkey, or (b) being the
# trusted-manager UID (APatch app, verified by APK signature).  A root shell
# gets is_trusted_caller but NOT is_authed, so loading must happen at boot.
#
# If the KPM is already resident (the user baked it into the boot image, or
# APatch loaded it from this directory on an earlier boot), we leave the
# existing copy alone rather than creating a duplicate load.
ui_print "[-] Checking susfs_kpm via dmesg (instant, no superkey needed)"
if dmesg 2>/dev/null | grep -q "susfs_kpm: loaded"; then
	ui_print "[-] susfs_kpm is already resident (detected via dmesg printk)"
	ui_print "[-] Leaving the installed KPM store untouched"
else
	KPM_ID=susfs_kpm
	KPM_DIR=/data/adb/ap/kpm/${KPM_ID}
	if [ -f "${MODPATH}/${KPM_ID}.kpm" ]; then
		ui_print "[-] Installing KPM to ${KPM_DIR}/${KPM_ID}.kpm"
		mkdir -p ${KPM_DIR}
		# Keep an existing `disable` marker: the user may have turned the
		# module off on purpose from the APatch app.
		cp -f "${MODPATH}/${KPM_ID}.kpm" "${KPM_DIR}/${KPM_ID}.kpm"
		chmod 644 "${KPM_DIR}/${KPM_ID}.kpm"
		if [ -e "${KPM_DIR}/disable" ]; then
			ui_print "[!] ${KPM_DIR}/disable exists — KPM stays disabled"
		else
			ui_print "[-] susfs_kpm will be loaded by APatch at the"
			ui_print "    post-fs-data event on the next reboot"
		fi
	else
		ui_print "[!] ${KPM_ID}.kpm missing from the zip"
		ui_print "    Re-flash, or load the KPM manually from APatch's KPM tab"
	fi
fi

# set permissions
chmod 644 ${MODPATH}/post-fs-data.sh ${MODPATH}/post-mount.sh ${MODPATH}/service.sh ${MODPATH}/boot-completed.sh ${MODPATH}/action.sh ${MODPATH}/uninstall.sh ${MODPATH}/susfs-bin-update.sh ${MODPATH}/susfs_reset.sh

# Check if config folder exists
if [ -d /data/adb/susfs4ksu ]; then
susfs4ksu_config_check
fi

ui_print "[-] Preparing susfs4ap persistent directory"
PERSISTENT_DIR=/data/adb/susfs4ksu
[ ! -d /data/adb/susfs4ksu ] && mkdir -p $PERSISTENT_DIR
files="sus_mount.txt try_umount.txt sus_path.txt sus_path_loop.txt sus_maps.txt sus_open_redirect.txt legit_mounts.txt sus_kstat_statically.json config.sh"
for i in $files ; do
    if [ ! -f $PERSISTENT_DIR/$i ] ; then
        # If file doesn't exist, create it
        cat $MODPATH/$i > $PERSISTENT_DIR/$i
    elif [ "$i" = "config.sh" ]; then
        # Ensure file ends with newline
        [ -s "$PERSISTENT_DIR/$i" ] && [ "$(tail -c1 "$PERSISTENT_DIR/$i" | xxd -p)" != "0a" ] && echo "" >> "$PERSISTENT_DIR/$i"
        # For config.sh, append only new keys
        while IFS= read -r line; do
            # Extract key name before = sign
            key=$(echo "$line" | cut -d'=' -f1)
            # Only append if key doesn't exist
            grep -q "^${key}=" "$PERSISTENT_DIR/$i" || echo "$line" >> "$PERSISTENT_DIR/$i"
        done < "$MODPATH/$i"
    fi
    rm $MODPATH/$i
done

# Random ro.boot.vbmeta.size value
vbmeta_size=$(( 5504 + (RANDOM % 14 + 1)*1024 ))  # 5504~16384

# Data persistence
if grep -q "^vbmeta_size=" /data/adb/susfs4ksu/config.sh; then
    sed -i "s/^vbmeta_size=.*/vbmeta_size=$vbmeta_size/" /data/adb/susfs4ksu/config.sh
else
    echo "vbmeta_size=$vbmeta_size" >> /data/adb/susfs4ksu/config.sh
fi

rm -rf ${MODPATH}/tools
rm ${MODPATH}/customize.sh

# EOF
