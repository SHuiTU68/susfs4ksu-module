#!/bin/sh
# susfs4ap-module customize.sh — APatch + KPM edition.
#
# This installer ships TWO artifacts:
#   tools/ksu_susfs_arm64 — userspace CLI that talks to the KPM through the
#   kcmp command channel (primary) or sc_kpm_control() (APatch supercall,
#   fallback).  Installed to /data/adb/ap/bin/ as ksu_susfs_real + wrapper.
#   susfs_kpm.kpm — the KernelPatch Module, deployed to
#   /data/adb/ap/kpm/susfs_kpm/susfs_kpm.kpm so APatch loads it at the
#   post-fs-data user event on the next boot (no boot-image surgery needed).
#
# A KPM embedded in the boot image still takes precedence: it is loaded at
# kernel init, long before the store is scanned.  post-fs-data.sh and
# action.sh both warn when the running KPM's version differs from
# module.prop:kpmVersion, which is the signature of that shadowing.
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
	  # Wipe both the current location and the pre-migration one, otherwise a
	  # stale /data/adb/susfs4ksu would be copied back in by the migration
	  # block below and "reset" would do nothing.
	  rm -rf /data/adb/ap/susfs4ksu /data/adb/susfs4ksu
	  SUSFS_RESET_PERFORMED=1
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
# Keep a pristine copy inside the module so action.sh can repair an install
# whose binaries were clobbered (upstream's action.sh used to overwrite
# ksu_susfs with the KSU universal binary — see action.sh).
mkdir -p ${MODPATH}/bin
cp -f ${TMPDIR}/susfs/tools/ksu_susfs_arm64 ${MODPATH}/bin/ksu_susfs_arm64
chmod 755 ${MODPATH}/bin/ksu_susfs_arm64
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
# We ALWAYS deploy the file (idempotent), even when a KPM is currently
# resident.  The previous revision skipped deployment when dmesg contained
# "susfs_kpm: loaded" — which on this device was true whenever the KPM had
# been embedded in the boot image, so the store stayed empty and every
# module update silently kept running the *stale embedded* KPM.  Deploying
# unconditionally makes the store authoritative once the embedded copy is
# removed, and post-fs-data.sh warns when the running KPM's version differs
# from the one shipped here.
KPM_ID=susfs_kpm
KPM_DIR=/data/adb/ap/kpm/${KPM_ID}
KPM_VER=$(sed -n 's/^kpmVersion=//p' ${MODPATH}/module.prop 2>/dev/null | head -1)
# The CI zips susfs_kpm.kpm at the archive root.  Magisk-family installers
# extract the whole archive into $MODPATH, and this script additionally
# unzips it into $TMPDIR/susfs for the userspace tool — accept either.
KPM_SRC=""
for cand in "${MODPATH}/${KPM_ID}.kpm" "${TMPDIR}/susfs/${KPM_ID}.kpm"; do
	[ -f "$cand" ] && KPM_SRC="$cand" && break
done
if [ -n "$KPM_SRC" ]; then
	ui_print "[-] Installing KPM${KPM_VER:+ v${KPM_VER}} to ${KPM_DIR}/${KPM_ID}.kpm"
	mkdir -p ${KPM_DIR}
	cp -f "$KPM_SRC" "${KPM_DIR}/${KPM_ID}.kpm"
	chmod 644 "${KPM_DIR}/${KPM_ID}.kpm"
	if [ -e "${KPM_DIR}/disable" ]; then
		ui_print "[!] ${KPM_DIR}/disable exists — KPM stays disabled"
	else
		ui_print "[-] susfs_kpm will be loaded by APatch at the"
		ui_print "    post-fs-data event on the next reboot"
	fi
	# If the KPM is ALSO embedded in the boot image, the embedded copy wins
	# (it is loaded at kernel init, before the store is scanned).  Detect and
	# report it so the user isn't left wondering why an update "did nothing".
	if dmesg 2>/dev/null | grep -q "susfs_kpm:"; then
		embedded_ver=$(dmesg 2>/dev/null | grep 'susfs_kpm: version=' | tail -1 | sed 's/.*version=//;s/ .*//')
		if [ -n "$embedded_ver" ]; then
			ui_print "[!] A KPM is already loaded in this boot (v${embedded_ver})."
			ui_print "[!] If it lives in the boot image it will shadow this copy —"
			ui_print "[!] remove it via APatch -> KPM tab (or re-embed v${KPM_VER:-the new one})."
		fi
	fi
else
	ui_print "[!] ${KPM_ID}.kpm missing from the zip"
	ui_print "    Re-flash, or load the KPM manually from APatch's KPM tab"
fi

# set permissions
chmod 644 ${MODPATH}/post-fs-data.sh ${MODPATH}/post-mount.sh ${MODPATH}/service.sh ${MODPATH}/boot-completed.sh ${MODPATH}/action.sh ${MODPATH}/uninstall.sh ${MODPATH}/susfs-bin-update.sh ${MODPATH}/susfs_reset.sh

# The persistent config directory moved from /data/adb/susfs4ksu to
# /data/adb/ap/susfs4ksu, so that all module state lives under APatch's own
# tree (/data/adb/ap/...) next to the KPM store and binaries that already
# write there (kpm_call.h's superkey cache, susfs_diag.txt, the logs dir).
LEGACY_PERSISTENT_DIR=/data/adb/susfs4ksu
PERSISTENT_DIR=/data/adb/ap/susfs4ksu
SUSFS_RESET_PERFORMED=0

# Check if config folder exists (either the current or the pre-migration one)
if [ -d "$PERSISTENT_DIR" ] || [ -d "$LEGACY_PERSISTENT_DIR" ]; then
susfs4ksu_config_check
fi

ui_print "[-] Preparing susfs4ap persistent directory"
mkdir -p $PERSISTENT_DIR
if [ "$SUSFS_RESET_PERFORMED" = "0" ] && [ -d "$LEGACY_PERSISTENT_DIR" ]; then
	# Bring an existing install's settings across so that upgrading the module
	# does not silently reset every toggle to the shipped default.  Files
	# already present in the new location win: that directory is the one the
	# KPM and the userspace binaries write to, so its copies are the live ones.
	ui_print "[-] Migrating settings: $LEGACY_PERSISTENT_DIR -> $PERSISTENT_DIR"
	for f in "$LEGACY_PERSISTENT_DIR"/*; do
		[ -f "$f" ] || continue
		b=$(basename "$f")
		[ -e "$PERSISTENT_DIR/$b" ] || cp -f "$f" "$PERSISTENT_DIR/$b"
	done
fi
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
if grep -q "^vbmeta_size=" /data/adb/ap/susfs4ksu/config.sh; then
    sed -i "s/^vbmeta_size=.*/vbmeta_size=$vbmeta_size/" /data/adb/ap/susfs4ksu/config.sh
else
    echo "vbmeta_size=$vbmeta_size" >> /data/adb/ap/susfs4ksu/config.sh
fi

rm -rf ${MODPATH}/tools
rm ${MODPATH}/customize.sh

# EOF
