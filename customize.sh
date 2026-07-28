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
# The real binary uses "su" as the supercall key, which only works for uids
# that APatch has su-granted. Scripts launched by apd (post-fs-data, service,
# boot-completed) run as root but WITHOUT the grant, so direct calls return
# EPERM (exit 255). We install the real binary as ksu_susfs_real and create
# a wrapper script as ksu_susfs that retries via `su -c` when EPERM occurs.
# This way all 70+ ${SUSFS_BIN} call sites in the module scripts work
# unchanged.
ui_print "[-] Installing ksu_susfs userspace tool"
chmod +x "${TMPDIR}/susfs/tools/ksu_susfs_arm64"
cp ${TMPDIR}/susfs/tools/ksu_susfs_arm64 ${DEST_BIN_DIR}/ksu_susfs_real
chmod 755 ${DEST_BIN_DIR}/ksu_susfs_real
cat > ${DEST_BIN_DIR}/ksu_susfs <<'WRAPPER'
#!/system/bin/sh
# ksu_susfs wrapper — retries via APatch su when supercall is rejected.
REAL=/data/adb/ap/bin/ksu_susfs_real
[ -x "$REAL" ] || exit 127
"$REAL" "$@"
rc=$?
# 255 = -1 = EPERM: supercall rejected because uid is not su-granted.
# Retry through APatch's su so apd grants the uid before exec'ing.
if [ $rc -eq 255 ] && command -v su >/dev/null 2>&1; then
	exec su -c "exec '$REAL' $(printf "'%s' " "$@")" 2>/dev/null
fi
exit $rc
WRAPPER
chmod 755 ${DEST_BIN_DIR}/ksu_susfs

# ---- KPM residency check (advisory only) ----
# The KPM is baked into the boot image by the user and auto-loaded by
# KernelPatch at boot via the extra_item mechanism — this module does NOT
# install or load it.
#
# Why we don't do a hard check here:
#   - `apd` has NO kpm subcommand (its CLI only manages APM modules; KPM
#     load/list/control is exposed via the APP's JNI, not apd CLI).
#   - `ksu_susfs show version` calls sc_kpm_control("su", ...) which only
#     succeeds when the caller's uid is in APatch's su allowlist — rarely
#     true during module install.
#   - dmesg won't show susfs_kpm: the KPM's boot-time load log goes to
#     KernelPatch's boot log buffer (retrievable via supercall "bootlog"),
#     not the regular kernel printk ring.
#
# So any probe here is unreliable. The authoritative status is computed
# after boot by post-fs-data.sh (which sets susfs_active) and reflected in
# the WebUI by boot-completed.sh. We only try the end-to-end probe as a
# convenience and never treat failure as an error.
ui_print "[-] Probing susfs_kpm (advisory — install-time probe is unreliable)"
SUSFS_VERSION_RAW="$(${DEST_BIN_DIR}/ksu_susfs show version 2>/dev/null)"
if [ -n "$SUSFS_VERSION_RAW" ] 2>/dev/null; then
	ui_print "[-] susfs_kpm active, version: $SUSFS_VERSION_RAW"
else
	ui_print "[-] KPM not reachable now — reboot to activate; status will be"
	ui_print "[-] shown in WebUI after boot (post-fs-data.sh sets susfs_active)"
fi

# set permissions
chmod 644 ${MODPATH}/post-fs-data.sh ${MODPATH}/post-mount.sh ${MODPATH}/service.sh ${MODPATH}/boot-completed.sh ${MODPATH}/action.sh ${MODPATH}/uninstall.sh ${MODPATH}/susfs-bin-update.sh ${MODPATH}/susfs_reset.sh

# Check if config folder exists
if [ -d /data/adb/susfs4ksu ]; then
susfs4ksu_config_check
fi

prop_value=$(getprop ro.boot.vbmeta.digest)
HASH_DIR=/data/adb/VerifiedBootHash
if ${AP_BIN} module list 2>/dev/null | grep -qE "vbmeta-fixer|TA_utl"; then
	ui_print "****************************************"
	ui_print "! vbmeta-fixer or Tricky Addon module detected"
	ui_print "! skipping VerifiedBootHash creation"
	ui_print "****************************************"
else
	if [ -z "$prop_value" ]; then
		ui_print "[!] Property ro.boot.vbmeta.digest is empty, generate VerifiedBootHash directory"
		if [ ! -d "$HASH_DIR" ]; then
		ui_print "[-] Creating VerifiedBootHash directory"
		mkdir -p "$HASH_DIR"
		[ ! -f "$HASH_DIR/VerifiedBootHash.txt" ] && touch "$HASH_DIR/VerifiedBootHash.txt"
		fi
		ui_print "****************************************"
		ui_print "! Please copy your VerifiedBootHash in Key Attestation demo"
		ui_print "! And Paste it to /data/adb/VerifiedBootHash/VerifiedBootHash.txt"
		ui_print "****************************************"
	else
		ui_print "****************************************"
		ui_print "! Property ro.boot.vbmeta.digest has a value"
		ui_print "! skipping VerifiedBootHash creation"
		ui_print "****************************************"
	fi
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
