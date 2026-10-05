#!/system/bin/sh
# susfs4ap action.sh — APatch + KPM edition: status + repair.
#
# HISTORY / WHY THIS NO LONGER UPDATES FROM THE CLOUD
# ---------------------------------------------------
# Upstream susfs4ksu's action.sh downloaded the "universal binary" from
#   https://raw.githubusercontent.com/sidex15/susfs4ksu-binaries/universal-binary/ksu_susfs_arm64
# and copied it over /data/adb/ap/bin/ksu_susfs.  That binary talks to
# KernelSU (reboot-magic syscall + ksu-specific prctls); it is NOT
# APatch-compatible.  Running it here replaced this module's su-fallback
# *wrapper* with the KSU binary, and every subsequent command failed with
#   [-] Requires susfs v1.5.3+
# i.e. the act of "updating" broke the userspace tool until the module was
# re-flashed.  On an APatch + KPM install there is nothing to update from the
# cloud anyway: the CLI is built from this repo (ksu_susfs/jni) by CI and
# speaks kcmp/supercall to *our* KPM.
#
# So this action now reports status and *repairs* a clobbered install:
#   * recreates the su-fallback wrapper if it is missing/foreign
#   * restores the real binary from the pristine copy kept by customize.sh
#   * re-deploys the KPM into APatch's KPM store
# It never downloads anything.

MODDIR=/data/adb/modules/susfs4ksu
AP_BIN=/data/adb/ap/bin
SUSFS_BIN=${AP_BIN}/ksu_susfs
REAL_BIN=${AP_BIN}/ksu_susfs_real
PRISTINE=${MODDIR}/bin/ksu_susfs_arm64
KPM_ID=susfs_kpm
KPM_DIR=/data/adb/ap/kpm/${KPM_ID}
TMPDIR=/data/adb/ap/susfs4ksu

echo "***************************************"
echo " SUSFS4AP status / repair (KPM edition)"
echo "***************************************"

# ---- 1. Running KPM identity (command channel) -------------------------
echo "[-] Querying the KPM command channel..."
if [ -x "$SUSFS_BIN" ]; then
	ver=$(${SUSFS_BIN} show version 2>/dev/null | head -1 | tr -d '\r')
	var=$(${SUSFS_BIN} show variant 2>/dev/null | head -1 | tr -d '\r')
	feat=$(${SUSFS_BIN} show enabled_features 2>/dev/null | grep -c '^CONFIG_')
	[ -z "$ver" ] && ver="(no reply)"
	[ -z "$var" ] && var="(no reply)"
	echo "    version : $ver"
	echo "    variant : $var"
	echo "    features: ${feat} reported"
	[ "$ver" = "(no reply)" ] && echo "    -> NO REPLY: the KPM is not loaded, or its kcmp hook is not installed"
	[ "$ver" != "(no reply)" ] && echo "    -> command channel OK"
else
	echo "[!] ${SUSFS_BIN} missing — userspace tool not installed"
fi

# ---- 2. Userspace tool integrity --------------------------------------
echo "[-] Checking userspace tool..."
need_wrapper=0
if [ ! -x "$REAL_BIN" ]; then
	if [ -x "$PRISTINE" ]; then
		mkdir -p "$AP_BIN"
		cp -f "$PRISTINE" "$REAL_BIN"
		chmod 755 "$REAL_BIN"
		echo "    restored ksu_susfs_real from the module copy"
	else
		echo "[!] ksu_susfs_real missing and no pristine copy in ${PRISTINE}"
		echo "    Re-flash the module to restore the userspace tool."
	fi
fi
# The wrapper is a tiny shell script.  Anything else sitting at $SUSFS_BIN
# (a foreign/cloud binary, a stale real binary, ...) is replaced.
if [ ! -x "$SUSFS_BIN" ]; then
	need_wrapper=1
elif ! grep -q 'ksu_susfs_real' "$SUSFS_BIN" 2>/dev/null; then
	echo "[!] ${SUSFS_BIN} is not this module's wrapper (foreign binary)"
	need_wrapper=1
fi
if [ $need_wrapper -eq 1 ]; then
	cat > ${AP_BIN}/ksu_susfs <<'WRAPPER'
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
	chmod 755 ${AP_BIN}/ksu_susfs
	echo "    wrapper restored"
else
	echo "    wrapper OK"
fi

# ---- 3. KPM store deployment ------------------------------------------
echo "[-] Checking the KPM store (${KPM_DIR})..."
if [ -f "${MODDIR}/${KPM_ID}.kpm" ]; then
	mkdir -p "$KPM_DIR"
	if [ ! -f "${KPM_DIR}/${KPM_ID}.kpm" ] || ! cmp -s "${MODDIR}/${KPM_ID}.kpm" "${KPM_DIR}/${KPM_ID}.kpm"; then
		cp -f "${MODDIR}/${KPM_ID}.kpm" "${KPM_DIR}/${KPM_ID}.kpm"
		chmod 644 "${KPM_DIR}/${KPM_ID}.kpm"
		echo "    deployed ${KPM_ID}.kpm -> ${KPM_DIR}"
	else
		echo "    store copy already up to date"
	fi
	[ -e "${KPM_DIR}/disable" ] && echo "[!] ${KPM_DIR}/disable exists — the KPM stays disabled"
else
	echo "[!] ${MODDIR}/${KPM_ID}.kpm missing — re-flash the module"
fi

# ---- 4. Boot-image shadow check ---------------------------------------
# A KPM baked into the boot image is loaded at kernel init, before the store
# is scanned, so it always wins.  Detect the mismatch instead of silently
# running the old one.
store_ver=$(grep -a -o 'susfs_kpm: version=[^ ]*' /data/adb/ap/log/dmesg.log 2>/dev/null | tail -1 | sed 's/.*version=//')
boot_ver=$(dmesg 2>/dev/null | grep 'susfs_kpm: version=' | tail -1 | sed 's/.*version=//;s/ .*//')
echo "[-] Versions: boot-image KPM=${boot_ver:-none-in-this-boot} store=${store_ver:-unknown}"
echo "    (an embedded KPM is loaded first and shadows the store copy;"
echo "     remove it in the APatch app -> KPM tab, then re-patch the boot image)"

echo "***************************************"
echo " Done. Reboot for a redeployed KPM."
echo "***************************************"
