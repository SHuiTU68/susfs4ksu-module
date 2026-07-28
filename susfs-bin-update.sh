#!/bin/sh
# Update the ksu_susfs real binary. The upstream sidex15 binary uses the
# KernelSU reboot-magic syscall and is NOT compatible with APatch — only
# use this if you have an APatch-compatible build hosted at a custom URL.
# The wrapper script (ksu_susfs) is preserved; this only replaces the
# real binary (ksu_susfs_real).
SUSFS_REAL=/data/adb/ap/bin/ksu_susfs_real
AP_BIN=/data/adb/ap/bin/
TMPDIR=/data/adb/ap/susfs4ksu

echo "***************************************"
echo "SUSFS4AP Userspace tool update script"
echo "***************************************"
echo "[!] NOTE: The upstream sidex15 binary is NOT APatch-compatible."
echo "[!] Only use an APatch-specific build."
echo "***************************************"

download() { busybox wget -T 1 --no-check-certificate -qO - "$1"; }
if command -v curl > /dev/null 2>&1; then
	download() { curl --connect-timeout 1 -Ls "$1"; }
fi

if download "https://raw.githubusercontent.com/sidex15/susfs4ksu-binaries/universal-binary/ksu_susfs_arm64" > ${TMPDIR}/ksu_susfs_remote ; then
    chmod +x ${TMPDIR}/ksu_susfs_remote
    if ${TMPDIR}/ksu_susfs_remote > /dev/null 2>&1 ; then
		# Install as ksu_susfs_real (wrapper is preserved)
		mv -f ${TMPDIR}/ksu_susfs_remote ${AP_BIN}/ksu_susfs_real
		chmod 755 ${AP_BIN}/ksu_susfs_real
		echo "[-] Update Complete!"
    else
		echo "[!] Download Test Failed"
		echo "[!] Update Failed"
        exit 1
    fi
else
	echo "[!] No internet connection or susfs binaries not found"
	echo "[!] Update Failed"
    exit 1
fi
#EOL