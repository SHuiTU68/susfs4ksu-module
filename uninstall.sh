# Remove userspace binary (real + wrapper)
rm -f /data/adb/ap/bin/ksu_susfs
rm -f /data/adb/ap/bin/ksu_susfs_real
# Remove the KPM from APatch's persistent store.  customize.sh installs it to
# /data/adb/ap/kpm/susfs_kpm/ on every module install, so uninstalling the
# module should not leave a stale KPM that keeps loading at boot.
# If you baked the KPM into the boot image yourself, reflash a non-susfs boot
# image as well — this line cannot unload a resident module.
rm -rf /data/adb/ap/kpm/susfs_kpm
# Remove temp/log directory
rm -rf /data/adb/ap/susfs4ksu
