# Remove userspace binary
rm -f /data/adb/ap/bin/ksu_susfs
# Remove KPM (unload + delete)
/data/adb/ap/bin/apd kpm unload susfs_kpm 2>/dev/null
rm -f /data/adb/kpm/susfs_kpm.kpm
# Remove temp/log directory
rm -rf /data/adb/ap/susfs4ksu
