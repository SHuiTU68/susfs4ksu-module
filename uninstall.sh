# Remove userspace binary (real + wrapper)
rm -f /data/adb/ap/bin/ksu_susfs
rm -f /data/adb/ap/bin/ksu_susfs_real
# KPM is embedded in the boot image — cannot be unloaded from here.
# To remove the KPM, reflash a stock or non-susfs boot image.
# Remove temp/log directory
rm -rf /data/adb/ap/susfs4ksu
