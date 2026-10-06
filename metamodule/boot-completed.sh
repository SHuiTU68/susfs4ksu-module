#!/system/bin/sh
# boot-completed.sh - disarms the bootloop guard and records how the boot went.
#
# metamount.sh arms $DATA_DIR/.booting at post-fs-data and this is the only
# thing that clears it, so "armed and never cleared" is exactly the signal that
# the last boot did not survive injection.  The next boot then suppresses
# mounting instead of looping (see metamount.sh, $DATA_DIR/disabled_boot).
#
# This is a normal <stage>.sh script: apd reaches it through
# run_stage("boot-completed") -> metamodule::exec_stage_script(), i.e. with
# AP_MODULE=kpmmount, cwd = this directory, and block=false.

MODDIR=${0%/*}
DATA_DIR=/data/adb/kpmmount
LOG="$DATA_DIR/mount.log"
MCTL="$DATA_DIR/bin/mctl"
KPM_DIR=/data/adb/ap/kpm/susfs_kpm

mkdir -p "$DATA_DIR" 2>/dev/null
log() { echo "$(date '+%F %T') $*" >> "$LOG"; }

log "boot-completed: enter"

# 1. Disarm the guard.
if [ -f "$DATA_DIR/.booting" ]; then
	rm -f "$DATA_DIR/.booting"
	log "[guard] disarmed"
else
	log "[guard] not armed (nothing to do)"
fi

# 2. Record what the mount engine actually got to, so an "enabled but injecting
#    nothing" state is visible here rather than only showing up later as files
#    mysteriously missing from /system.
if [ ! -f "$DATA_DIR/enable" ]; then
	log "[state] disabled by $DATA_DIR/enable"
elif [ -f "$DATA_DIR/disabled_boot" ]; then
	log "[state] suppressed by the bootloop guard ($DATA_DIR/disabled_boot)"
elif [ ! -f "$KPM_DIR/susfs_kpm.kpm" ]; then
	log "[state] no engine at $KPM_DIR/susfs_kpm.kpm -> overlayfs fallback was used"
elif [ -f "$KPM_DIR/disable" ]; then
	log "[state] engine disabled by $KPM_DIR/disable -> overlayfs fallback was used"
elif [ -x "$MCTL" ]; then
	rules=$("$MCTL" rule count 2>/dev/null | tr -d '\r\n')
	log "[state] engine up, dcache rules=${rules:-unknown}"
else
	log "[state] mctl missing -> overlayfs fallback was used"
fi

log "boot-completed: done"
exit 0