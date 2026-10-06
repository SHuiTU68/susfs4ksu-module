#!/system/bin/sh
# uninstall.sh - the metamodule's last act.
#
# apd runs this from module::prune_modules() during post-fs-data of the first
# boot after the user marked the metamodule for removal.  By that point it has
# already removed /data/adb/metamodule, so on this boot (and every one after it)
# no metamodule mount script runs - and since stock APatch has no mounting code
# of its own, the user's modules would simply stop appearing.
#
# So the last act is a handover: if mounting was enabled, mount the module set
# with plain overlayfs before we go.  Worse than the dcache engine, much better
# than silently losing every module in /data/adb/modules.  For the same reason
# we delete nothing from /data/adb/modules.
#
# What we deliberately keep:
#   * $DATA_DIR (enable/force_e4/logs) - a re-install picks the state back up
#   * the engine .kpm in /data/adb/ap/kpm/ - the susfs4ksu module may own it too

MODDIR=${0%/*}
DATA_DIR=/data/adb/kpmmount
LOG="$DATA_DIR/mount.log"

mkdir -p "$DATA_DIR" 2>/dev/null
log() { echo "$(date '+%F %T') [uninstall] $*" >> "$LOG"; }

log "metamodule removed (AP_MODULE=${AP_MODULE:-?} MODULE_ID=${MODULE_ID:-?})"

if [ -f "$DATA_DIR/enable" ] && [ -x "$MODDIR/metamount.sh" ]; then
	log "handing the module set to real overlayfs so modules survive without us"
	KPM_FORCE_E4=1 "$MODDIR/metamount.sh" hot e4
fi

# The guard must not survive us: there is no metamodule left to disarm it, and
# a stale marker would look exactly like a boot that failed to complete.
rm -f "$DATA_DIR/.booting"

log "done; state kept in $DATA_DIR"
exit 0