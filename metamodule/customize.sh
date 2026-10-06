#!/system/bin/sh
# customize.sh - runs inside APatch's installer when this metamodule is flashed.
#
# Two things get deployed:
#   1. the engine, as /data/adb/ap/kpm/susfs_kpm/susfs_kpm.kpm.  That path is
#      KernelPatch's autoload slot: kernel/patch/android/userd.c
#      (load_ap_kpm_modules) scans /data/adb/ap/kpm/<id>/<id>.kpm at
#      `post-fs-data: before` and loads it, unless <id>/disable exists.  It is
#      the *same* file the susfs4ksu module deploys, so we only install it when
#      it is not already there: whichever package is flashed first wins and a
#      later flash never downgrades the engine.
#   2. mctl, the userspace client for the engine's command channel, into
#      /data/adb/kpmmount/bin/mctl.
#
# We deliberately do NOT create /data/adb/metamodule: apd does that itself when
# it installs a metamodule (apd/src/module.rs:501 -> metamodule::ensure_symlink)
# and removes it on uninstall (module.rs:323).  Creating it here would only
# fight the daemon.

SKIPUNZIP=0

DATA_DIR=/data/adb/kpmmount
KPM_ID=susfs_kpm
KPM_DIR=/data/adb/ap/kpm/${KPM_ID}
STATE_ENABLE=${DATA_DIR}/enable

ui_print "- KPM Mount (metamodule)"

mkdir -p "$KPM_DIR" "$DATA_DIR/bin"

# ---- engine ----------------------------------------------------------------
if [ -f "$KPM_DIR/${KPM_ID}.kpm" ]; then
	ui_print "- engine already at ${KPM_DIR}/${KPM_ID}.kpm, keeping it"
elif [ -f "$MODPATH/${KPM_ID}.kpm" ]; then
	cp -f "$MODPATH/${KPM_ID}.kpm" "$KPM_DIR/${KPM_ID}.kpm" &&
		chmod 644 "$KPM_DIR/${KPM_ID}.kpm" &&
		ui_print "- engine installed to ${KPM_DIR}/${KPM_ID}.kpm"
else
	ui_print "! ${KPM_ID}.kpm not in the zip"
	ui_print "! without it mounting falls back to overlayfs"
fi

# A stale disable marker from a previous engine would silently keep it unloaded.
if [ -f "$KPM_DIR/disable" ]; then
	rm -f "$KPM_DIR/disable"
	ui_print "- cleared stale engine disable marker"
fi

# ---- userspace client ------------------------------------------------------
mctl_src=""
[ -f "$MODPATH/tools/mctl" ] && mctl_src="$MODPATH/tools/mctl"
[ -z "$mctl_src" ] && [ -f "$MODPATH/bin/mctl" ] && mctl_src="$MODPATH/bin/mctl"
if [ -n "$mctl_src" ]; then
	cp -f "$mctl_src" "$DATA_DIR/bin/mctl"
	chmod 755 "$DATA_DIR/bin/mctl"
	ui_print "- installed mctl to ${DATA_DIR}/bin/mctl"
else
	ui_print "! mctl not in the zip; the engine will run script-only"
fi

# Enabled by default: flashing the metamodule is the opt-in.
[ -f "$STATE_ENABLE" ] || touch "$STATE_ENABLE"

# The mount engine takes over at the next boot; a running system keeps whatever
# it has now (the metamodule contract only fires at post-fs-data).
ui_print "- reboot to hand mounting over to the engine"
