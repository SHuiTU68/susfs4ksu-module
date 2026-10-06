#!/system/bin/sh
# action.sh - what the Action button in APatch Manager (APM) runs.
#
# WHY THIS FILE *IS* THE BUTTON
# -----------------------------
# APM does not need a new UI element for this: it already renders a play button
# for every module whose directory contains an action.sh.  In apd,
# module::_list_modules() sets "action" = (action.sh exists || <id>.lua action
# exists) for *every* directory with a module.prop - metamodules included - and
# the Compose item in app/src/main/java/me/bmax/apatch/ui/screen/APM.kt draws
# that button when module.hasActionScript, without filtering metamodules.  The
# module list is sorted with enabled metamodules first, so our entry and its
# button are at the top.  Tapping it opens ExecuteAPMActionScreen, which runs
#
#     /data/adb/apd module action kpmmount
#
# -> module::run_action() -> exec_script("/data/adb/modules/kpmmount/action.sh")
# with the usual module env (AP_MODULE=kpmmount, APATCH=true, cwd = this dir),
# streaming everything we print into the on-screen log.
#
# So shipping this file *is* putting a working button for the mount bridge into
# APM, with no app-side change and nothing to keep in sync with upstream.
#
# Subcommands (all optional; no argument = status + hot apply):
#   status           what the engine thinks right now
#   apply            rebuild the mount set without rebooting (hot) - E7 only
#   rearm            clear the bootloop guard's suppression
#   enable|disable   turn mounting on/off (persistent, effective next boot)
#   e7|e4            prefer dcache injection | force real overlayfs
#   log              tail the mount log
#
# The split matters: E7 is a *rule set*, so it can be rebuilt at runtime.  E4 is
# real mounts; re-mounting a live /system partition is not something we do
# behind the user's back, so E4 refreshes need a reboot.

MODDIR=${0%/*}
DATA_DIR=/data/adb/kpmmount
LOG="$DATA_DIR/mount.log"
MCTL="$DATA_DIR/bin/mctl"
ENABLE_FILE="$DATA_DIR/enable"
FORCE_E4_FILE="$DATA_DIR/force_e4"
DISABLED_BOOT_FILE="$DATA_DIR/disabled_boot"
BOOT_MARK="$DATA_DIR/.booting"
KPM_DIR=/data/adb/ap/kpm/susfs_kpm
METAMOUNT="$MODDIR/metamount.sh"

mkdir -p "$DATA_DIR" 2>/dev/null
say() { echo "$*"; echo "$(date '+%F %T') [action] $*" >> "$LOG"; }

engine_ready() {
	[ -f "$KPM_DIR/susfs_kpm.kpm" ] || return 1
	[ -f "$KPM_DIR/disable" ] && return 1
	[ -x "$MCTL" ] || return 1
	"$MCTL" version >/dev/null 2>&1
}

active_modules() {
	n=0
	for m in /data/adb/modules/*; do
		[ -d "$m" ] || continue
		[ "${m##*/}" = "kpmmount" ] && continue
		[ -f "$m/disable" ] && continue
		[ -f "$m/remove" ] && continue
		n=$((n + 1))
	done
	echo "$n"
}

show_status() {
	echo "***************************************"
	echo " KPM Mount - module mount bridge"
	echo "***************************************"
	if [ -f "$ENABLE_FILE" ]; then
		echo "state    : enabled"
	else
		echo "state    : DISABLED  (${ENABLE_FILE})"
	fi
	if [ -f "$FORCE_E4_FILE" ]; then
		echo "engine   : E4 forced - real overlayfs"
	else
		echo "engine   : E7 preferred - dcache injection"
	fi
	echo "modules  : $(active_modules) active module(s)"
	if [ -f "$DISABLED_BOOT_FILE" ]; then
		echo "guard    : SUPPRESSED after a bad boot - run 'rearm' to undo"
	elif [ -f "$BOOT_MARK" ]; then
		echo "guard    : armed (post-fs-data ran; boot-completed has not)"
	else
		echo "guard    : idle"
	fi

	if [ ! -f "$KPM_DIR/susfs_kpm.kpm" ]; then
		echo "kpm      : missing (${KPM_DIR}/susfs_kpm.kpm)"
	elif [ -f "$KPM_DIR/disable" ]; then
		echo "kpm      : disabled by marker"
	else
		echo "kpm      : present"
	fi
	if [ -x "$MCTL" ]; then
		ver=$("$MCTL" version 2>/dev/null | head -1 | tr -d '\r')
		echo "mctl     : ${ver:-no reply}"
		if [ -n "$ver" ]; then
			cnt=$("$MCTL" rule count 2>/dev/null | tr -d '\r\n')
			echo "rules    : ${cnt:-unknown} dcache rule(s)"
			"$MCTL" rule list 2>/dev/null | head -20
		fi
	else
		echo "mctl     : not installed (${MCTL}) - script-only mode, E4 in use"
	fi
}

do_apply() {
	if [ ! -f "$ENABLE_FILE" ]; then
		say "disabled - nothing to apply (run 'enable' first)"
		return 0
	fi
	if [ -f "$FORCE_E4_FILE" ]; then
		say "E4 is forced: overlayfs mounts can only be (re)created at"
		say "post-fs-data - reboot to apply the current module set"
		return 0
	fi
	if ! engine_ready; then
		say "the dcache engine is not available on this boot, so modules are"
		say "mounted with real overlayfs - that cannot be redone while the"
		say "system is running. Reboot to apply the current module set."
		return 0
	fi
	say "handing the module set to the dcache engine (hot rebuild)"
	KPM_FORCE_E4= "$METAMOUNT" hot
	say "rebuild finished - see ${LOG}"
}

do_rearm() {
	rm -f "$DISABLED_BOOT_FILE"
	if [ -f "$DATA_DIR/disable_engine" ]; then
		rm -f "$DATA_DIR/disable_engine"
	fi
	say "bootloop guard cleared; mounting resumes at the next boot"
	if engine_ready && [ -f "$ENABLE_FILE" ]; then
		say "engine is up, applying now"
		KPM_FORCE_E4= "$METAMOUNT" hot
	fi
}

case "${1:-}" in
status|"")
	show_status
	[ -z "${1:-}" ] && do_apply
	;;
apply)
	do_apply
	;;
rearm)
	do_rearm
	;;
enable)
	touch "$ENABLE_FILE"
	say "mounting enabled - reboot to apply (or 'apply' if the engine is up)"
	;;
disable)
	rm -f "$ENABLE_FILE"
	say "mounting disabled - reboot to drop the current mount set"
	;;
e7)
	rm -f "$FORCE_E4_FILE"
	say "engine preference: E7 (dcache injection)"
	;;
e4)
	touch "$FORCE_E4_FILE"
	say "engine preference: E4 (real overlayfs)"
	;;
log)
	tail -n 60 "$LOG" 2>/dev/null || echo "(no log yet)"
	;;
*)
	echo "usage: action.sh [status|apply|rearm|enable|disable|e7|e4|log]"
	;;
esac

exit 0