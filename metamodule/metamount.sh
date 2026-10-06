#!/system/bin/sh
# metamount.sh - the mount policy hook stock APatch calls at post-fs-data.
#
# apd runs this (busybox sh, cwd = this directory) from
# metamodule::exec_mount_script() inside on_post_data_fs() - after sepolicy and
# restorecon, before any module's own post-fs-data.sh.  It is handed
# MODULE_DIR=/data/adb/modules, i.e. the whole directory rather than a single
# module, so walking the module set is our job.
#
# Two engines, in order of preference:
#
#   E7  the susfs_kpm dcache engine.  Hand it the module trees and it
#       synthesises dentry+inode pairs on the target superblocks.  Nothing gets
#       mounted, so there is nothing to hide: /proc/mounts is untouched and
#       st_dev stays the real partition's.
#   E4  real overlayfs per partition inside the global mount namespace, i.e. the
#       way APatch mounted modules before mounting was removed from the daemon.
#       Detectable, but it does not depend on the KPM at all.
#
# E4 is used when the engine is unavailable, and also when a module asks for
# something E7 v1 deliberately does not implement (whiteout / opaque replace):
# silently dropping those would be worse than a weaker layer.
#
# Modes: boot (default; arms the bootloop guard) | hot (runtime refresh, no guard)
# Second argument: "e4" forces real overlayfs (used by uninstall.sh's handover).
# Companion scripts: action.sh (the APM Action button), boot-completed.sh
# (disarms the guard), metainstall.sh / metauninstall.sh (install-time hooks),
# uninstall.sh (handover when the metamodule is removed).

MODDIR=${0%/*}
MODULES_DIR="${MODULE_DIR:-/data/adb/modules}"
META_ID="${AP_MODULE:-kpmmount}"
DATA_DIR=/data/adb/kpmmount
LOG="$DATA_DIR/mount.log"
MCTL="$DATA_DIR/bin/mctl"
KPM_ID=susfs_kpm
KPM_FILE="/data/adb/ap/kpm/$KPM_ID/$KPM_ID.kpm"
KPM_DISABLE="/data/adb/ap/kpm/$KPM_ID/disable"
ENABLE_FILE="$DATA_DIR/enable"
FORCE_E4_FILE="$DATA_DIR/force_e4"
BOOT_MARK="$DATA_DIR/.booting"
DISABLED_BOOT_FILE="$DATA_DIR/disabled_boot"
# $1 = mode: boot (default; arms the guard) | hot (runtime refresh, no guard)
# $2 = optional engine override, currently only "e4" (force real overlayfs)
MODE="${1:-boot}"
FORCE_E4_ARG="${2:-}"

TARGET_PARTITIONS="system system_ext vendor odm product oem apex optics prism
                   mi_ext my_bigball my_carrier my_company my_engineering my_heytap
                   my_manifest my_preload my_product my_region my_reserve my_stock"

log() { echo "$*" >> "$LOG"; }

mkdir -p "$DATA_DIR" 2>/dev/null

if [ ! -f "$ENABLE_FILE" ]; then
	log "=== $(date) === disabled by $ENABLE_FILE, leaving the loop alone"
	exit 0
fi

# Suppressed after an earlier boot that never completed: stay out of the way
# until the user re-arms from the Action button.  We deliberately do *not* drop
# a `disable` marker in $MODDIR here - that would also hand us to apd's
# check_install_safety() blocking branch (regular module installs refused until
# the metamodule is re-enabled) and stop the metamodule's own `<stage>.sh`
# scripts from running, i.e. exactly the scripts that are the recovery path.
if [ -f "$DISABLED_BOOT_FILE" ]; then
	log "=== $(date) ==="
	log "[guard] mounting suppressed after a previous failed boot; tap Action on $META_ID to re-arm"
	exit 0
fi

if [ "$MODE" != "hot" ]; then
	# Bootloop guard: this file is armed here and disarmed by boot-completed.sh.
	# Finding it still present means the previous boot never got that far, so
	# the next boot mounts nothing instead of looping forever.
	if [ -f "$BOOT_MARK" ]; then
		log "=== $(date) ==="
		log "[FATAL] previous boot never reached boot-completed; suppressing mounts until re-armed"
		touch "$DISABLED_BOOT_FILE"
		rm -f "$BOOT_MARK"
		exit 1
	fi
	touch "$BOOT_MARK"
fi

log "=== $(date) mode=$MODE MODULE_DIR=$MODULES_DIR ==="

# --- the module set --------------------------------------------------------
# APatch semantics: a module participates unless it carries a marker file.
active_modules() {
	for m in "$MODULES_DIR"/*; do
		[ -d "$m" ] || continue
		id="${m##*/}"
		[ "$id" = "$META_ID" ] && continue
		[ -f "$m/disable" ] && { log "[skip] $id: disable"; continue; }
		[ -f "$m/remove" ] && { log "[skip] $id: remove"; continue; }
		[ -f "$m/skip_mount" ] && { log "[skip] $id: skip_mount"; continue; }
		echo "$m"
	done
}

# Does any active module need what E7 v1 does not do?  Whiteouts arrive as a
# 0:0 char device, and APatch's installer also leaves .replace markers.
needs_e4() {
	[ -f "$FORCE_E4_FILE" ] && return 0
	for m in $(active_modules); do
		for p in $TARGET_PARTITIONS; do
			[ -d "$m/$p" ] || continue
			if find -L "$m/$p" \( -type c -o -name '.replace' \) -print -quit 2>/dev/null | grep -q .; then
				log "[e4] $m/$p has a whiteout/opaque marker"
				return 0
			fi
		done
	done
	return 1
}

engine_up() {
	[ -f "$KPM_FILE" ] || return 1
	[ -f "$KPM_DISABLE" ] && return 1
	[ -x "$MCTL" ] || return 1
	"$MCTL" version >/dev/null 2>&1
}

# --- E7: hand the trees to the engine --------------------------------------
# One syscall per partition tree, not per path: NUL-separated
# `virtual-path\0real-path\0` records on stdin.
inject_e7() {
	trees=0
	"$MCTL" rule clear >> "$LOG" 2>&1
	for m in $(active_modules); do
		for p in $TARGET_PARTITIONS; do
			[ -d "$m/$p" ] || continue
			[ -d "/$p" ] || [ -d "/system/$p" ] || continue
			root="/$p"
			[ -d "$root" ] || root="/system/$p"
			find -L "$m/$p" \( -type f -o -type l \) ! -name '.replace' -exec sh -c '
				for f do
					v="${f#'"$m/$p"'}"
					case "$v" in /system/odm/*) v="/odm/${v#/system/odm/}";; esac
					printf "%s\0%s\0" "'"$root"'$v" "$f"
				done
			' _ {} + 2>/dev/null | "$MCTL" rule add >> "$LOG" 2>&1
			trees=$((trees + 1))
		done
	done
	log "[e7] handed over $trees partition tree(s)"
	"$MCTL" rule list >> "$LOG" 2>&1
}

# --- E4: real overlayfs, in the namespace everyone inherits ----------------
mount_e4() {
	if [ "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ]; then
		# `mount` here would land in apd's private namespace and nobody would
		# ever see it, so re-exec under PID 1's namespace.  The mode/override
		# arguments have to be spelled out: inside a function "$@" is empty.
		nsenter_cmd=""
		if command -v nsenter >/dev/null 2>&1; then
			nsenter_cmd="nsenter"
		elif [ -x /data/adb/ap/bin/busybox ]; then
			nsenter_cmd="/data/adb/ap/bin/busybox nsenter"
		fi
		if [ -n "$nsenter_cmd" ]; then
			log "[e4] re-exec inside the global mount namespace"
			exec $nsenter_cmd -t 1 -m -- "$0" "$MODE" "$FORCE_E4_ARG"
		fi
		log "[e4] ERROR: not in the global mount namespace and no nsenter"
	fi
	mkdir -p "$DATA_DIR/rw"
	grep -q " $DATA_DIR/rw " /proc/mounts || mount -t tmpfs -o mode=0755 tmpfs "$DATA_DIR/rw" || log "[e4] tmpfs failed"
	for p in $TARGET_PARTITIONS; do
		[ -d "/$p" ] || continue
		lowers=""
		for m in $(active_modules); do
			[ -d "$m/$p" ] && lowers="$lowers:$m/$p"
		done
		[ -n "$lowers" ] || continue
		mkdir -p "$DATA_DIR/rw/$p/upper" "$DATA_DIR/rw/$p/work"
		# In overlayfs the left-most lowerdir is the top one, so module trees
		# have to come before the real partition.
		if mount -t overlay overlay \
			-o "lowerdir=${lowers#:}:/$p,upperdir=$DATA_DIR/rw/$p/upper,workdir=$DATA_DIR/rw/$p/work" "/$p"; then
			log "[e4] overlay on /$p lowers=${lowers#:}"
		else
			log "[e4] overlay FAILED on /$p"
		fi
	done
}

# Engine choice: an explicit request wins, then the engine if it is usable,
# then real overlayfs.
if [ -n "$FORCE_E4_ARG" ] || [ -n "${KPM_FORCE_E4:-}" ]; then
	log "[e4] forced by request"
	mount_e4
elif engine_up && ! needs_e4; then
	inject_e7
else
	if ! engine_up; then
		why="unavailable"
		[ -f "$KPM_FILE" ] || why="engine file missing ($KPM_FILE)"
		[ -f "$KPM_DISABLE" ] && why="engine disabled by marker ($KPM_DISABLE)"
		[ -x "$MCTL" ] || why="mctl missing ($MCTL)"
		log "[e4] falling back: $why"
	fi
	mount_e4
fi

log "=== done: $(date) ==="
exit 0