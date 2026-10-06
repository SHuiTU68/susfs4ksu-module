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
#   E7  the mount_kpm dcache engine.  Hand it the module trees and it
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
# "Unavailable" includes an engine that is loaded but not finished: E7 is gated
# on the `readdir` capability it advertises (see engine_up()).  That is on
# purpose - while the engine can resolve a path but not merge directory
# listings, `stat /system/bin/foo` would succeed while `ls /system/bin` would
# not show foo, and that mismatch is exactly the anomaly a root-hiding setup
# must not have.  A half-built engine therefore falls back to overlayfs instead
# of half-mounting the module set.
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
# The MOUNT engine is its own KPM package: /data/adb/ap/kpm/<id>/<id>.kpm is
# the autoload slot KernelPatch scans at post-fs-data, and mount_kpm.kpm is a
# different package from the security engine (susfs_kpm.kpm).  The two load
# independently and answer on different channel magics, so neither one's
# presence, version or capabilities constrain the other.  Everything below
# talks to the mount engine: it is the one that owns the dcache rule store.
KPM_ID=mount_kpm
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

# The kcmp command channel answers: engine file present, not disabled, mctl
# installed and getting a reply.  This says the engine is *reachable*, not that
# it can do the job - see engine_up().
channel_up() {
	[ -f "$KPM_FILE" ] || return 1
	[ -f "$KPM_DISABLE" ] && return 1
	[ -x "$MCTL" ] || return 1
	"$MCTL" version >/dev/null 2>&1
}

# Capabilities the engine advertises, comma-separated (empty on an engine that
# predates the query).
engine_caps() {
	"$MCTL" caps 2>/dev/null | tr -d '\r' | head -n 1
}

# E7 is used only when the engine advertises `readdir`, i.e. when both halves of
# a mount exist: the path resolves (dentry) *and* a directory listing shows it
# (readdir).  Gating on everything-but-readdir would give lookups that succeed
# while `ls` does not show the file - the one anomaly a root-hiding setup cannot
# afford.  A half-built engine therefore falls back to overlayfs.
engine_up() {
	channel_up || return 1
	case "$(engine_caps)" in
	*readdir*) return 0 ;;
	esac
	return 1
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
#
# WHY THE MODULE TREES HAVE TO BE STAGED FIRST
#
# The direct route - lowerdir=<module tree>:/$p - no longer works on this
# device, and neither does any variant that keeps a module tree as a layer:
#
#   * /data is f2fs with the casefold feature, and overlayfs rejects *every*
#     layer (lower or upper) whose superblock allows case-insensitive dentries.
#     That is upstream "ovl: Always reject mounting over case-insensitive
#     filesystems" (in every 6.6 stable from 6.6.8.y on), and it is what shows
#     up as `overlay: case-insensitive capable filesystem on ... not supported`
#     followed by EINVAL.  The module trees live under /data/adb/modules, so no
#     amount of option tweaking avoids it.
#   * the mount ALSO has to carry `userxattr`: without it overlayfs tries to set
#     trusted.overlay.* on the upper, which needs CAP_SYS_ADMIN in the initial
#     *user* namespace (we are in the global *mount* namespace but not the
#     initial user namespace), and the mount fails with EINVAL as well.
#
# So each module tree is copied onto a tmpfs - which overlayfs accepts - before
# it is used as a lowerdir, and the copy is exact: mctl stage reproduces modes,
# owners, symlinks, whiteouts (0:0 char devices) and, crucially, the SELinux
# labels.  A plain `cp -a` would leave every staged file labelled tmpfs:s0, and
# every read through the overlay would be denied.
#
# BUDGET
#
# The staging tmpfs is RAM, so it is capped: each tree is staged with the
# *remaining* budget and a tree that does not fit is skipped (and logged)
# instead of filling the tmpfs and taking the boot down.  The default, 1 GiB,
# fits the reference device's ~975 MB module set; smaller devices can set
# KPM_E4_CAP_KB (KiB) or drop a number into $DATA_DIR/e4_cap_kb.
E4_CAP_KB_FILE="$DATA_DIR/e4_cap_kb"
e4_cap_kb() {
	if [ -f "$E4_CAP_KB_FILE" ]; then
		cat "$E4_CAP_KB_FILE" 2>/dev/null
	elif [ -n "${KPM_E4_CAP_KB:-}" ]; then
		echo "$KPM_E4_CAP_KB"
	else
		echo 1048576
	fi
}

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

	e4_cap_kb_val=$(e4_cap_kb)
	stage_root="$DATA_DIR/rw/stage"

	mkdir -p "$DATA_DIR/rw"
	if ! grep -q " $DATA_DIR/rw " /proc/mounts; then
		# size= leaves headroom over the copy budget for the overlay's
		# upper/work directories, which live on this same tmpfs.  Rounded to MiB.
		tmpfs_mib=$(( (e4_cap_kb_val + 1023) / 1024 + 64 ))
		mount -t tmpfs -o "mode=0755,size=${tmpfs_mib}m" tmpfs "$DATA_DIR/rw" ||
			log "[e4] tmpfs mount failed"
	fi
	rm -rf "$stage_root"
	mkdir -p "$stage_root"

	# ---- 1. stage every module tree (exact copy) onto the tmpfs ----
	remaining_kb=$e4_cap_kb_val
	for m in $(active_modules); do
		id="${m##*/}"
		for p in $TARGET_PARTITIONS; do
			[ -d "$m/$p" ] || continue
			dst="$stage_root/$id/$p"
			mkdir -p "$(dirname "$dst")" 2>/dev/null
			if staged=$("$MCTL" stage --cap-kb "$remaining_kb" "$m/$p" "$dst" 2>>"$LOG"); then
				used=$(echo "$staged" | sed -n 's/^staged_kib=//p' | head -n 1)
				[ -n "$used" ] || used=0
				remaining_kb=$((remaining_kb - used))
				[ "$remaining_kb" -lt 0 ] && remaining_kb=0
				log "[e4] staged $id/$p (${used} KiB, ${remaining_kb} KiB left)"
			else
				rc=$?
				log "[e4] stage $id/$p failed (rc=$rc) - module skipped"
				rm -rf "$stage_root/$id" 2>/dev/null
			fi
		done
	done

	# ---- 2. one overlay per partition; lowers = staged trees, then the real one ----
	for p in $TARGET_PARTITIONS; do
		[ -d "/$p" ] || continue
		lowers=""
		for d in "$stage_root"/*/"$p"; do
			[ -d "$d" ] || continue
			lowers="$lowers:$d"
		done
		[ -n "$lowers" ] || continue
		mkdir -p "$DATA_DIR/rw/$p/upper" "$DATA_DIR/rw/$p/work"
		# In overlayfs the left-most lowerdir is the top one, so the staged
		# module trees have to come before the real partition.  userxattr is
		# mandatory (see the note above); redirect_dir=nofollow keeps overlayfs
		# from rewriting a rename across the layers.
		if mount -t overlay overlay \
			-o "lowerdir=${lowers#:}:/$p,upperdir=$DATA_DIR/rw/$p/upper,workdir=$DATA_DIR/rw/$p/work,userxattr,redirect_dir=nofollow" "/$p"; then
			log "[e4] overlay on /$p lowers=${lowers#:}"
		else
			log "[e4] overlay FAILED on /$p"
		fi
	done
	unset id p dst d lowers e4_cap_kb_val remaining_kb used staged rc 2>/dev/null
}

# Engine choice: an explicit request wins, then the engine if it is usable,
# then real overlayfs.
if [ -n "$FORCE_E4_ARG" ] || [ -n "${KPM_FORCE_E4:-}" ]; then
	log "[e4] forced by request"
	mount_e4
elif engine_up && ! needs_e4; then
	inject_e7
else
	if ! channel_up; then
		why="unavailable"
		[ -f "$KPM_FILE" ] || why="engine file missing ($KPM_FILE)"
		[ -f "$KPM_DISABLE" ] && why="engine disabled by marker ($KPM_DISABLE)"
		[ -x "$MCTL" ] || why="mctl missing ($MCTL)"
		log "[e4] falling back: $why"
	else
		log "[e4] falling back: engine caps=[$(engine_caps)] and E7 needs readdir"
	fi
	mount_e4
fi

log "=== done: $(date) ==="
exit 0