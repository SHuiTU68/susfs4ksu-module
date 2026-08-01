#!/bin/sh
PATH=/data/adb/ksu/bin:$PATH
kernel_version='default'
kernel_build='default'
[ -f $PERSISTENT_DIR/config.sh ] && . $PERSISTENT_DIR/config.sh
## susfs_clone_perm <file/or/dir/perm/to/be/changed> <file/or/dir/to/clone/from>
susfs_clone_perm() {
	TO=$1
	FROM=$2
	if [ -z "${TO}" -o -z "${FROM}" ]; then
		return
	fi
	CLONED_PERM_STRING=$(stat -c "%a %U %G" ${FROM})
	set ${CLONED_PERM_STRING}
	chmod $1 ${TO}
	chown $2:$3 ${TO}
	busybox chcon --reference=${FROM} ${TO}
}

## susfs_hexpatch_props <target_prop_name> <spoofed_prop_name> <spoofed_prop_value>
susfs_hexpatch_props() {
	TARGET_PROP_NAME=$1
	SPOOFED_PROP_NAME=$2
	SPOOFED_PROP_VALUE=$3
	if [ -z "${TARGET_PROP_NAME}" -o -z "${SPOOFED_PROP_NAME}" -o -z "${SPOOFED_PROP_VALUE}" ]; then
		return 1
	fi
	if [ "${#TARGET_PROP_NAME}" != "${#SPOOFED_PROP_NAME}" ]; then
		return 1
	fi
	resetprop -n ${TARGET_PROP_NAME} ${SPOOFED_PROP_VALUE}
	magiskboot hexpatch /dev/__properties__/$(resetprop -Z ${TARGET_PROP_NAME}) $(echo -n ${TARGET_PROP_NAME} | xxd -p | tr "[:lower:]" "[:upper:]") $(echo -n ${SPOOFED_PROP_NAME} | xxd -p | tr "[:lower:]" "[:upper:]")
}

check_missing_prop() {
  local NAME=$1
  local EXPECTED=$2
  local VALUE=$(resetprop $NAME)
  [ -z $VALUE ] && resetprop $NAME $EXPECTED # if the property is missing
}

check_reset_prop() {
  local NAME=$1
  local EXPECTED=$2
  local VALUE=$(resetprop $NAME)
  [ -z $VALUE ] || [ $VALUE = $EXPECTED ] || resetprop $NAME $EXPECTED # if the property is not what we expect
}

check_missing_match_prop() {
  local NAME=$1
  local EXPECTED=$2
  local VALUE=$(resetprop $NAME)
  [ -z $VALUE ] || [ $VALUE = $EXPECTED ] || resetprop $NAME $EXPECTED # if the property is not what we expect
  [ -z $VALUE ] && resetprop $NAME $EXPECTED # if the property is missing
}

contains_reset_prop() {
  local NAME=$1
  local CONTAINS=$2
  local NEWVAL=$3
  [[ "$(resetprop $NAME)" = *"$CONTAINS"* ]] && resetprop $NAME $NEWVAL
}

spoof_uname() {
	[ -z $kernel_version ] && kernel_version='default'
	[ -z $kernel_build ] && kernel_build='default'
	${SUSFS_BIN} set_uname "$kernel_version" "$kernel_build"
}

## hookless SUSFS (KernelSU-Next `susfs-hookless`) normalization.
#
# hookless SUSFS reports version "v0.2" and feature names like "sus_path" /
# "open_redirect" instead of the "CONFIG_KSU_SUSFS_*" names the base scripts
# gate on, and it reports variant "hookless". As a result the base's
# version/feature gates (>= 1.5.x / CONFIG_KSU_SUSFS_*) would wrongly SKIP
# features hookless actually supports (hide_sus_mnts, spoof_cmdline,
# open_redirect, sus_map, sus_path_loop, ...).
#
# This is called once per script right after $version / $susfs_features /
# $SUSFS_DECIMAL_* are computed. On hookless it:
#   - flags SUSFS_HOOKLESS=1 (used to guard unsupported v2.x commands below)
#   - bumps SUSFS_DECIMAL_* to 2.5.9 so the base's v2.x code paths run for the
#     features hookless supports (hide_sus_mnts, set_cmdline_or_bootconfig,
#     open_redirect uid_scheme, sus_path_loop, and the feature-checked sus_su
#     disable path that avoids a failed `sus_su` call);
#   - appends CONFIG_KSU_SUSFS_OPEN_REDIRECT and CONFIG_KSU_SUSFS_SUS_MAP so
#     the base's feature gates recognise them.
#
# It deliberately does NOT add CONFIG_KSU_SUSFS_SUS_MOUNT / TRY_UMOUNT / SUS_SU:
# hookless removed the per-path add_sus_mount + add_try_umount commands (mount
# hiding is the global hide_sus_mnts_for_non_su_procs toggle + KSU umount
# policy) and sus_su needs the core kprobe hooks hookless disables. Those stay
# feature-gated out and are cleanly skipped.
susfs_hookless_normalize() {
	case "$susfs_features" in
		*hookless*)
			SUSFS_HOOKLESS=1
			SUSFS_DECIMAL_MAIN=2
			SUSFS_DECIMAL_SUB=5
			SUSFS_DECIMAL_PATCH=9
			case "$susfs_features" in *CONFIG_KSU_SUSFS_OPEN_REDIRECT*) ;; *)
				susfs_features="$susfs_features
CONFIG_KSU_SUSFS_OPEN_REDIRECT" ;; esac
			case "$susfs_features" in *CONFIG_KSU_SUSFS_SUS_MAP*) ;; *)
				susfs_features="$susfs_features
CONFIG_KSU_SUSFS_SUS_MAP" ;; esac
			;;
	esac
}

## convenience predicate for scripts that need a hookless branch
susfs_is_hookless() { [ "${SUSFS_HOOKLESS:-0}" = "1" ]; }

