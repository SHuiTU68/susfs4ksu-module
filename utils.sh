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
# gate on. On the universal binary the `show` subcommand is gated by
# HAVE(153) (g_version >= 153 in main.c); hookless parses "v0.2" to
# g_version=0, so `show version`, `show enabled_features` and `show variant`
# ALL fail with the message "[-] Requires susfs v1.5.3+".
#
# As a result:
#   - $version / $susfs_features contain that error string (non-empty, so
#     susfs_active is still touched — good);
#   - but $SUSFS_DECIMAL_* end up non-numeric and every version/feature gate
#     in the base scripts is skipped or errors out — bad.
#
# This is called once per script right after $version / $susfs_features /
# $SUSFS_DECIMAL_* are computed. On hookless it:
#   - flags SUSFS_HOOKLESS=1 (used to guard unsupported v2.x commands below);
#   - bumps SUSFS_DECIMAL_* to 2.5.9 so the base's v2.x code paths run for the
#     features hookless supports (hide_sus_mnts, set_cmdline_or_bootconfig,
#     open_redirect uid_scheme, sus_path_loop, ...);
#   - replaces $susfs_features with the CONFIG_KSU_SUSFS_* names hookless
#     actually supports, so the base's feature gates recognise them.
#
# It deliberately does NOT add CONFIG_KSU_SUSFS_SUS_MOUNT / TRY_UMOUNT /
# SUS_SU / AUTO_ADD_* / MAGIC_MOUNT / SUS_OVERLAYFS: hookless removed the
# per-path add_sus_mount + add_try_umount commands (mount hiding is the global
# hide_sus_mnts_for_non_su_procs toggle + KSU umount policy), sus_su needs the
# core kprobe hooks hookless disables, and the auto-add/magic-mount/overlayfs
# features belong to the full susfs patch. Those stay feature-gated out.
susfs_hookless_normalize() {
	[ "${SUSFS_HOOKLESS:-0}" = "1" ] && return

	# Detection path 1: older hookless builds reported "hookless" inside the
	# enabled_features string.
	case "$susfs_features" in
		*hookless*) SUSFS_HOOKLESS=1 ;;
	esac

	# Detection path 2: universal binary refuses `show` on hookless
	# (g_version=0 fails HAVE(153)), so both $version and $susfs_features
	# arrive as "[-] Requires susfs v1.5.3+". Confirm via the help banner,
	# which always prints "Detected kernel: susfs v0.2 (ABI: sys_reboot)".
	if [ "${SUSFS_HOOKLESS:-0}" != "1" ]; then
		case "$version" in
			*"Requires susfs"*)
				local _banner
				_banner=$(${SUSFS_BIN} 2>&1)
				case "$_banner" in
					*"susfs v0.2"*"sys_reboot"*) SUSFS_HOOKLESS=1 ;;
				esac
				;;
		esac
	fi

	[ "${SUSFS_HOOKLESS:-0}" != "1" ] && return

	# Bump decimal version so the base's v2.x code paths run.
	# Don't override $version — it's used for module.prop display and would
	# show a fake "v2.5.9" to the user; the decimal trio is enough for gates.
	SUSFS_DECIMAL_MAIN=2
	SUSFS_DECIMAL_SUB=5
	SUSFS_DECIMAL_PATCH=9

	# hookless supports: sus_path, sus_map, sus_kstat, spoof_uname,
	# spoof_cmdline_or_bootconfig, open_redirect, enable_log,
	# hide_ksu_susfs_symbols. Replace the error string with the proper
	# CONFIG_KSU_SUSFS_* names so feature gates recognise them.
	susfs_features="CONFIG_KSU_SUSFS_SUS_PATH
CONFIG_KSU_SUSFS_SUS_MAP
CONFIG_KSU_SUSFS_SUS_KSTAT
CONFIG_KSU_SUSFS_SPOOF_UNAME
CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
CONFIG_KSU_SUSFS_OPEN_REDIRECT
CONFIG_KSU_SUSFS_ENABLE_LOG
CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS"

	# Persist the hookless flag + normalised values so the ksu_susfs wrapper
	# (installed by customize.sh) can answer `show` queries from the WebUI,
	# which calls the binary directly and bypasses this normaliser.
	if [ -n "${tmpfolder:-}" ] && [ -d "$tmpfolder/logs" ]; then
		touch "$tmpfolder/logs/is_hookless"
		printf 'v2.5.9\n' > "$tmpfolder/logs/hookless_version"
		printf 'GKI\n' > "$tmpfolder/logs/hookless_variant"
		printf '%s\n' "$susfs_features" > "$tmpfolder/logs/hookless_features"
	fi
}

## convenience predicate for scripts that need a hookless branch
susfs_is_hookless() { [ "${SUSFS_HOOKLESS:-0}" = "1" ]; }

