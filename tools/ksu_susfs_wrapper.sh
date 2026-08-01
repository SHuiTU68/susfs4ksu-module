#!/system/bin/sh
# ksu_susfs wrapper for hookless SUSFS (KernelSU-Next susfs-hookless).
#
# The universal ksu_susfs binary gates its `show` subcommand on HAVE(153)
# (g_version >= 153 in main.c). hookless kernels report version "v0.2" which
# parses to g_version=0, so `show version`, `show enabled_features` and
# `show variant` ALL fail with "[-] Requires susfs v1.5.3+". The WebUI calls
# the binary directly (bypassing the shell-side susfs_hookless_normalize in
# utils.sh), so without this wrapper the WebUI's feature badges all show
# "Disabled" and the variant/version fields display the error string.
#
# This wrapper:
#   - Fast-paths every non-`show` command straight to the real binary via
#     exec (zero overhead — the shell is replaced by the ELF).
#   - For `show` on hookless, returns the normalised values that
#     susfs_hookless_normalize wrote to $tmpfolder/logs/hookless_*.
#   - For `show` on non-hookless (or before post-fs-data.sh has run), falls
#     through to the real binary so behaviour is unchanged.
#
# The real binary lives at ksu_susfs.bin (next to this wrapper). The install
# flow (customize.sh) and the bin-update/check scripts both target ksu_susfs.bin
# so this wrapper is never overwritten by a binary update.

REAL_BIN=/data/adb/ksu/bin/ksu_susfs.bin
LOGDIR=/data/adb/ksu/susfs4ksu/logs

# Anything that isn't `show` goes straight to the real binary.
case "${1:-}" in
	show) ;;
	*) exec "$REAL_BIN" "$@" ;;
esac

# Only intercept `show` when hookless has been detected and the cache files
# have been written by susfs_hookless_normalize (post-fs-data.sh runs first
# at boot, so by the time the WebUI opens these files exist).
if [ -f "$LOGDIR/is_hookless" ]; then
	case "${2:-}" in
		version)
			[ -f "$LOGDIR/hookless_version" ] && { cat "$LOGDIR/hookless_version"; exit 0; }
			;;
		variant)
			[ -f "$LOGDIR/hookless_variant" ] && { cat "$LOGDIR/hookless_variant"; exit 0; }
			;;
		enabled_features)
			[ -f "$LOGDIR/hookless_features" ] && { cat "$LOGDIR/hookless_features"; exit 0; }
			;;
	esac
fi

# Not hookless, or cache missing — defer to the real binary.
exec "$REAL_BIN" "$@"
