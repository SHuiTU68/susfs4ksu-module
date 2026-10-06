#!/system/bin/sh
# metauninstall.sh - called when a module is uninstalled, with MODULE_ID set.
#
# We deliberately do not clear the engine's rules here.  Rules are built as a
# whole set at post-fs-data, so clearing them at runtime would make *every*
# module's files vanish until the next boot, which is a much worse failure than
# one stale module lingering until a reboot.  All we do is record the change so
# the Action button can rebuild the set on demand.

DATA_DIR=/data/adb/kpmmount
[ -d "$DATA_DIR" ] || mkdir -p "$DATA_DIR"

printf '%s uninstall %s\n' "$(date '+%F %T')" "${MODULE_ID:-unknown}" >> "$DATA_DIR/pending"

ui_print "- ${MODULE_ID:-module} will be gone from the mount set after a rebuild"
ui_print "- tap Action on KPM Mount to rebuild now, or just reboot"
