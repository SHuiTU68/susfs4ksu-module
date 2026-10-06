#!/system/bin/sh
# metainstall.sh - appended to the installer of every *regular* module install.
#
# apd/src/metamodule.rs::get_install_script() builds
# `{installer_content}\n{metamodule_content}\nexit 0\n`, so this runs last in
# the installer, with MODULE_ID and MODPATH set.
#
# There is nothing to mount here: injection happens at post-fs-data, and the
# freshly installed tree is picked up by then.  What this script is for is the
# case where the user does *not* want to reboot - it records the change so that
# action.sh (the module's Action button) or the next boot can apply it.
#
# Caveat worth knowing: shipping metainstall.sh is what puts this metamodule
# into apd's check_install_safety() branch.  While the metamodule carries an
# update/remove/disable marker, APatch will refuse to install modules that need
# mounting, telling the user to reboot first.  That is the price of being able
# to react to installs at all.

DATA_DIR=/data/adb/kpmmount
[ -d "$DATA_DIR" ] || mkdir -p "$DATA_DIR"

printf '%s install %s %s\n' "$(date '+%F %T')" "${MODULE_ID:-unknown}" "${MODPATH:-}" >> "$DATA_DIR/pending"

ui_print "- recorded ${MODULE_ID:-module} for the mount engine"
ui_print "- tap Action on KPM Mount to apply it now, or just reboot"
