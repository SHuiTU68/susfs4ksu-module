/*
 * susfs_cmds.h - susfs command codes (single source of truth for ksu_susfs).
 *
 * Mirrors the authoritative kernel table in
 *   luyanci/susfs4oki  kernel_patches/include/linux/susfs_def.h
 * (susfs v2.3.0, the reference implementation this APatch KPM reimplements).
 *
 * Why this file exists: upstream susfs4ksu-module re-`#define`s the CMD_*
 * values inside every feature .c file.  That made it easy for the APatch KPM
 * port to drift out of sync (it had ADD_TRY_UMOUNT=0x55562 and
 * ADD_SUS_MOUNT=0x55564, which in real susfs mean
 * UMOUNT_FOR_ZYGOTE_ISO_SERVICE and nothing at all).  Keeping the table in
 * one place means the CLI can never disagree with the KPM about a code.
 *
 * The values are wire-compatible with stock susfs, so:
 *   - a stock `ksu_susfs` binary built for a real susfs kernel would still
 *     address the same features if pointed at the KPM channel, and
 *   - the KPM can be diffed against susfs_def.h at a glance.
 *
 * Codes marked [deprecated] exist only for compatibility: the KPM either
 * implements them on top of its hybrid (userspace-assisted) machinery or
 * returns 0 as an advisory no-op.  They are printed in the same order as
 * susfs_def.h so the two files can be diffed directly.
 */
#ifndef SUSFS_CMDS_H
#define SUSFS_CMDS_H

/* ===== paths ===== */
#define CMD_SUSFS_ADD_SUS_PATH                    0x55550
#define CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH      0x55551 /* [deprecated] */
#define CMD_SUSFS_SET_SDCARD_ROOT_PATH            0x55552 /* [deprecated] */
#define CMD_SUSFS_ADD_SUS_PATH_LOOP               0x55553

/* ===== mounts ===== */
#define CMD_SUSFS_ADD_SUS_MOUNT                   0x55560 /* [deprecated] */
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS  0x55561
#define CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE   0x55562 /* [deprecated] */

/* ===== kstat ===== */
#define CMD_SUSFS_ADD_SUS_KSTAT                   0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT                0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY        0x55572

/* ===== try_umount (userspace umount -l assist) ===== */
#define CMD_SUSFS_ADD_TRY_UMOUNT                  0x55580 /* [deprecated] */

/* ===== misc toggles ===== */
#define CMD_SUSFS_SET_UNAME                       0x55590
#define CMD_SUSFS_ENABLE_LOG                      0x555a0
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG       0x555b0
#define CMD_SUSFS_ADD_OPEN_REDIRECT               0x555c0

/* ===== show / query ===== */
#define CMD_SUSFS_SHOW_VERSION                    0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES           0x555e2
#define CMD_SUSFS_SHOW_VARIANT                    0x555e3
#define CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE        0x555e4 /* [deprecated] */
#define CMD_SUSFS_IS_SUS_SU_READY                 0x555f0 /* [deprecated] */

/* ===== sus_su (not implemented by the KPM, kept for wire parity) ===== */
#define CMD_SUSFS_SUS_SU                          0x60000 /* [deprecated] */

/* ===== newer features ===== */
#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING         0x60010
#define CMD_SUSFS_ADD_SUS_MAP                     0x60020

/* ===== KPM-only extension (NOT part of stock susfs) =====
 * Stock susfs has no equivalent: upstream implements
 * auto_add_try_umount_for_bind_mount entirely in userspace (post-fs-data.sh
 * walks /proc/mounts and calls add_try_umount per entry).  This KPM exposes
 * a single advisory command that tells the kernel module to mark the bind
 * mounts it already knows about, which the userspace half then detaches.
 * 0x55563 is an unused hole in susfs_def.h, so it can never collide with a
 * future stock command that is still below 0x55570.  Keep it outside the
 * documented ranges when reviewing.
 */
#define CMD_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT 0x55563 /* KPM-only */

#endif /* SUSFS_CMDS_H */
