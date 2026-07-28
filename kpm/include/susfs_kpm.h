/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * susfs_kpm - KernelPatch Module reimplementation of susfs for APatch
 *
 * Targets: android15-6.6 GKI kernel only.
 * Receives commands from userspace via sc_kpm_control() with a text protocol:
 *   "<CMD_HEX>|<arg1>|<arg2>|..."
 */
#ifndef SUSFS_KPM_H
#define SUSFS_KPM_H

/* Command codes — kept identical to upstream susfs so ksu_susfs CLI stays familiar */
#define CMD_SUSFS_ADD_SUS_PATH              0x55550
#define CMD_SUSFS_ADD_SUS_PATH_LOOP         0x55553
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU  0x55561
#define CMD_SUSFS_ADD_SUS_KSTAT             0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT          0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY  0x55572
#define CMD_SUSFS_SET_UNAME                 0x55590
#define CMD_SUSFS_ENABLE_LOG                0x555a0
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG 0x555b0
#define CMD_SUSFS_ADD_OPEN_REDIRECT         0x555c0
#define CMD_SUSFS_SHOW_VERSION              0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES     0x555e2
#define CMD_SUSFS_SHOW_VARIANT              0x555e3
#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING   0x60010
#define CMD_SUSFS_ADD_SUS_MAP               0x60020

#define SUSFS_MAX_LEN_PATHNAME              256
#define SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE 8192
#define SUSFS_ENABLED_FEATURES_SIZE         8192
#define SUSFS_MAX_VERSION_BUFSIZE           16
#define SUSFS_MAX_VARIANT_BUFSIZE           16
#define __NEW_UTS_LEN                       64

/* KPM identity exposed to userspace.
 * VERSION is set to "1.5.2" so the existing module scripts' version checks
 * (which parse the susfs version string) behave correctly.  The KPM itself
 * does not enforce this — it's purely informational for userspace. */
#define SUSFS_KPM_NAME    "susfs_kpm"
#define SUSFS_KPM_VERSION "1.5.2"
#define SUSFS_KPM_VARIANT "GKI-APATCH"

/* UID schemes for open_redirect (mirror upstream enum) */
enum uid_scheme {
    UID_NON_APP_PROC = 0,
    UID_ROOT_PROC_EXCEPT_SU_PROC,
    UID_NON_SU_PROC,
    UID_UMOUNTED_APP_PROC,
    UID_UMOUNTED_PROC,
};

/* Shared feature prototypes */
struct sus_path_entry;
struct open_redirect_entry;
struct sus_kstat_entry;
struct sus_map_entry;

/* features/sus_path.c */
int susfs_add_sus_path(const char *path, int is_loop);
void susfs_sus_path_cleanup(void);
int susfs_sus_path_init_hooks(void);

/* features/open_redirect.c */
int susfs_add_open_redirect(const char *target, const char *redirected, int uid_scheme);
void susfs_open_redirect_cleanup(void);
int susfs_open_redirect_init_hooks(void);

/* features/sus_mount.c */
int susfs_set_hide_sus_mnts(int enabled);
void susfs_sus_mount_cleanup(void);
int susfs_sus_mount_init_hooks(void);

/* features/sus_kstat.c */
int susfs_add_sus_kstat(const char *path, unsigned long target_ino,
                        unsigned long spoofed_ino, unsigned long spoofed_dev,
                        unsigned int spoofed_nlink, long long spoofed_size,
                        long atime_sec, unsigned long atime_nsec,
                        long mtime_sec, unsigned long mtime_nsec,
                        long ctime_sec, unsigned long ctime_nsec,
                        long long blocks, long blksize, int flags, int is_static);
void susfs_sus_kstat_cleanup(void);
int susfs_sus_kstat_init_hooks(void);

/* features/sus_map.c */
int susfs_add_sus_map(const char *path);
void susfs_sus_map_cleanup(void);
int susfs_sus_map_init_hooks(void);

/* features/set_uname.c */
int susfs_set_uname(const char *release, const char *version);
void susfs_set_uname_cleanup(void);
int susfs_set_uname_init_hooks(void);

/* features/set_cmdline.c */
int susfs_set_cmdline_or_bootconfig(const char *content);
void susfs_set_cmdline_cleanup(void);
int susfs_set_cmdline_init_hooks(void);

/* features/flags.c */
int susfs_set_log_enabled(int enabled);
int susfs_set_avc_log_spoofing(int enabled);
int susfs_get_log_enabled(void);
int susfs_get_avc_log_spoofing(void);

/* features/show.c */
int susfs_show_version(char *out, int outlen);
int susfs_show_enabled_features(char *out, int outlen);
int susfs_show_variant(char *out, int outlen);

#endif /* SUSFS_KPM_H */
