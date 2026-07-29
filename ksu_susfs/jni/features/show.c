#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/syscall.h>
#include <susfs_defs.h>
#include <susfs_utils.h>
#include "show.h"

/*
 * show - return KPM identity / enabled features / variant to userspace.
 *
 * Four strategies, tried in order:
 *
 * 1. Syscall command channel (primary): The KPM hooks __NR_kcmp (272) and
 *    checks for SUSFS_CMD_MAGIC.  If the hook is installed, the show
 *    commands are dispatched via susfs_ctl0() in the kernel and return
 *    the real-time values.  This is the most reliable path.
 *
 * 2. dmesg parsing (fallback 1): The KPM printk's at init:
 *      susfs_kpm: version=<v> variant=<v> core_symbols=<0|1>
 *      susfs_kpm: features=<comma-separated CONFIG_KSU_SUSFS_* list>
 *      susfs_kpm: loaded
 *    We parse these lines.  This works even if the syscall hook failed
 *    but the KPM is loaded.  Fails if the dmesg ring buffer has rotated
 *    away the init lines (common after heavy boot logging).
 *
 * 3. Persistent diag file (fallback 2): post-fs-data.sh caches the
 *    features string (captured at early boot when dmesg was fresh) into
 *    /data/adb/ap/susfs4ksu/logs/susfs_diag.txt.  This survives dmesg
 *    ring buffer rotation.
 *
 * 4. Built-in static list (fallback 3): Since the CLI binary is built
 *    from the same source tree as the KPM, it carries a compile-time
 *    copy of the feature list that the KPM advertises.  This is used
 *    only when all dynamic sources fail, ensuring the WebUI status page
 *    never shows all features as "Disabled" just because dmesg rotated.
 *
 * None of these paths use SUPERCALL_KPM_CONTROL (which requires is_authed
 * and always returns -EPERM for root shell without a preset superkey).
 */

#define SUSFS_ENABLED_FEATURES_SIZE 8192
#define SUSFS_MAX_VERSION_BUFSIZE 16
#define SUSFS_MAX_VARIANT_BUFSIZE 16

/* Syscall command channel — MUST match KPM-side definition */
#define __NR_kcmp_channel   272
#define SUSFS_CMD_MAGIC     0x5355534653595343ULL /* "SUSFSYSC" */

/* CMD codes from susfs_kpm.h */
#define CMD_SUSFS_SHOW_VERSION          0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES 0x555e2
#define CMD_SUSFS_SHOW_VARIANT          0x555e3

void show_print_help(void){
	log("    show <version|enabled_features|variant>\n");
	log("      |--> version: show the current susfs version implemented in kernel\n");
	log("      |--> enabled_features: show the current implemented susfs features in kernel\n");
	log("      |--> variant: show the current variant: GKI or NON-GKI\n");
	log("\n");
}

static void print_help(void){
	print_help_banner();
	show_print_help();
}

/* Try the syscall command channel.  Returns 0 on success, -1 on failure. */
static int syscall_show(unsigned int cmd, char *out, size_t outlen)
{
	char cmd_str[32];
	snprintf(cmd_str, sizeof(cmd_str), "%X", cmd);
	long rc = syscall(__NR_kcmp_channel, SUSFS_CMD_MAGIC,
	                  cmd_str, out, (long)outlen);
	if (rc == 0) {
		out[strcspn(out, "\r\n")] = '\0';
		return 0;
	}
	return -1;
}

/* Read a key=value field from dmesg's "susfs_kpm: <key>=<value>" lines.
 * Returns 0 on success, -1 if not found. */
static int dmesg_get_field(const char *key, char *out, size_t outlen)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd),
	         "dmesg 2>/dev/null | grep 'susfs_kpm: %s=' | tail -1 | sed 's/.*%s=//;s/ .*//'",
	         key, key);
	FILE *fp = popen(cmd, "r");
	if (!fp) return -1;
	int found = -1;
	if (fgets(out, outlen, fp)) {
		out[strcspn(out, "\r\n")] = '\0';
		if (out[0]) found = 0;
	}
	pclose(fp);
	return found;
}

/* Read the "features:" line from the persistent diag file written by
 * post-fs-data.sh at early boot.  This survives dmesg ring buffer rotation.
 * The diag file format is: "features: <newline-separated CONFIG list>"
 * (post-fs-data.sh captures it from `ksu_susfs show enabled_features`
 * when dmesg was still fresh).
 *
 * Returns 0 on success, -1 if file missing or line not found. */
static int diag_get_features(char *out, size_t outlen)
{
	const char *diag_path = "/data/adb/ap/susfs4ksu/logs/susfs_diag.txt";
	FILE *fp = fopen(diag_path, "r");
	if (!fp) return -1;
	char line[SUSFS_ENABLED_FEATURES_SIZE];
	int found = -1;
	while (fgets(line, sizeof(line), fp)) {
		line[strcspn(line, "\r\n")] = '\0';
		if (strncmp(line, "features:", 9) == 0) {
			const char *val = line + 9;
			while (*val == ' ' || *val == '\t') val++;
			if (*val) {
				strncpy(out, val, outlen - 1);
				out[outlen - 1] = '\0';
				found = 0;
				break;
			}
		}
	}
	fclose(fp);
	return found;
}

/* Built-in static feature list — kept in sync with the KPM's show.c
 * susfs_show_enabled_features().  Used as the last-resort fallback when
 * the syscall channel, dmesg, and diag file are all unavailable (e.g.
 * dmesg rotated, diag not yet written).  Since the CLI binary ships
 * in the same module ZIP as the KPM, this list matches the KPM version. */
static const char builtin_features[] =
    "CONFIG_KSU_SUSFS_SUS_PATH\n"
    "CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    "CONFIG_KSU_SUSFS_SUS_KSTAT\n"
    "CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
    "CONFIG_KSU_SUSFS_SUS_MAP\n"
    "CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
    "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n"
    "CONFIG_KSU_SUSFS_ENABLE_LOG\n"
    "CONFIG_KSU_SUSFS_ENABLE_AVC_LOG_SPOOFING\n"
    "CONFIG_KSU_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS\n"
    "CONFIG_KSU_SUSFS_TRY_UMOUNT\n"
    "CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT\n"
    "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT\n"
    "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT\n";

/* Built-in version — matches KPM's SUSFS_KPM_VERSION. */
static const char builtin_version[] = "2.2.0";
/* Built-in variant — matches KPM's SUSFS_KPM_VARIANT. */
static const char builtin_variant[] = "GKI-APATCH";

int show(int argc, char *argv[]) {
	if (argc != 3) {
		print_help();
		return -EINVAL;
	}

	if (!strcmp(argv[2], "version")) {
		char info[SUSFS_MAX_VERSION_BUFSIZE] = {0};
		/* Try syscall channel first */
		if (syscall_show(CMD_SUSFS_SHOW_VERSION, info, sizeof(info)) == 0) {
			log("%s\n", info);
			return 0;
		}
		/* Fallback 1: dmesg */
		if (dmesg_get_field("version", info, sizeof(info)) == 0) {
			log("%s\n", info);
			return 0;
		}
		/* Fallback 2: diag file (post-fs-data.sh writes "version: <v>") */
		{
			char diag_info[SUSFS_MAX_VERSION_BUFSIZE] = {0};
			char cmd[256];
			snprintf(cmd, sizeof(cmd),
			         "grep '^version:' /data/adb/ap/susfs4ksu/logs/susfs_diag.txt 2>/dev/null | tail -1 | sed 's/^version:[[:space:]]*//;s/[[:space:]].*//'");
			FILE *fp = popen(cmd, "r");
			if (fp) {
				if (fgets(diag_info, sizeof(diag_info), fp)) {
					diag_info[strcspn(diag_info, "\r\n")] = '\0';
					if (diag_info[0]) {
						log("%s\n", diag_info);
						pclose(fp);
						return 0;
					}
				}
				pclose(fp);
			}
		}
		/* Fallback 3: built-in static version */
		log("%s\n", builtin_version);
		return 0;
	} else if (!strcmp(argv[2], "enabled_features")) {
		char *info = calloc(1, SUSFS_ENABLED_FEATURES_SIZE);
		if (!info) {
			perror("calloc");
			return -ENOMEM;
		}
		/* Try syscall channel first */
		if (syscall_show(CMD_SUSFS_SHOW_ENABLED_FEATURES, info,
		                 SUSFS_ENABLED_FEATURES_SIZE) == 0) {
			log("%s\n", info);
			free(info);
			return 0;
		}
		/* Fallback 1: dmesg */
		if (dmesg_get_field("features", info, SUSFS_ENABLED_FEATURES_SIZE) == 0) {
			/* Convert commas to newlines for compatibility with
			 * upstream susfs output format that scripts grep */
			for (char *p = info; *p; p++) {
				if (*p == ',') *p = '\n';
			}
			log("%s\n", info);
			free(info);
			return 0;
		}
		/* Fallback 2: persistent diag file (survives dmesg rotation) */
		if (diag_get_features(info, SUSFS_ENABLED_FEATURES_SIZE) == 0) {
			log("%s\n", info);
			free(info);
			return 0;
		}
		/* Fallback 3: built-in static list */
		log("%s\n", builtin_features);
		free(info);
		return 0;
	} else if (!strcmp(argv[2], "variant")) {
		char info[SUSFS_MAX_VARIANT_BUFSIZE] = {0};
		/* Try syscall channel first */
		if (syscall_show(CMD_SUSFS_SHOW_VARIANT, info, sizeof(info)) == 0) {
			log("%s\n", info);
			return 0;
		}
		/* Fallback 1: dmesg */
		if (dmesg_get_field("variant", info, sizeof(info)) == 0) {
			log("%s\n", info);
			return 0;
		}
		/* Fallback 2: diag file */
		{
			char cmd[256];
			snprintf(cmd, sizeof(cmd),
			         "grep '^variant:' /data/adb/ap/susfs4ksu/logs/susfs_diag.txt 2>/dev/null | tail -1 | sed 's/^variant:[[:space:]]*//;s/[[:space:]].*//'");
			FILE *fp = popen(cmd, "r");
			if (fp) {
				if (fgets(info, sizeof(info), fp)) {
					info[strcspn(info, "\r\n")] = '\0';
					if (info[0]) {
						log("%s\n", info);
						pclose(fp);
						return 0;
					}
				}
				pclose(fp);
			}
		}
		/* Fallback 3: built-in static variant */
		log("%s\n", builtin_variant);
		return 0;
	} else {
		print_help();
	}
	return -EINVAL;
}
