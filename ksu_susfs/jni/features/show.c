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
 * Two strategies, tried in order:
 *
 * 1. Syscall command channel (primary): The KPM hooks __NR_kcmp (272) and
 *    checks for SUSFS_CMD_MAGIC.  If the hook is installed, the show
 *    commands are dispatched via susfs_ctl0() in the kernel and return
 *    the real-time values.  This is the most reliable path.
 *
 * 2. dmesg parsing (fallback): The KPM printk's at init:
 *      susfs_kpm: version=<v> variant=<v> core_symbols=<0|1>
 *      susfs_kpm: features=<comma-separated CONFIG_KSU_SUSFS_* list>
 *      susfs_kpm: loaded
 *    We parse these lines.  This works even if the syscall hook failed
 *    but the KPM is loaded.
 *
 * Neither path uses SUPERCALL_KPM_CONTROL (which requires is_authed and
 * always returns -EPERM for root shell without a preset superkey).
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
		/* Fallback: dmesg */
		if (dmesg_get_field("version", info, sizeof(info)) == 0) {
			log("%s\n", info);
			return 0;
		}
		log("[-] KPM susfs_kpm not loaded (no version in dmesg)\n");
		return -ENOSYS;
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
		/* Fallback: dmesg */
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
		free(info);
		log("[-] KPM susfs_kpm not loaded (no features in dmesg)\n");
		return -ENOSYS;
	} else if (!strcmp(argv[2], "variant")) {
		char info[SUSFS_MAX_VARIANT_BUFSIZE] = {0};
		/* Try syscall channel first */
		if (syscall_show(CMD_SUSFS_SHOW_VARIANT, info, sizeof(info)) == 0) {
			log("%s\n", info);
			return 0;
		}
		/* Fallback: dmesg */
		if (dmesg_get_field("variant", info, sizeof(info)) == 0) {
			log("%s\n", info);
			return 0;
		}
		log("[-] KPM susfs_kpm not loaded (no variant in dmesg)\n");
		return -ENOSYS;
	} else {
		print_help();
	}
	return -EINVAL;
}
