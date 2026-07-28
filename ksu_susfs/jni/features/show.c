#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <susfs_defs.h>
#include <susfs_utils.h>
#include "show.h"

/*
 * show - return KPM identity / enabled features / variant to userspace.
 *
 * IMPORTANT: These commands do NOT use SUPERCALL_KPM_CONTROL.  The supercall
 * path requires is_authed, which is only granted to the APatch trusted-
 * manager UID (APK signature match) or a correct superkey.  ksu_susfs runs
 * in a root shell (uid 0) — NOT the trusted manager — so it can never get
 * is_authed, and supercall always returns -EPERM.
 *
 * Instead we parse the KPM's init-time printk lines from dmesg.  The KPM
 * emits (see susfs_kpm.c:susfs_init):
 *   susfs_kpm: version=<v> variant=<v> core_symbols=<0|1>
 *   susfs_kpm: features=<comma-separated CONFIG_KSU_SUSFS_* list>
 *   susfs_kpm: loaded
 *
 * This is instant (no superkey extraction, no supercall) and works
 * regardless of whether a superkey was preset.
 */

#define SUSFS_ENABLED_FEATURES_SIZE 8192
#define SUSFS_MAX_VERSION_BUFSIZE 16
#define SUSFS_MAX_VARIANT_BUFSIZE 16

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

/* Read a key=value field from dmesg's "susfs_kpm: <key>=<value>" lines.
 * Returns 0 on success, -1 if not found.  out must be at least outlen bytes. */
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
		if (dmesg_get_field("version", info, sizeof(info)) == 0) {
			log("%s\n", info);
			return 0;
		}
		log("[-] KPM susfs_kpm not loaded (no version in dmesg)\n");
		return -ENOSYS;
	} else if (!strcmp(argv[2], "enabled_features")) {
		/* The KPM prints features as a comma-separated list on a single
		 * dmesg line.  Convert to newline-separated for compatibility
		 * with the upstream susfs output format that scripts grep. */
		char *info = calloc(1, SUSFS_ENABLED_FEATURES_SIZE);
		if (!info) {
			perror("calloc");
			return -ENOMEM;
		}
		if (dmesg_get_field("features", info, SUSFS_ENABLED_FEATURES_SIZE) == 0) {
			/* Convert commas to newlines */
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
