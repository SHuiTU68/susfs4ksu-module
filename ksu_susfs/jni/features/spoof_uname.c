#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <errno.h>
#include <susfs_defs.h>
#include <susfs_utils.h>
#include <kpm_call.h>
#include "spoof_uname.h"

#define CMD_SUSFS_SET_UNAME 0x55590

#ifndef __NEW_UTS_LEN
#define __NEW_UTS_LEN 64
#endif

void set_uname_print_help(void){
	log("    set_uname <release> <version>\n");
	log("      |--> Spoof uname for all processes, set string to 'default' to imply the function to use original string\n");
	log("      |--> NOTE: only 'release' and <version> are spoofed as others are no longer needed\n");
	log("      |--> e.g., set_uname '4.9.337-g3291538446b7' '#1 SMP PREEMPT Mon Oct 6 16:50:48 UTC 2025'\n");
	log("\n");
}

static void print_help(void){
	print_help_banner();
	set_uname_print_help();
}

int set_uname(int argc, char *argv[]) {
	if (argc != 4) {
		print_help();
		return -EINVAL;
	}

	if (*argv[2] == '\0') {
		log("[-] argv[2] is empty'\n");
		return -EINVAL;
	}

	if (*argv[3] == '\0') {
		log("[-] argv[3] is empty'\n");
		return -EINVAL;
	}

	/* The text protocol uses '|' as field separator, so any '|' inside the
	 * release/version strings would break parsing.  Uname release/version
	 * strings don't normally contain '|', but bail out defensively. */
	if (strchr(argv[2], '|') || strchr(argv[3], '|')) {
		log("[-] release/version cannot contain '|'\n");
		return -EINVAL;
	}

	int rc = kpm_send(CMD_SUSFS_SET_UNAME, "%s|%s", argv[2], argv[3]);
	if (rc == -ENOSYS) {
		log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_SET_UNAME);
	}
	return rc;
}
