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
#include "avc_log_spoofing.h"

#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING 0x60010

void enable_avc_log_spoofing_print_help(void){
	log("    enable_avc_log_spoofing <0|1>\n");
	log("      |--> 0: disable spoofing the sus tcontext 'su' shown in avc log in kernel\n");
	log("      |--> 1: enable spoofing the sus tcontext 'su' with 'u:r:priv_app:s0:c512,c768' shown in avc log in kernel\n");
	log("      * Important Notes *\n");
	log("      - Hooks audit_log_format() to rewrite tcontext in AVC audit logs\n");
	log("      - It is set to '0' by default in kernel\n");
	log("      - Enabling this may sometimes make developers hard to identify the cause when they are debugging with some permission or selinux issues, so users are advised to disable this when doing so.\n");
	log("\n");
}

static void print_help(void){
	print_help_banner();
	enable_avc_log_spoofing_print_help();
}

int enable_avc_log_spoofing(int argc, char *argv[]) {
	if (argc != 3) {
		print_help();
		return -EINVAL;
	}

	if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) {
		print_help();
		return -EINVAL;
	}
	int enabled = atoi(argv[2]);
	int rc = kpm_send(CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING, "%d", enabled);
	if (rc == -ENOSYS) {
		log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING);
	}
	return rc;
}
