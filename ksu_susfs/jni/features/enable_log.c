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
#include "enable_log.h"

#define CMD_SUSFS_ENABLE_LOG 0x555a0

void enable_log_print_help(void){
	log("    enable_log <0|1>\n");
	log("      |--> 0: disable susfs log in kernel\n");
	log("      |--> 1: enable susfs log in kernel\n");
	log("\n");
}

static void print_help(void){
	print_help_banner();
	enable_log_print_help();
}

int enable_log(int argc, char *argv[]) {
	if (argc != 3) {
		print_help();
		return -EINVAL;
	}

	if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) {
		print_help();
		return -EINVAL;
	}
	int enabled = atoi(argv[2]);
	int rc = kpm_send(CMD_SUSFS_ENABLE_LOG, "%d", enabled);
	if (rc == -ENOSYS) {
		log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_ENABLE_LOG);
	}
	return rc;
}
