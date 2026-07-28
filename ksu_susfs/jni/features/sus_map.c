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
#include "sus_map.h"

#define CMD_SUSFS_ADD_SUS_MAP 0x60020

void sus_map_print_help(void){
	log("    add_sus_map </path/to/actual/library>\n");
	log("      |--> added real file path which gets mmapped will be hidden from /proc/self/[maps|smaps|smaps_rollup|map_files|mem|pagemap]\n");
	log("      |--> e.g., add_sus_map '/data/adb/modules/my_module/zygisk/arm64-v8a.so'\n");
	log("      * Important Notes *\n");
	log("      - It does NOT support hiding for anon memory.\n");
	log("      - It does NOT hide any inline hooks or plt hooks cause by the injected library itself\n");
	log("      - It may not be able to evade detections by apps that implement a good injection detection\n");
	log("      - Only effective for umounted process with uid >= 10000\n");
	log("\n");
}

static void print_help(void){
	print_help_banner();
	sus_map_print_help();
}

int add_sus_map(int argc, char *argv[]) {
	if (argc != 3) {
		print_help();
		return -EINVAL;
	}

	if (*argv[2] == '\0') {
		log("[-] argv[2] is empty'\n");
		return -EINVAL;
	}

	int rc = kpm_send(CMD_SUSFS_ADD_SUS_MAP, "%s", argv[2]);
	if (rc == -ENOSYS) {
		log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_ADD_SUS_MAP);
	}
	return rc;
}
