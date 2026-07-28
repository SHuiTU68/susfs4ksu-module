#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <errno.h>
#include <limits.h>
#include <susfs_defs.h>
#include <susfs_utils.h>
#include <kpm_call.h>
#include "sus_path.h"

#define CMD_SUSFS_ADD_SUS_PATH 0x55550
#define CMD_SUSFS_ADD_SUS_PATH_LOOP 0x55553

void sus_path_print_help(void){
	log("    add_sus_path </path/of/file_or_directory>\n");
	log("      |--> Added path and all its sub-paths will be hidden for umounted app process from several syscalls\n");
	log("      |--> Please be reminded that if the target path has upper mounts then make sure the proper layer is added, otherwise it may not be effective for the target process.\n");
	log("      * Important Notes *\n");
	log("      - Only effective for umounted process with uid >= 10000\n");
	log("\n");
	log("    add_sus_path_loop </path/of/file_or_directory>\n");
	log("      |--> The only difference to add_sus_path is that the added sus_path via this cli will be flagged as SUS_PATH again for the app process when it is being spawned by zygote and marked umounted\n");
	log("      |--> Also it does not check if the path is existed or not, instead it checks for empty string only, so be careful what to add.\n");
	log("      * Important Notes *\n");
	log("      - Only effective for umounted process with uid >= 10000\n");
	log("\n");
}

static void print_help(void){
	print_help_banner();
	sus_path_print_help();
}

int add_sus_path(int argc, char *argv[]) {
	char resolved_pathname[PATH_MAX];

	if (argc != 3) {
		print_help();
		return -EINVAL;
	}

	if (*argv[2] == '\0') {
		log("[-] argv[2] is empty'\n");
		return -EINVAL;
	}

	if (!realpath(argv[2], resolved_pathname)) {
		log("[-] failed to get realpath from path: %s\n", argv[2]);
		return errno;
	}

	int rc = kpm_send(CMD_SUSFS_ADD_SUS_PATH, "%s", resolved_pathname);
	if (rc == -ENOSYS) {
		log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_ADD_SUS_PATH);
	}
	return rc;
}

int add_sus_path_loop(int argc, char *argv[]) {
	if (argc != 3) {
		print_help();
		return -EINVAL;
	}

	if (*argv[2] == '\0') {
		log("[-] argv[2] is empty'\n");
		return -EINVAL;
	}

	int rc = kpm_send(CMD_SUSFS_ADD_SUS_PATH_LOOP, "%s", argv[2]);
	if (rc == -ENOSYS) {
		log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_ADD_SUS_PATH_LOOP);
	}
	return rc;
}
