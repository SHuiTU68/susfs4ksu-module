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
#include "show.h"

#define CMD_SUSFS_SHOW_VERSION 0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES 0x555e2
#define CMD_SUSFS_SHOW_VARIANT 0x555e3

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

int show(int argc, char *argv[]) {
	if (argc != 3) {
		print_help();
		return -EINVAL;
	}

	if (!strcmp(argv[2], "version")) {
		char info[SUSFS_MAX_VERSION_BUFSIZE] = {0};
		int rc = kpm_send_recv(CMD_SUSFS_SHOW_VERSION, NULL, info, sizeof(info));
		if (rc == -ENOSYS) {
			log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_SHOW_VERSION);
		} else if (rc == 0) {
			log("%s\n", info);
		}
		return rc;
	} else if (!strcmp(argv[2], "enabled_features")) {
		char *info = calloc(1, SUSFS_ENABLED_FEATURES_SIZE);
		if (!info) {
			perror("calloc");
			return -ENOMEM;
		}
		int rc = kpm_send_recv(CMD_SUSFS_SHOW_ENABLED_FEATURES, NULL, info, SUSFS_ENABLED_FEATURES_SIZE);
		if (rc == -ENOSYS) {
			log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_SHOW_ENABLED_FEATURES);
		} else if (rc == 0) {
			log("%s", info); /* KPM already includes trailing newline */
		}
		free(info);
		return rc;
	} else if (!strcmp(argv[2], "variant")) {
		char info[SUSFS_MAX_VARIANT_BUFSIZE] = {0};
		int rc = kpm_send_recv(CMD_SUSFS_SHOW_VARIANT, NULL, info, sizeof(info));
		if (rc == -ENOSYS) {
			log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_SHOW_VARIANT);
		} else if (rc == 0) {
			log("%s\n", info);
		}
		return rc;
	} else {
		print_help();
	}
	return -EINVAL;
}
