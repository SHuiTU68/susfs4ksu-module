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
#include "spoof_cmdline_or_bootconfig.h"

#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG 0x555b0

#define SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE 8192

void set_cmdline_or_bootconfig_print_help(void){
	log("    set_cmdline_or_bootconfig </path/to/fake_cmdline_file/or/fake_bootconfig_file>\n");
	log("      |--> Spoof the output of /proc/cmdline (non-gki) or /proc/bootconfig (gki) from a text file\n");
	log("\n");
}

static void print_help(void){
	print_help_banner();
	set_cmdline_or_bootconfig_print_help();
}

int set_cmdline_or_bootconfig(int argc, char *argv[]) {
	char resolved_pathname[PATH_MAX];
	FILE *file;
	long file_size;
	size_t read_size;
	int err = 0;
	char buf[SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE];

	if (argc != 3) {
		print_help();
		return -EINVAL;
	}

	if (*argv[2] == '\0') {
		log("[-] argv[2] is empty'\n");
		return -EINVAL;
	}

	if (!realpath(argv[2], resolved_pathname)) {
		perror("realpath");
		return errno;
	}
	file = fopen(resolved_pathname, "rb");
	if (file == NULL) {
		perror("error opening file");
		return errno;
	}
	fseek(file, 0, SEEK_END);
	file_size = ftell(file);
	if (file_size >= SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE) {
		perror("file_size too long");
		fclose(file);
		return -EINVAL;
	}
	rewind(file);
	read_size = fread(buf, 1, file_size, file);
	if (read_size != file_size) {
		perror("reading error");
		fclose(file);
		return -EFAULT;
	}
	fclose(file);
	buf[file_size] = '\0';

	/* The text protocol splits fields on '|'.  Replace any '|' in the
	 * fake cmdline content with '\n' — /proc/bootconfig is multi-line
	 * anyway, and '|' is extremely unlikely in real cmdlines. */
	for (size_t i = 0; i < (size_t)file_size; i++) {
		if (buf[i] == '|') buf[i] = '\n';
	}

	int rc = kpm_send(CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG, "%s", buf);
	if (rc == -ENOSYS) {
		log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG);
	}
	return rc;
	(void)err;
}
