#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <susfs_defs.h>
#include <susfs_utils.h>
#include <kpm_call.h>
#include "sus_kstat.h"

#define CMD_SUSFS_ADD_SUS_KSTAT 0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT 0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY 0x55572

#define KSTAT_SPOOF_INO (1 << 0)
#define KSTAT_SPOOF_DEV (1 << 1)
#define KSTAT_SPOOF_NLINK (1 << 2)
#define KSTAT_SPOOF_SIZE (1 << 3)
#define KSTAT_SPOOF_ATIME_TV_SEC (1 << 4)
#define KSTAT_SPOOF_ATIME_TV_NSEC (1 << 5)
#define KSTAT_SPOOF_MTIME_TV_SEC (1 << 6)
#define KSTAT_SPOOF_MTIME_TV_NSEC (1 << 7)
#define KSTAT_SPOOF_CTIME_TV_SEC (1 << 8)
#define KSTAT_SPOOF_CTIME_TV_NSEC (1 << 9)
#define KSTAT_SPOOF_BLOCKS (1 << 10)
#define KSTAT_SPOOF_BLKSIZE (1 << 11)
#define KSTAT_AUTO_SPOOF (KSTAT_SPOOF_INO | KSTAT_SPOOF_DEV | KSTAT_SPOOF_ATIME_TV_SEC | KSTAT_SPOOF_ATIME_TV_NSEC | \
		    KSTAT_SPOOF_MTIME_TV_SEC | KSTAT_SPOOF_MTIME_TV_NSEC | KSTAT_SPOOF_CTIME_TV_SEC | KSTAT_SPOOF_CTIME_TV_NSEC | \
		    KSTAT_SPOOF_BLKSIZE | KSTAT_SPOOF_BLOCKS)
#define KSTAT_AUTO_SPOOF_FULL_CLONE (KSTAT_AUTO_SPOOF | KSTAT_SPOOF_NLINK | KSTAT_SPOOF_SIZE)

/* Wire format sent to the KPM for every sus_kstat command:
 *   cmd|path|target_ino|spoofed_ino|spoofed_dev|spoofed_nlink|spoofed_size|
 *   spoofed_atime_sec|spoofed_atime_nsec|spoofed_mtime_sec|spoofed_mtime_nsec|
 *   spoofed_ctime_sec|spoofed_ctime_nsec|spoofed_blocks|spoofed_blksize|flags
 * Userspace resolves "default" sentinels (and current stat for the auto
 * variants) before sending, so the KPM just stores the values as-is. */
#define SUS_KSTAT_FMT \
	"%s|%lu|%lu|%lu|%u|%lld|%ld|%lu|%ld|%lu|%ld|%lu|%lld|%ld|%d"

void sus_kstat_print_help(void){
	log("    add_sus_kstat_statically </path/of/file_or_directory> <ino> <dev> <nlink> <size> <atime> <atime_nsec> <mtime> <mtime_nsec> <ctime> <ctime_nsec> <blocks> <blksize>\n");
	log("      |--> Use 'stat' tool to find the format:\n");
	log("               ino -> %%i, dev -> %%d, nlink -> %%h, atime -> %%X, mtime -> %%Y, ctime -> %%Z\n");
	log("               size -> %%s, blocks -> %%b, blksize -> %%B\n");
	log("      |--> e.g., %s add_sus_kstat_statically '/system/addon.d' '1234' '1234' '2' '223344'\\\n", TAG);
	log("                    '1712592355' '0' '1712592355' '0' '1712592355' '0' '1712592355' '0'\\\n");
	log("                    '16' '512'\n");
	log("      |--> Or pass 'default' to use its original value:\n");
	log("      |--> e.g., %s add_sus_kstat_statically '/system/addon.d' 'default' 'default' 'default' 'default'\\\n", TAG);
	log("                    '1712592355' 'default' '1712592355' 'default' '1712592355' 'default'\\\n");
	log("                    'default' 'default'\n");
	log("      * Important Notes *\n");
	log("      - Only effective for umounted process with uid >= 10000\n");
	log("\n");
	log("    add_sus_kstat </path/of/file_or_directory>\n");
	log("      |--> Add the desired path BEFORE it gets bind mounted or overlayed, this is used for storing original stat info in kernel memory\n");
	log("      |--> This command must be completed with <update_sus_kstat> later after the added path is bind mounted or overlayed\n");
	log("      * Important Notes *\n");
	log("      - Only effective for umounted process with uid >= 10000\n");
	log("\n");
	log("    update_sus_kstat </path/of/file_or_directory>\n");
	log("      |--> Add the desired path you have added before via <add_sus_kstat> to complete the kstat spoofing procedure\n");
	log("      |--> This updates the target ino, but size and blocks are remained the same as current stat\n");
	log("      * Important Notes *\n");
	log("      - Only effective for umounted process with uid >= 10000\n");
	log("\n");
	log("    update_sus_kstat_full_clone </path/of/file_or_directory>\n");
	log("      |--> Add the desired path you have added before via <add_sus_kstat> to complete the kstat spoofing procedure\n");
	log("      |--> This updates the target ino only, other stat members are remained the same as the original stat\n");
	log("      * Important Notes *\n");
	log("      - Only effective for umounted process with uid >= 10000\n");
	log("\n");
}

static void print_help(void){
	print_help_banner();
	sus_kstat_print_help();
}

static int send_sus_kstat(unsigned int cmd, const char *path, unsigned long target_ino,
		struct stat *sb, int flags) {
	int rc = kpm_send(cmd, SUS_KSTAT_FMT,
		path,
		target_ino,
		(unsigned long)sb->st_ino,
		(unsigned long)sb->st_dev,
		(unsigned int)sb->st_nlink,
		(long long)sb->st_size,
		(long)sb->st_atime,
		(unsigned long)sb->st_atimensec,
		(long)sb->st_mtime,
		(unsigned long)sb->st_mtimensec,
		(long)sb->st_ctime,
		(unsigned long)sb->st_ctimensec,
		(long long)sb->st_blocks,
		(long)sb->st_blksize,
		flags);
	if (rc == -ENOSYS) {
		log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", cmd);
	}
	return rc;
}

int add_sus_kstat_statically(int argc, char *argv[]) {
	struct stat sb;
	char resolved_pathname[PATH_MAX];
	char* endptr;
	unsigned long ino, dev, nlink, size, atime, atime_nsec, mtime, mtime_nsec, ctime, ctime_nsec, blksize;
	long blocks;
	unsigned long target_ino;
	int flags = 0;

	if (argc != 15) {
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

	/* get the stat of the target path first */
	int err = get_file_stat(resolved_pathname, &sb);
	if (err) {
		log("[-] failed to get stat from path: '%s'\n", resolved_pathname);
		return err;
	}
	/* it is statically: remember the original ino, then resolve "default" */
	target_ino = sb.st_ino;

	/* ino */
	if (strcmp(argv[3], "default")) {
		ino = strtoul(argv[3], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		sb.st_ino = ino;
		flags |= KSTAT_SPOOF_INO;
	}
	/* dev */
	if (strcmp(argv[4], "default")) {
		dev = strtoul(argv[4], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		sb.st_dev = dev;
		flags |= KSTAT_SPOOF_DEV;
	}
	/* nlink */
	if (strcmp(argv[5], "default")) {
		nlink = strtoul(argv[5], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		sb.st_nlink = nlink;
		flags |= KSTAT_SPOOF_NLINK;
	}
	/* size */
	if (strcmp(argv[6], "default")) {
		size = strtoul(argv[6], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		sb.st_size = size;
		flags |= KSTAT_SPOOF_SIZE;
	}
	/* atime */
	if (strcmp(argv[7], "default")) {
		atime = strtol(argv[7], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		sb.st_atime = atime;
		flags |= KSTAT_SPOOF_ATIME_TV_SEC;
	}
	/* atime_nsec */
	if (strcmp(argv[8], "default")) {
		atime_nsec = strtoul(argv[8], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		sb.st_atimensec = atime_nsec;
		flags |= KSTAT_SPOOF_ATIME_TV_NSEC;
	}
	/* mtime */
	if (strcmp(argv[9], "default")) {
		mtime = strtol(argv[9], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		sb.st_mtime = mtime;
		flags |= KSTAT_SPOOF_MTIME_TV_SEC;
	}
	/* mtime_nsec */
	if (strcmp(argv[10], "default")) {
		mtime_nsec = strtoul(argv[10], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		sb.st_mtimensec = mtime_nsec;
		flags |= KSTAT_SPOOF_MTIME_TV_NSEC;
	}
	/* ctime */
	if (strcmp(argv[11], "default")) {
		ctime = strtol(argv[11], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		sb.st_ctime = ctime;
		flags |= KSTAT_SPOOF_CTIME_TV_SEC;
	}
	/* ctime_nsec */
	if (strcmp(argv[12], "default")) {
		ctime_nsec = strtoul(argv[12], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		sb.st_ctimensec = ctime_nsec;
		flags |= KSTAT_SPOOF_CTIME_TV_NSEC;
	}
	/* blocks */
	if (strcmp(argv[13], "default")) {
		blocks = strtoul(argv[13], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		sb.st_blocks = blocks;
		flags |= KSTAT_SPOOF_BLOCKS;
	}
	/* blksize */
	if (strcmp(argv[14], "default")) {
		blksize = strtoul(argv[14], &endptr, 10);
		if (*endptr != '\0') {
			print_help();
			return -EINVAL;
		}
		sb.st_blksize = blksize;
		flags |= KSTAT_SPOOF_BLKSIZE;
	}

	return send_sus_kstat(CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY, resolved_pathname, target_ino, &sb, flags);
}

int add_sus_kstat(int argc, char *argv[]) {
	struct stat sb;
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

	int err = get_file_stat(resolved_pathname, &sb);
	if (err) {
		log("[-] failed to get stat from path: '%s'\n", resolved_pathname);
		return err;
	}
	return send_sus_kstat(CMD_SUSFS_ADD_SUS_KSTAT, resolved_pathname, sb.st_ino, &sb, KSTAT_AUTO_SPOOF);
}

int update_sus_kstat(int argc, char *argv[]) {
	struct stat sb;
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

	int err = get_file_stat(resolved_pathname, &sb);
	if (err) {
		log("[-] failed to get stat from path: '%s'\n", resolved_pathname);
		return err;
	}
	return send_sus_kstat(CMD_SUSFS_UPDATE_SUS_KSTAT, resolved_pathname, sb.st_ino, &sb, KSTAT_AUTO_SPOOF);
}

int update_sus_kstat_full_clone(int argc, char *argv[]) {
	struct stat sb;
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

	int err = get_file_stat(resolved_pathname, &sb);
	if (err) {
		log("[-] failed to get stat from path: '%s'\n", resolved_pathname);
		return err;
	}
	return send_sus_kstat(CMD_SUSFS_UPDATE_SUS_KSTAT, resolved_pathname, sb.st_ino, &sb, KSTAT_AUTO_SPOOF_FULL_CLONE);
}
