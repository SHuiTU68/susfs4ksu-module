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
#include "sus_mount.h"

#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS 0x55561
#define CMD_SUSFS_ADD_TRY_UMOUNT 0x55562
#define CMD_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT 0x55563
#define CMD_SUSFS_ADD_SUS_MOUNT 0x55564

void sus_mount_print_help(void){
	log("    hide_sus_mnts_for_non_su_procs <0|1>\n");
	log("      |--> 0 -> DO NOT hide sus mounts for non-su processes\n");
	log("      |--> 1 -> hide all sus mounts for non-su processes\n");
	log("      * Important Notes *\n");
	log("      - It is set to 0 in kernel by default\n");
	log("      - For ReZygisk without TreatWheel module, it is recommended to set to 1 in post-fs-data.sh to prevent zygote from caching the sus mounts in memory, and revert to 0 in boot-completed.sh stage, or keep it enabled if you want to keep them hidden from /proc/self/[mounts|mountinfo|mountstat] for non-su processes\n");
	log("\n");
	log("    hide_sus_mnts_for_all_procs <0|1>\n");
	log("      |--> Alias for hide_sus_mnts_for_non_su_procs (APatch KPM does not\n");
	log("        distinguish all-procs vs non-su-procs; both go through the same hook)\n");
	log("\n");
	log("    add_sus_mount </path/of/mount>\n");
	log("      |--> Add a mount path to the sus mount list for hiding from /proc/mounts\n");
	log("      - In this KPM, sus_mount paths are recorded and post-mount.sh performs\n");
	log("        the actual umount -l to detach them in the init mount namespace.\n");
	log("\n");
	log("    add_try_umount </path/of/mount> <0|1>\n");
	log("      |--> 0 -> hide the mount from /proc/mounts only\n");
	log("      |--> 1 -> also detach it (userspace `umount -l` in post-mount.sh)\n");
	log("      - Records the path in the KPM list; the actual detach is done\n");
	log("        by post-mount.sh so it propagates to zygote-spawned apps.\n");
	log("\n");
	log("    auto_add_try_umount_for_bind_mount\n");
	log("      - Advisory toggle: marks that post-mount.sh should auto-scan\n");
	log("        /proc/mounts for suspicious bind mounts and umount them.\n");
	log("\n");
	log("    umount_for_zygote_iso_service <0|1>\n");
	log("      |--> Advisory toggle for zygote isolation service umount (no-op in this KPM)\n");
	log("\n");
}

static void print_help(void){
	print_help_banner();
	sus_mount_print_help();
}

int hide_sus_mnts_for_non_su_procs(int argc, char *argv[]) {
	if (argc != 3) {
		print_help();
		return -EINVAL;
	}

	if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) {
		print_help();
		return -EINVAL;
	}
	int enabled = atoi(argv[2]);
	int rc = kpm_send(CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS, "%d", enabled);
	if (rc == -ENOSYS) {
		log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS);
	}
	return rc;
}

/* hide_sus_mnts_for_all_procs — alias for hide_sus_mnts_for_non_su_procs.
 * The KPM does not distinguish all-procs vs non-su-procs; both use the same
 * hook.  This exists so legacy scripts that call hide_sus_mnts_for_all_procs
 * don't fail silently. */
int hide_sus_mnts_for_all_procs(int argc, char *argv[]) {
	return hide_sus_mnts_for_non_su_procs(argc, argv);
}

/* add_sus_mount — add a mount path to the sus mount hiding list.
 * In upstream susfs this marks the vfsmount as SUS so it's hidden from
 * /proc/mounts for non-su readers.  This KPM records the path via the
 * same try_umount list (mode=0, hide only) so the show_mountinfo hook
 * can filter it.  post-mount.sh may also umount -l paths from
 * sus_mount.txt if needed. */
int add_sus_mount(int argc, char *argv[]) {
	if (argc != 3) {
		print_help();
		return -EINVAL;
	}
	if (*argv[2] == '\0') {
		log("[-] argv[2] is empty\n");
		return -EINVAL;
	}
	/* Send as sus_mount (mode=0 = hide only, no umount).  The KPM
	 * dispatches CMD_SUSFS_ADD_SUS_MOUNT to susfs_add_try_umount(path, 0). */
	int rc = kpm_send(CMD_SUSFS_ADD_SUS_MOUNT, "%s", argv[2]);
	if (rc == -ENOSYS) {
		log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_ADD_SUS_MOUNT);
	}
	return rc;
}

int add_try_umount(int argc, char *argv[]) {
	if (argc != 4) {
		print_help();
		return -EINVAL;
	}
	if (strcmp(argv[3], "0") && strcmp(argv[3], "1")) {
		print_help();
		return -EINVAL;
	}
	int mode = atoi(argv[3]);
	int rc = kpm_send(CMD_SUSFS_ADD_TRY_UMOUNT, "%s|%d", argv[2], mode);
	if (rc == -ENOSYS) {
		log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n", CMD_SUSFS_ADD_TRY_UMOUNT);
	}
	return rc;
}

int auto_add_try_umount_for_bind_mount(int argc, char *argv[]) {
	(void)argc; (void)argv;
	int rc = kpm_send(CMD_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT, NULL);
	if (rc == -ENOSYS) {
		log("[-] CMD: '0x%x', KPM susfs_kpm not loaded\n",
		    CMD_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT);
	}
	return rc;
}

/* umount_for_zygote_iso_service — advisory toggle, no-op in this KPM.
 * Returns 0 so scripts don't treat it as a failure. */
int umount_for_zygote_iso_service(int argc, char *argv[]) {
	(void)argc; (void)argv;
	return 0;
}
