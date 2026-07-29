#ifndef SUS_MOUNT_H
#define SUS_MOUNT_H

void sus_mount_print_help(void);
int hide_sus_mnts_for_non_su_procs(int argc, char *argv[]);
int hide_sus_mnts_for_all_procs(int argc, char *argv[]);
int add_sus_mount(int argc, char *argv[]);
int add_try_umount(int argc, char *argv[]);
int auto_add_try_umount_for_bind_mount(int argc, char *argv[]);
int umount_for_zygote_iso_service(int argc, char *argv[]);

#endif // #ifndef SUS_MOUNT_H

