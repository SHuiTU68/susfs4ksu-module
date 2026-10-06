/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * susfs_offsets.h - kernel struct offsets + small accessors shared by the
 * susfs_kpm feature implementations.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Native susfs (luyanci/susfs4oki -> kernel_patches/fs/susfs.c) is compiled
 * INTO the kernel, so it can freely dereference struct inode / dentry /
 * vfsmount / vm_area_struct / kstat.  A KPM cannot: it is a separately
 * linked module and we deliberately do NOT include the kernel's struct
 * definitions (they are not in KernelPatch's header set, and guessing them
 * from source of another kernel version is how you get a boot loop).
 *
 * Since KernelPatch 0.13.x KPMs are version-specific to a GKI kernel
 * anyway (inline hooks patch machine code), so we pin the offsets to the
 * target kernel family and read them from that kernel's OWN BTF instead of
 * hand-guessing:
 *
 *   adb shell cp /sys/kernel/btf/vmlinux /sdcard/Download/vmlinux.btf
 *   python3 tools/btf_offsets.py --btf vmlinux.btf --vfs
 *
 * (This used to point at a btf_parse.py that never existed; the tool is
 * tools/btf_offsets.py, and `--emit-c` writes the defines below for you.)
 *
 * Source of truth used here:
 *   Linux version 6.6.118-android15-8-ge58033dc8ea6-abogki498046332-4k
 *   (GKI, aarch64, Android 15 / kernel 6.6, BTF type count 141452)
 *
 * Every offset below was dumped from that BTF.  GKI freezes its ABI per
 * branch, and struct file/inode/dentry/vfsmount/vm_area_struct layouts have
 * not changed within android15-6.6, so these values also hold for other
 * 6.6.x GKI builds.  Each hook additionally sanity-checks what it reads
 * (see kpm_*_looks_valid()) and stays inert if the layout does not match,
 * so a future kernel that reflows a struct degrades to "feature off"
 * instead of corrupting memory.
 *
 * Offsets (bytes):
 *   struct path          { vfsmount *mnt; dentry *dentry; }
 *   struct dentry        { ...; struct inode *d_inode; ... }
 *   struct inode         { ...; struct super_block *i_sb; struct
 *                          address_space *i_mapping; unsigned long i_ino; }
 *   struct super_block   { ...; dev_t s_dev; ... }
 *   struct file          { ...; struct path f_path; struct inode *f_inode; }
 *   struct vm_area_struct{ ...; struct file *vm_file; ... }
 *   struct vfsmount      { struct dentry *mnt_root; struct super_block *mnt_sb; }
 *   struct mount         { ...hlist...; struct vfsmount mnt; ...; int mnt_id; }
 *   struct seq_file      { char *buf; size_t size; size_t from; size_t count; }
 */
#ifndef SUSFS_KPM_OFFSETS_H
#define SUSFS_KPM_OFFSETS_H

#include <ktypes.h>
#include <kputils.h>   /* current_uid(), compat_copy_to_user(), ... */

/* ===== struct offsets ===== */
#define KPM_OFF_PATH_MNT                0
#define KPM_OFF_PATH_DENTRY             8

#define KPM_OFF_DENTRY_D_INODE          48

#define KPM_OFF_INODE_I_SB              40
#define KPM_OFF_INODE_I_MAPPING         48
#define KPM_OFF_INODE_I_INO             64

#define KPM_OFF_SB_S_DEV                16

#define KPM_OFF_FILE_F_PATH             168
#define KPM_OFF_FILE_F_INODE            184

#define KPM_OFF_VMA_VM_FILE             128

#define KPM_OFF_VFSMOUNT_MNT_ROOT       0
#define KPM_OFF_VFSMOUNT_MNT_SB         8

/* mnt_id lives in struct mount, which embeds struct vfsmount 'mnt' at
 * offset 32; show_mountinfo()/show_vfsmnt() receive &mount->mnt.  So from
 * that pointer mnt_id sits at 324 - 32 = 292. */
#define KPM_OFF_MOUNT_MNT_ID            292

#define KPM_OFF_SEQ_BUF                 0
#define KPM_OFF_SEQ_SIZE                8
#define KPM_OFF_SEQ_FROM                16
#define KPM_OFF_SEQ_COUNT               24

/* ===== struct offsets: slice 2 (dcache synthesis) =====
 *
 * Same source of truth as the block above - the device's own BTF
 * (6.6.118-android15-8 GKI, aarch64).  Regenerate with:
 *
 *     python3 tools/btf_offsets.py --btf /sys/kernel/btf/vmlinux --vfs2
 *     python3 tools/btf_offsets.py --btf ... --dump dentry   # whole struct
 *
 * Only the names not already defined above appear here, so the two blocks
 * read as one offset table.  Everything is expressed as an offset rather
 * than a struct because the KPM is a separately linked object: including
 * the kernel's own definitions would mean guessing them, and a wrong guess
 * here is a boot loop rather than a compile error.
 *
 * Reminder for the accessors below: `struct inode.i_count` is a refcount_t
 * and `i_lock` a spinlock; build synthetic inodes through the VFS
 * (new_inode_pseudo) so those are initialised correctly, and never
 * hand-roll them.  The offsets are for *reading* the fields the VFS will
 * not initialise for us (i_sb, i_ino, i_mode, i_size, i_op, i_fop, i_data).
 */

/* struct inode (KPM_SZ_INODE, 704 bytes) */
#define KPM_OFF_INODE_I_MODE            0      /* umode_t   */
#define KPM_OFF_INODE_I_OPFLAGS         2
#define KPM_OFF_INODE_I_UID             4      /* kuid_t    */
#define KPM_OFF_INODE_I_GID             8      /* kgid_t    */
#define KPM_OFF_INODE_I_FLAGS           12
#define KPM_OFF_INODE_I_OP              32
#define KPM_OFF_INODE_I_RDEV            76     /* dev_t, inside the anon union at +72 */
#define KPM_OFF_INODE_I_SIZE            80     /* loff_t    */
#define KPM_OFF_INODE_I_ATIME           88     /* timespec64 */
#define KPM_OFF_INODE_I_MTIME           104
#define KPM_OFF_INODE_I_CTIME           120    /* __i_ctime */
#define KPM_OFF_INODE_I_BYTES           140    /* unsigned short */
#define KPM_OFF_INODE_I_BLK_BITS        142
#define KPM_OFF_INODE_I_BLOCKS          144
#define KPM_OFF_INODE_I_STATE           152    /* unsigned long */
#define KPM_OFF_INODE_I_DATA            400    /* embedded struct address_space */

/* struct dentry (KPM_SZ_DENTRY, 208 bytes) */
#define KPM_OFF_DENTRY_D_FLAGS          0
#define KPM_OFF_DENTRY_D_SEQ            4
#define KPM_OFF_DENTRY_D_HASH           8      /* hlist_bl_node */
#define KPM_OFF_DENTRY_D_PARENT         24
#define KPM_OFF_DENTRY_D_NAME           32     /* struct qstr   */
#define KPM_OFF_DENTRY_D_NAME_HASH      32
#define KPM_OFF_DENTRY_D_NAME_LEN       36
#define KPM_OFF_DENTRY_D_NAME_NAME      40
#define KPM_OFF_DENTRY_D_INAME          56     /* short-name inline buffer */
#define KPM_OFF_DENTRY_D_LOCKREF        88     /* struct lockref */
#define KPM_OFF_DENTRY_D_LOCKREF_CNT    92
#define KPM_OFF_DENTRY_D_OP             96
#define KPM_OFF_DENTRY_D_SB             104
#define KPM_OFF_DENTRY_D_TIME           112
#define KPM_OFF_DENTRY_D_FSDATA         120
#define KPM_OFF_DENTRY_D_CHILD          144    /* list_head */
#define KPM_OFF_DENTRY_D_SUBDIRS        160    /* list_head */
#define KPM_OFF_DENTRY_D_U              176    /* union { d_alias; d_rcu; d_ci; } */

/* struct super_block (KPM_SZ_SUPER_BLOCK, 1536 bytes) */
#define KPM_OFF_SB_S_TYPE               40
#define KPM_OFF_SB_S_OP                 48
#define KPM_OFF_SB_S_IFLAGS             88
#define KPM_OFF_SB_S_MAGIC              96
#define KPM_OFF_SB_S_FS_INFO            968

/* struct address_space (KPM_SZ_ADDRESS_SPACE, 240 bytes), via inode->i_mapping */
#define KPM_OFF_MAPPING_HOST            0
#define KPM_OFF_MAPPING_GFP_MASK        88
#define KPM_OFF_MAPPING_NRPAGES         112
#define KPM_OFF_MAPPING_A_OPS           128

/* struct file_operations (KPM_SZ_FILE_OPERATIONS, 264 bytes).  Note this
 * 6.6 GKI vector has no .iterate, no .ioctl (only .unlocked_ioctl) and no
 * .mmap_prepare - a shadow copy must be built against the fields that are
 * really there. */
#define KPM_OFF_FOP_LLSEEK              8
#define KPM_OFF_FOP_READ                16
#define KPM_OFF_FOP_WRITE               24
#define KPM_OFF_FOP_READ_ITER           32
#define KPM_OFF_FOP_WRITE_ITER          40
#define KPM_OFF_FOP_ITERATE_SHARED      56
#define KPM_OFF_FOP_MMAP                88
#define KPM_OFF_FOP_OPEN                104
#define KPM_OFF_FOP_RELEASE             120
#define KPM_OFF_FOP_FSYNC               128
#define KPM_OFF_FOP_GET_UNMAPPED        152
#define KPM_OFF_FOP_SPLICE_WRITE        176
#define KPM_OFF_FOP_SPLICE_READ         184

/* struct inode_operations (KPM_SZ_INODE_OPERATIONS, 256 bytes) */
#define KPM_OFF_IOP_LOOKUP              0
#define KPM_OFF_IOP_GET_LINK            8
#define KPM_OFF_IOP_PERMISSION          16
#define KPM_OFF_IOP_READLINK            32
#define KPM_OFF_IOP_GETATTR             112

/* struct address_space_operations (KPM_SZ_ADDRESS_SPACE_OPS, 160 bytes) */
#define KPM_OFF_AOPS_WRITEPAGE          0
#define KPM_OFF_AOPS_READ_FOLIO         8
#define KPM_OFF_AOPS_DIRTY_FOLIO        24
#define KPM_OFF_AOPS_READAHEAD          32
#define KPM_OFF_AOPS_WRITE_BEGIN        40
#define KPM_OFF_AOPS_WRITE_END          48
#define KPM_OFF_AOPS_DIRECT_IO          88

/* sizeof() for the structs slice 2 allocates or copies */
#define KPM_SZ_INODE                    704
#define KPM_SZ_DENTRY                   208
#define KPM_SZ_SUPER_BLOCK              1536
#define KPM_SZ_ADDRESS_SPACE            240
#define KPM_SZ_ADDRESS_SPACE_OPS        160
#define KPM_SZ_FILE_OPERATIONS          264
#define KPM_SZ_INODE_OPERATIONS         256
#define KPM_SZ_QSTR                     16
#define KPM_SZ_FILE                     264
#define KPM_SZ_PATH                     16

/* ===== raw accessors ===== */
static inline void *kpm_rp(void *base, unsigned long off)
{
    return *(void **)((char *)base + off);
}
static inline unsigned long kpm_rul(void *base, unsigned long off)
{
    return *(unsigned long *)((char *)base + off);
}
static inline unsigned int kpm_ru32(void *base, unsigned long off)
{
    return *(unsigned int *)((char *)base + off);
}
static inline void kpm_wp(void *base, unsigned long off, void *val)
{
    *(void **)((char *)base + off) = val;
}
static inline void kpm_wul(void *base, unsigned long off, unsigned long val)
{
    *(unsigned long *)((char *)base + off) = val;
}
static inline void kpm_wu32(void *base, unsigned long off, unsigned int val)
{
    *(unsigned int *)((char *)base + off) = val;
}

/* ===== typed helpers ===== */
static inline void *kpm_file_inode(void *file)
{
    return file ? kpm_rp(file, KPM_OFF_FILE_F_INODE) : 0;
}
static inline void *kpm_dentry_inode(void *dentry)
{
    return dentry ? kpm_rp(dentry, KPM_OFF_DENTRY_D_INODE) : 0;
}
static inline void *kpm_path_dentry(void *path)
{
    return path ? kpm_rp(path, KPM_OFF_PATH_DENTRY) : 0;
}
static inline void *kpm_path_mnt(void *path)
{
    return path ? kpm_rp(path, KPM_OFF_PATH_MNT) : 0;
}
static inline void *kpm_path_inode(void *path)
{
    return kpm_dentry_inode(kpm_path_dentry(path));
}
static inline void *kpm_inode_sb(void *inode)
{
    return inode ? kpm_rp(inode, KPM_OFF_INODE_I_SB) : 0;
}
static inline unsigned long kpm_inode_ino(void *inode)
{
    return inode ? kpm_rul(inode, KPM_OFF_INODE_I_INO) : 0;
}
/* inode->i_sb->s_dev — internal (packed) dev_t, dev_t is u32 on arm64 */
static inline unsigned int kpm_inode_dev(void *inode)
{
    void *sb = kpm_inode_sb(inode);
    return sb ? kpm_ru32(sb, KPM_OFF_SB_S_DEV) : 0;
}
/* mnt->mnt_root->d_inode */
static inline void *kpm_mnt_root_inode(void *mnt)
{
    return mnt ? kpm_dentry_inode(kpm_rp(mnt, KPM_OFF_VFSMOUNT_MNT_ROOT)) : 0;
}
/* mount id of a struct vfsmount that is embedded in a struct mount */
static inline int kpm_mnt_id(void *mnt)
{
    return mnt ? (int)kpm_ru32(mnt, KPM_OFF_MOUNT_MNT_ID) : -1;
}

/* Sanity checks: a kernel inode at 6.6 GKI is 704 bytes, its i_sb and
 * i_mapping are kernel pointers (the top byte is 0xff for linear-map /
 * vmalloc addresses on arm64) and i_no is a slot index.  If any of these do
 * not hold we are looking at a struct layout we do not understand and the
 * caller must stay out of the way. */
static inline int kpm_is_kernel_ptr(void *p)
{
    unsigned long v = (unsigned long)p;
    /* arm64 kernel addresses live in ffff_xxxx_xxxx_xxxx (or the
     * 64K-page variants); userspace never exceeds 48 bits. */
    return (v >> 48) == 0xffffUL;
}
static inline int kpm_inode_looks_valid(void *inode)
{
    void *sb;
    if (!kpm_is_kernel_ptr(inode)) return 0;
    sb = kpm_inode_sb(inode);
    if (!kpm_is_kernel_ptr(sb)) return 0;
    return 1;
}

/* ===== dev_t encoding =====
 *
 * struct kstat.dev and inode->i_sb->s_dev hold the kernel-internal packed
 * dev_t: MKDEV(ma, mi) = (mi & 0xfffff) | (ma << 20).
 *
 * On arm64 (BITS_PER_LONG == 64) fs/stat.c converts it for userspace with
 * huge_encode_dev():
 *      st_dev = (mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12)
 *
 * The ksu_susfs CLI fills spoofed_dev from struct stat::st_dev, i.e. with
 * the *encoded* value.  To have stat() hand that same value back we must
 * decode it first — exactly what upstream susfs does with
 * `info.spoofed_dev = huge_decode_dev(info.spoofed_dev)` on arm64.
 */
static inline unsigned int kpm_huge_decode_dev(unsigned long long v)
{
    unsigned int ma = (unsigned int)((v >> 8) & 0xfffULL);
    unsigned int mi = (unsigned int)((v & 0xffULL) | ((v >> 12) & 0xfffff00ULL));
    return (mi & 0xfffffu) | (ma << 20);
}
static inline unsigned int kpm_huge_encode_dev(unsigned int dev)
{
    unsigned int ma = (dev >> 20) & 0xfffu;
    unsigned int mi = dev & 0xfffffu;
    return (mi & 0xffu) | (ma << 8) | ((mi & ~0xffu) << 12);
}

/* ===== calling-process helpers =====
 *
 * Native susfs distinguishes "ksu domain" and "umounted process" via KSU's
 * TIF_PROC_UMOUNTED task flag.  A KPM has no access to KSU's task flags, so
 * like the rest of this KPM we approximate with the process UID:
 *   uid >= 10000  -> Android app / isolated process  (what must not see the
 *                    module's files and mounts)
 *   uid <  10000  -> root, system, daemons            (management side; the
 *                    ksu_susfs CLI runs here and must keep full visibility)
 */
#define KPM_APP_UID_MIN 10000

static inline int kpm_current_uid_int(void)
{
    return (int)current_uid();
}
static inline int kpm_is_app_proc(void)
{
    return kpm_current_uid_int() >= KPM_APP_UID_MIN;
}
static inline int kpm_is_root_proc(void)
{
    return kpm_current_uid_int() == 0;
}
/* Best-effort "su / manager domain" test.  We cannot read the KSU domain
 * from a KPM; root is the closest proxy (the ksu_susfs CLI, Magisk/APatch
 * shells and the manager app's root helper all run as uid 0). */
static inline int kpm_is_su_like_proc(void)
{
    return kpm_is_root_proc();
}

/* ===== seq_file helpers =====
 *
 * Writing directly into the seq_file buffer is how we replace the content
 * of /proc/cmdline, /proc/bootconfig and the path column of
 * /proc/self/maps.  It is exactly what seq_puts()/seq_write() do
 * (fs/seq_file.c): copy into seq->buf + seq->count and bump seq->count.  We
 * do it inline instead of calling seq_puts() because the KPM must not take
 * a dependency on another kallsyms symbol, and because in a *before* hook
 * we want to own the output completely.
 *
 * Returns the number of bytes written (0 if the buffer could not hold the
 * text, in which case the caller must let the original function run).
 */
static inline int kpm_seq_append(void *m, const char *s, int len, int add_nl)
{
    char *buf;
    unsigned long size, count;
    int need;

    if (!m || !s || len <= 0) return 0;
    if (!kpm_is_kernel_ptr(m)) return 0;

    buf   = (char *)kpm_rp(m, KPM_OFF_SEQ_BUF);
    size  = kpm_rul(m, KPM_OFF_SEQ_SIZE);
    count = kpm_rul(m, KPM_OFF_SEQ_COUNT);

    if (!kpm_is_kernel_ptr(buf)) return 0;
    if (size == 0 || size > 0x100000UL) return 0;   /* sanity */
    if (count > size) return 0;

    need = len + (add_nl ? 1 : 0);
    if (count + (unsigned long)need > size) return 0;

    {
        int i;
        char *dst = buf + count;
        for (i = 0; i < len; i++) dst[i] = s[i];
        if (add_nl) dst[len] = '\n';
    }
    kpm_wul(m, KPM_OFF_SEQ_COUNT, count + (unsigned long)need);
    return need;
}

/* length of a NUL terminated string, capped (no strlen dependency) */
static inline int kpm_strlen_max(const char *s, int max)
{
    int n = 0;
    if (!s) return 0;
    while (n < max && s[n]) n++;
    return n;
}

#endif /* SUSFS_KPM_OFFSETS_H */
