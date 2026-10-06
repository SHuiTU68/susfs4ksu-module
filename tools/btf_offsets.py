#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# btf_offsets.py - pull struct field offsets out of a kernel's BTF.
#
# Why this exists: the KPM is compiled without kernel headers, so every kernel
# structure is opaque and a field such as inode->i_op can only be reached
# through a numeric byte offset.  Those offsets belong to the *target* kernel
# and differ between KMI (5.10 / 5.15 / 6.1 / 6.6 / 6.12).  Hand-editing them
# per kernel does not scale, so read them from the kernel's own BTF instead:
# GKI always ships /sys/kernel/btf/vmlinux, and it is a complete, versioned
# description of the exact structures that kernel was built with.
#
# Usage:
#   ./btf_offsets.py --dump inode                    # every field of a struct
#   ./btf_offsets.py --size inode file_operations    # struct sizes
#   ./btf_offsets.py inode.i_op dentry.d_op          # individual offsets
#   ./btf_offsets.py --vfs                           # preset: the fields a
#                                                    # nomount-style VFS
#                                                    # hijack needs
#   ./btf_offsets.py --vfs --emit-c                  # ...as a C header
#   ./btf_offsets.py --btf /path/to/vmlinux ...
#
# The BTF format is documented in Documentation/bpf/btf.rst; only the subset
# needed to walk structures is implemented here.

import argparse
import struct
import sys

BTF_MAGIC = 0xEB9F

(K_UNKN, K_INT, K_PTR, K_ARRAY, K_STRUCT, K_UNION, K_ENUM, K_FWD,
 K_TYPEDEF, K_VOLATILE, K_CONST, K_RESTRICT, K_FUNC, K_PROTO,
 K_VAR, K_DATASEC, K_FLOAT, K_DECL_TAG, K_TYPE_TAG, K_ENUM64) = range(20)

KIND_NAME = {
    K_UNKN: "UNKN", K_INT: "INT", K_PTR: "PTR", K_ARRAY: "ARRAY",
    K_STRUCT: "STRUCT", K_UNION: "UNION", K_ENUM: "ENUM", K_FWD: "FWD",
    K_TYPEDEF: "TYPEDEF", K_VOLATILE: "VOLATILE", K_CONST: "CONST",
    K_RESTRICT: "RESTRICT", K_FUNC: "FUNC", K_PROTO: "FUNC_PROTO",
    K_VAR: "VAR", K_DATASEC: "DATASEC", K_FLOAT: "FLOAT",
    K_DECL_TAG: "DECL_TAG", K_TYPE_TAG: "TYPE_TAG", K_ENUM64: "ENUM64",
}

# Kinds whose members we want to keep.
AGGREGATE = (K_STRUCT, K_UNION)


class Type(object):
    __slots__ = ("id", "name", "kind", "vlen", "size", "type", "members")

    def __init__(self, tid, name, kind, vlen, size, type_):
        self.id = tid
        self.name = name
        self.kind = kind
        self.vlen = vlen
        self.size = size          # only meaningful for STRUCT/UNION/INT
        self.type = type_         # underlying type for PTR/TYPEDEF/...
        self.members = []         # [(name, type_id, bit_offset)] for aggregates


class BTF(object):
    def __init__(self, blob):
        (magic, ver, flags, hdr_len,
         type_off, type_len, str_off, str_len) = struct.unpack_from("<HBBIIIII", blob, 0)
        if magic != BTF_MAGIC:
            raise ValueError("not a BTF blob (magic=0x%x)" % magic)
        if ver not in (1, 2, 3, 4):
            raise ValueError("unsupported BTF version %d" % ver)

        self.blob = blob
        self.version = ver
        self.strings = blob[hdr_len + str_off: hdr_len + str_off + str_len]

        self.types = [None]  # BTF type ids start at 1; id 0 means "void"
        self._parse(blob, hdr_len + type_off, type_len)

    # -- string table ----------------------------------------------------

    def string(self, off):
        if off == 0:
            return ""
        end = self.strings.find(b"\0", off)
        if end < 0:
            end = len(self.strings)
        return self.strings[off:end].decode("utf-8", "replace")

    # -- type section ----------------------------------------------------

    def _parse(self, blob, pos, length):
        end = pos + length
        tid = 1
        while pos < end:
            name_off, info, size_or_type = struct.unpack_from("<III", blob, pos)
            pos += 12
            vlen = info & 0xFFFF
            kind = (info >> 24) & 0x1F
            kflag = (info >> 31) & 1
            t = Type(tid, self.string(name_off), kind, vlen, size_or_type, size_or_type)

            if kind == K_INT:
                pos += 4
            elif kind == K_ARRAY:
                pos += 12
            elif kind in AGGREGATE:
                for _ in range(vlen):
                    m_name, m_type, m_off = struct.unpack_from("<III", blob, pos)
                    pos += 12
                    if kflag:
                        bit_off = m_off & 0xFFFFFF
                        bit_sz = m_off >> 24
                        if bit_sz == 0:
                            bit_sz = 0
                        # non-bitfield members have bit_sz == 0 and a plain
                        # bit offset
                        m_off = bit_off
                    t.members.append((self.string(m_name), m_type, m_off))
                self._check_size(t)
            elif kind == K_ENUM:
                pos += 8 * vlen
            elif kind == K_ENUM64:
                pos += 12 * vlen
            elif kind == K_PROTO:
                pos += 8 * vlen
            elif kind == K_VAR:
                pos += 4
            elif kind == K_DATASEC:
                pos += 12 * vlen
            elif kind == K_DECL_TAG:
                pos += 4
            elif kind in (K_FLOAT,):
                pass

            self.types.append(t)
            tid += 1

    def _check_size(self, t):
        # Sanity: a struct's size must cover its last member.  Kernel BTF has
        # been correct in practice; this only guards against parser desync,
        # which would silently produce plausible-looking garbage.
        probe = 0
        for _, mtype, bit_off in t.members:
            m = self.by_id(mtype)
            if m is None:
                continue
            msz = self._sizeof(mtype)
            if msz is None:
                msz = 8
            probe = max(probe, bit_off // 8 + msz)
        if t.size and probe > t.size + 64:
            sys.stderr.write(
                "warning: %s parsed size %d does not cover member at %d "
                "(possible BTF desync)\n" % (t.name, t.size, probe))

    # -- lookups ---------------------------------------------------------

    def by_id(self, tid):
        if 0 < tid < len(self.types):
            return self.types[tid]
        return None

    def resolve(self, tid):
        """Follow typedefs/qualifiers down to a real type."""
        seen = 0
        t = self.by_id(tid)
        while t is not None and t.kind in (K_TYPEDEF, K_VOLATILE, K_CONST,
                                           K_RESTRICT, K_TYPE_TAG) and seen < 32:
            t = self.by_id(t.type)
            seen += 1
        return t

    def find(self, name):
        """Find an aggregate type by name (preferring a struct over a union)."""
        hits = []
        for t in self.types:
            if t is None or t.kind not in AGGREGATE:
                continue
            if t.name == name:
                hits.append(t)
        if not hits:
            # the name may only exist as a typedef
            for t in self.types:
                if t is None or t.kind != K_TYPEDEF or t.name != name:
                    continue
                r = self.resolve(t.id)
                if r is not None and r.kind in AGGREGATE:
                    hits.append(r)
        if not hits:
            return None
        hits.sort(key=lambda x: (x.kind != K_STRUCT, -x.size))
        return hits[0]

    def _sizeof(self, tid):
        t = self.resolve(tid)
        if t is None:
            return None
        if t.kind in AGGREGATE or t.kind in (K_INT, K_ENUM, K_ENUM64):
            return t.size
        if t.kind == K_PTR:
            return 8
        if t.kind == K_ARRAY:
            return None
        return 8

    def offset(self, path):
        """path is 'struct.field' or 'struct.field.subfield' (byte offset)."""
        parts = path.split(".")
        if len(parts) < 2:
            raise ValueError("expected struct.field, got %r" % path)
        t = self.find(parts[0])
        if t is None:
            raise KeyError("no such struct: %s" % parts[0])
        total = 0
        for want in parts[1:]:
            got = self._member_offset(t, want)
            if got is None:
                raise KeyError("%s has no field %s" % (t.name, want))
            off, t = got
            total += off
        return total

    def _member_offset(self, t, want):
        """Return (byte_offset, member_type) or None.  Recurses through
        anonymous members, whose fields are visible in the parent."""
        for name, mtype, bit_off in t.members:
            if name == want:
                return bit_off // 8, self.resolve(mtype)
        for name, mtype, bit_off in t.members:
            if name != "":
                continue
            sub = self.resolve(mtype)
            if sub is None or sub.kind not in AGGREGATE:
                continue
            got = self._member_offset(sub, want)
            if got is not None:
                return bit_off // 8 + got[0], got[1]
        return None

    def dump(self, name):
        t = self.find(name)
        if t is None:
            raise KeyError("no such struct: %s" % name)
        out = ["struct %s (id %d, size %d)" % (t.name, t.id, t.size)]
        for m_name, m_type, bit_off in t.members:
            m = self.resolve(m_type)
            kind = KIND_NAME.get(m.kind, "?") if m else "?"
            label = m_name if m_name else "<anon>"
            out.append("  +%-4d %-28s %-9s %s" % (bit_off // 8, label, kind,
                                                  m.name if m else ""))
        return "\n".join(out)


# --------------------------------------------------------------------------
# The field set a nomount-style VFS hijack needs.
#
# nomount (github.com/maxsteeel/nomount) is an LKM: it is compiled with the
# kernel headers, so it writes inode->i_op and friends directly.  A KPM cannot
# do that.  These are the fields it touches, expressed as offsets.
# --------------------------------------------------------------------------

VFS_FIELDS = [
    # struct inode
    "inode.i_op", "inode.i_fop", "inode.i_ino", "inode.i_mode",
    "inode.i_private", "inode.i_sb", "inode.i_nlink", "inode.i_size",
    "inode.i_mapping",
    # struct dentry
    "dentry.d_flags", "dentry.d_op", "dentry.d_inode", "dentry.d_sb",
    "dentry.d_parent", "dentry.d_name", "dentry.d_lockref", "dentry.d_fsdata",
    # struct qstr (d_name is embedded, hence the full path)
    "dentry.d_name.len", "dentry.d_name.hash", "dentry.d_name.name",
    # struct super_block
    "super_block.s_op", "super_block.s_xattr", "super_block.s_root",
    "super_block.s_dev", "super_block.s_type", "super_block.s_flags",
    # struct file
    "file.f_op", "file.f_inode", "file.f_path", "file.f_mode", "file.f_flags",
    "file.f_pos", "file.f_count", "file.private_data",
    # struct vm_area_struct (read/write redirection through mmap)
    "vm_area_struct.vm_file", "vm_area_struct.vm_ops", "vm_area_struct.vm_pgoff",
    "vm_area_struct.vm_start", "vm_area_struct.vm_end",
    # struct dir_context (directory iteration)
    "dir_context.actor", "dir_context.pos",
    # struct path (kern_path output)
    "path.mnt", "path.dentry",
    # struct vfsmount / mount (mountinfo hiding)
    "vfsmount.mnt_root", "vfsmount.mnt_sb",
    "mount.mnt", "mount.mnt_id",
    # struct seq_file (show_mountinfo() argument)
    "seq_file.buf", "seq_file.size", "seq_file.from", "seq_file.count",
]

# Function-pointer slots inside the operation vectors.  A port has to build a
# shadow copy of the real vector and replace exactly these slots.
VFS_SLOTS = [
    ("inode_operations", ["lookup", "get_link", "permission"]),
    ("file_operations", ["open", "release", "llseek", "read_iter", "write_iter",
                         "mmap", "mmap_prepare", "iterate_shared", "iterate",
                         "splice_read", "splice_write", "fsync",
                         "get_unmapped_area", "ioctl"]),
    ("dentry_operations", ["d_revalidate", "d_weak_revalidate"]),
    ("super_operations", ["drop_inode", "evict_inode"]),
    ("xattr_handler", ["get", "set"]),
]

VFS_SIZES = [
    "inode", "dentry", "qstr", "super_block", "file", "path",
    "inode_operations", "file_operations", "dentry_operations",
    "super_operations", "vm_area_struct", "dir_context", "xattr_handler",
    "vfsmount", "mount", "seq_file",
]

# --------------------------------------------------------------------------
# The field set the dcache-synthesis engine (kpm/features/mount_dcache.c
# slice 2) needs.  Where --vfs describes hijacking *existing* objects, this
# one describes *building new* ones: an inode has to be filled in the fields
# new_inode_pseudo() leaves alone (i_sb/i_ino/i_mode/i_size/i_op/i_fop) and a
# dentry linked in by hand, so both get the full set of fields the engine
# reads or writes.  Kept separate from --vfs so the nomount report stays
# byte-stable for the existing hooks.
# --------------------------------------------------------------------------

VFS2_FIELDS = [
    # struct inode - what a synthetic file inode must be given
    "inode.i_mode", "inode.i_opflags", "inode.i_uid", "inode.i_gid",
    "inode.i_flags", "inode.i_op", "inode.i_sb", "inode.i_mapping",
    "inode.i_ino", "inode.i_rdev", "inode.i_size", "inode.i_atime",
    "inode.i_mtime", "inode.__i_ctime", "inode.i_bytes", "inode.i_blocks",
    "inode.i_state", "inode.i_data", "inode.i_private",
    # struct dentry - what a synthetic dentry must be linked with
    "dentry.d_flags", "dentry.d_parent", "dentry.d_name",
    "dentry.d_name.hash", "dentry.d_name.len", "dentry.d_name.name",
    "dentry.d_inode", "dentry.d_iname", "dentry.d_lockref", "dentry.d_op",
    "dentry.d_sb", "dentry.d_time", "dentry.d_fsdata",
    "dentry.d_child", "dentry.d_subdirs",
    # struct super_block - validating the target partition's sb
    "super_block.s_dev", "super_block.s_type", "super_block.s_op",
    "super_block.s_flags", "super_block.s_iflags", "super_block.s_magic",
    "super_block.s_root", "super_block.s_fs_info",
    # struct address_space - reached through inode->i_mapping
    "address_space.host", "address_space.gfp_mask", "address_space.nrpages",
    "address_space.a_ops",
]

VFS2_SLOTS = [
    ("file_operations", ["llseek", "read", "write", "read_iter", "write_iter",
                         "iterate_shared", "mmap", "open", "release", "fsync",
                         "get_unmapped_area", "splice_read", "splice_write"]),
    ("inode_operations", ["lookup", "get_link", "permission", "readlink",
                          "getattr"]),
    ("address_space_operations", ["writepage", "read_folio", "dirty_folio",
                                  "readahead", "write_begin", "write_end",
                                  "direct_IO"]),
]

VFS2_SIZES = [
    "inode", "dentry", "super_block", "address_space",
    "address_space_operations", "file_operations", "inode_operations",
    "qstr", "file", "path",
]


def main():
    ap = argparse.ArgumentParser(
        description="Emit kernel struct field offsets from BTF.")
    ap.add_argument("--btf", default="/sys/kernel/btf/vmlinux",
                    help="path to a BTF blob (default: %(default)s)")
    ap.add_argument("--dump", metavar="STRUCT",
                    help="print every field of a struct")
    ap.add_argument("--size", nargs="+", metavar="STRUCT",
                    help="print sizeof(struct)")
    ap.add_argument("--vfs", action="store_true",
                    help="preset: fields + sizes for a nomount-style VFS hijack")
    ap.add_argument("--vfs2", action="store_true",
                    help="preset: fields + sizes for the dcache-synthesis engine")
    ap.add_argument("--emit-c", action="store_true",
                    help="emit C #defines instead of an aligned report")
    ap.add_argument("--kmi", default="",
                    help="KMI tag to stamp into --emit-c output (e.g. 6.6)")
    ap.add_argument("fields", nargs="*",
                    help="struct.field paths to resolve")
    args = ap.parse_args()

    try:
        blob = open(args.btf, "rb").read()
    except OSError as e:
        sys.exit("cannot read %s: %s" % (args.btf, e))
    btf = BTF(blob)

    if args.dump:
        print(btf.dump(args.dump))
        return

    names = []
    if args.vfs:
        names += [("offset", f) for f in VFS_FIELDS]
        names += [("offset", "%s.%s" % (s, f)) for s, fs in VFS_SLOTS for f in fs]
        names += [("size", s) for s in VFS_SIZES]
    if args.vfs2:
        names += [("offset", f) for f in VFS2_FIELDS]
        names += [("offset", "%s.%s" % (s, f)) for s, fs in VFS2_SLOTS for f in fs]
        names += [("size", s) for s in VFS2_SIZES]
    names += [("offset", f) for f in args.fields]
    if args.size:
        names += [("size", s) for s in args.size]
    if not names:
        ap.print_help()
        return

    rows = []
    missing = []
    for what, name in names:
        try:
            if what == "offset":
                rows.append((what, name, btf.offset(name)))
            else:
                t = btf.find(name)
                if t is None:
                    missing.append(name)
                    continue
                rows.append((what, name, t.size))
        except (KeyError, ValueError) as e:
            missing.append("%s (%s)" % (name, e))

    if args.emit_c:
        if args.kmi:
            print("/* generated from %s for KMI %s - do not edit */"
                  % (args.btf, args.kmi))
        else:
            print("/* generated from %s - do not edit */" % args.btf)
        print("#ifndef _SUSFS_VFS_OFFSETS_H")
        print("#define _SUSFS_VFS_OFFSETS_H")
        for what, name, val in rows:
            macro = (("KPM_OFF_" if what == "offset" else "KPM_SZ_")
                     + name.upper().replace(".", "_"))
            print("#define %-40s 0x%04x" % (macro, val))
        for name in missing:
            print("/* missing: %s */" % name)
        print("#endif")
        return

    width = max(len(n) for _, n, _ in rows) if rows else 8
    for what, name, val in rows:
        unit = "bytes" if what == "size" else ""
        print("%-*s = %5d   %s" % (width, name, val, unit))
    if missing:
        print()
        print("not present in this kernel's BTF:")
        for name in missing:
            print("  - %s" % name)


if __name__ == "__main__":
    main()
