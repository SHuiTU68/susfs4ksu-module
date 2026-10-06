# Can we build a nomount-style VFS implementation into this KPM?

Question asked: could we embed a VFS-mount implementation, referencing
[maxsteeel/nomount](https://github.com/maxsteeel/nomount)?

Short answer: **yes, technically — but not by porting nomount.** nomount is a
different kind of object (a loadable kernel module compiled against kernel
headers), and the interesting half of what it does is the half we do not need.
There is a much cheaper way to get the one capability we actually lack.

This document records what was measured on the target device, so the next
person does not have to re-derive it.

---

## 1. What nomount actually is

Read from source at `master` (`fd52514`), cloned to `/root/nomount`.

*   **An LKM, not a KPM.** `kernel/src/nomount.c` (1697 lines) +
    `nomount.h` (370), built by `.github/workflows/build-lkm.yml` into one
    `.ko` **per KMI** (`android12-5.10` … `android16-6.12`, 7 targets) using
    the DDK container: `make -C $KDIR M=kernel/src modules`.
*   It is a *metamodule*: it wants to take over module mounting from
    KernelSU/APatch and inject files without any mount at all.
*   Userspace ↔ kernel IPC is via the **keyring** (`add_key`), not ioctls or
    /dev nodes: `register_key_type(&nm_key_type)` is the entire `init`.
*   On GKI it needs `MODULE_IMPORT_NS(ANDROID_GKI_VFS_EXPORT_ONLY)` and
    `MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver)`.

## 2. Its mechanism — four hijack points

It never installs a global function hook. It performs surgery on live VFS
objects and lets the kernel's own code call its replacements:

1.  `kern_path()` → `struct path` → `d_backing_inode()`.
2.  **Dir inode**: allocate a shadow copy of `inode->i_op` / `i_fop`, replace
    `.lookup` and `.iterate_shared` (`.iterate` before 6.6), then
    `smp_store_release(&inode->i_op, &shadow)`. This is what gives it
    directory-listing control (inject entries, whiteout entries).
3.  **Dentry**: swap `dentry->d_op` for a proxy with `.d_revalidate`, under
    `spin_lock(&dentry->d_lock)`.
4.  **Superblock**: `sb->s_op` shadow with `.drop_inode` / `.evict_inode`
    replaced, plus a proxy array for `sb->s_xattr`.

Fake inodes are the entry point for content redirection: an injected name
resolves to a synthetic inode whose file vector forwards reads/`mmap` to the
real file.

## 3. Why a KPM can do all of that

KernelPatch gives a module the primitives nomount uses, and then some:

| Need | KPM has it |
| --- | --- |
| Resolve any kernel symbol | `kallsyms_lookup_name{,_by_suffix}`, `symbol_lookup_name` (`kernel/include/symbol.h`) |
| Call any kernel function | `kfunc_def()` resolved at load, or our own `susfs_ksym()` |
| Read/write kernel memory | `io.h` raw accessors, `hotpatch()`, `hotpatch_nosync()` |
| Hook any instruction | `hook.h` (`hook_wrap`, fargs0-4, `hook_syscalln`) |
| Allocate | `kpmalloc.h` (`kp_malloc` / `kp_free`, RW and RWX pools), or kernel `__kmalloc` |
| Locks | `kp_spinlock.h`, plus the kernel spinlock via resolved offset |

Two consequences worth stating explicitly:

*   **KP's loader does not enforce symbol namespaces or GPL-only tags.**
    `kernel/patch/module/module.c` contains no `kstrtabns` / namespace logic at
    all. So the GKI `VFS_EXPORT_ONLY` gate that forces nomount to declare
    `MODULE_IMPORT_NS` is simply not a constraint for us; non-exported and
    namespace-gated symbols are fair game.
*   **KP has no weak symbols.** `simplify_symbols()` returns `-ENOENT` for any
    unresolved `SHN_UNDEF`, which kills the whole module load. Every symbol a
    port references must exist on the target, which is why we resolve at
    runtime (`susfs_ksym`) instead of taking link-time references.

## 4. What the port would actually cost

Measured on the target: `Linux 6.6.118-android15-8-ge58033dc8ea6-abogki498046332-4k`.

### 4.1. No struct headers ⇒ offsets, and they must come from BTF

KP's `linux/*.h` shims only forward-declare `struct inode/dentry/file`
(`kernel/linux/include/linux/fs.h`), so every field access is a numeric
offset. `tools/btf_offsets.py` (added with this document) reads
`/sys/kernel/btf/vmlinux` and prints them; `--vfs` is the preset for exactly
this kind of work. Real values for 6.6:

```
inode.i_op                    32      file_operations.open                    104
inode.i_fop                  384      file_operations.release                 120
inode.i_private              696      file_operations.read_iter                32
inode.i_mode                   0      file_operations.write_iter               40
dentry.d_flags                 0      file_operations.mmap                     88
dentry.d_op                   96      file_operations.iterate_shared           56
dentry.d_inode                48      inode_operations.lookup                   0
dentry.d_sb                  104      dentry_operations.d_revalidate            0
dentry.d_name                 32      dentry_operations.d_weak_revalidate       8
dentry.d_lockref              88      super_operations.drop_inode              40
super_block.s_op              48      super_operations.evict_inode             48
super_block.s_xattr          192      dir_context.actor                         0
file.f_op                    192      dir_context.pos                           8

sizeof: inode 704, dentry 208, file 264, super_block 1536,
        inode_operations 256, file_operations 264,
        dentry_operations 192, super_operations 208
```

The shadow vectors must be allocated with the *target's* size (hence the
`sizeof` list), which is exactly why these are generated and not hardcoded:
between 5.15 and 6.6 `file_operations` lost `iterate`/`sendpage` and gained
`splice_eof`/`uring_cmd`/`uring_cmd_iopoll`; `inode_operations` gained
`get_inode_acl`/`get_offset_ctx`; `dentry_operations` lost
`d_canonical_path`; `super_operations` gained `shutdown`. Slots are inserted
mid-struct, so every later offset shifts. Cross-KMI means running the tool
against each KMI's BTF.

### 4.2. Some of what nomount calls does not exist as a symbol

LTO + CFI + `static inline` remove symbols a naive port would reference.
Checked against this kernel's `/proc/kallsyms` (which is the real one — the
terminal's `uname` matches the device):

*   Present exactly: `kern_path`, `path_put`, `d_alloc`, `d_add`, `d_drop`,
    `dput`, `dget_parent`, `d_alloc_parallel`, `d_rehash`, `d_invalidate`,
    `shrink_dcache_parent`, `new_inode`, `iget5_locked`,
    `insert_inode_locked`, `unlock_new_inode`, `iput`, `make_bad_inode`,
    `inode_init_always`, `clear_inode`, `generic_delete_inode`,
    `rcu_barrier`, `kvfree_call_rcu`, `kfree`, `register_key_type`,
    `unregister_key_type`, `full_name_hash`.
*   **Absent** (must be inlined by us, using the offsets above):
    `dget` (refcount bump — `dget_parent` is not a substitute),
    `kmalloc`, `kzalloc` (same problem our `susfs_kzalloc` already works
    around with `__kmalloc`), `hlist_add_head_rcu` (static inline),
    `d_backing_inode`, `d_inode`, `d_unhashed`.
*   Traps: `dentry->d_lock` is **a macro**, not a field —
    `include/linux/dcache.h:81` says `#define d_lock d_lockref.lock`. On 6.6
    that resolves to offset 88, which `btf_offsets.py` prints for
    `dentry.d_lockref.lock`.

## 5. Recommendation: do not port nomount; take the cheap half first

We already have the syscall-level half of this story (`sus_path`, `sus_map`,
`sus_kstat`, `open_redirect`). What we genuinely lack is **entry-level hiding:
a name that `ls`/`find`/`readdir` never sees**. That is worth having, and
there are two ways to get it.

### Option A — filter `getdents64` (budget, ~200 lines)

Hook the directory-read path at the syscall boundary and rewrite the returned
`struct linux_dirent64` buffer, dropping records that match our hide rules.

*   Reuses our existing architecture: a `hook_syscalln` slot plus the path
    cache we already maintain for `sus_path`.
*   No VFS surgery, no BTF offsets, no shadow vectors, no per-KMI struct
    drift, nothing to get wrong under `d_lock`.
*   Coverage: everything userspace does (`ls`, `find`, `readdir`, Java/NDK
    directory scans) goes through this syscall.
*   Limits: kernel-internal readers that call `iterate_dir()` directly are not
    filtered; content redirection and `mmap` substitution are out of scope.
*   Must keep `d_off` semantics sane (return the original offsets of kept
    records; never invent offsets).

### Option B — nomount-style VFS surgery (full, ~800-1000 lines)

As in sections 2-4. Buys entry-level hiding *plus* fake inodes, content
redirection and `mmap` forwarding, and works for in-kernel readers too.

Cost and risk, honestly:

*   ~40 offsets + 9 shadow vectors, per KMI.
*   Inlined-symbol workarounds above.
*   Locking: mutating `dentry->d_op` / `inode->i_op` on live objects that
    other CPUs are walking through right now. nomount's answer is
    `smp_store_release` + RCU + `d_lockref.lock` + pinned dentries; a mistake
    here is dcache corruption or a panic, not a failed feature.
*   Unload must be provably safe (restore every shadowed vector).
*   Policy: we must **not** replicate the metamodule part. KernelSU/APatch
    already own module mounting; two owners of the same problem is how you get
    a device that boots to a black screen.

**Plan:** Option A first, because it is small, it matches how the rest of this
KPM already works, and it delivers the visible win (`ls` no longer shows the
hidden path). Reach for Option B only if we specifically need in-kernel
invisibility or path-level content substitution that `sus_map` cannot express —
and then start with *hiding only*, leaving `sb->s_op`/`sb->s_xattr` alone
(nomount needs those for its fake inodes; hiding does not).

## 6. Open questions for the maintainer

*   Is the goal "`ls` does not show it" (Option A is enough) or "the file does
    not exist for anything in the kernel, but reads still work" (Option B)?
*   If Option B: which KMIs must be supported? 6.6 only keeps the offset table
    at manageable size.
*   Should any of this live behind a build flag so the current, working
    behaviour stays the default?
