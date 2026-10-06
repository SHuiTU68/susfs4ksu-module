# Our own metamodule: a KPM-backed mount system for stock APatch

Status: **P0 landed** — the `kpmmount` metamodule package exists and works
end to end on stock APatch (real overlayfs mounts + bootloop guard + the APM
Action button), CI builds its zip. **P1 (the E7 dcache engine) is not started
yet**: `metamount.sh` has the E7 branch wired to the `mctl` contract and falls
back to E4 until that engine and client exist. Design verified against
**official** `bmax121/APatch` `903e645` and `bmax121/KernelPatch` @
`/root/kp_sync`.

## TL;DR

* Stock APatch has **no module-mounting code at all**. Mounting is delegated to
  a *metamodule*; if none is installed, `system/` never appears. That is a
  contract, not an accident, and it is the door we walk through.
* We therefore do **not** need to patch APatch. We ship our own metamodule
  package; APatch calls it at post-fs-data and we own the entire injection
  policy.
* KernelPatch already auto-loads every `/data/adb/ap/kpm/<id>/<id>.kpm` at
  `post-fs-data:before` and hands the KPM a `post-fs-data` init event. So the
  engine can live 100% in-kernel with no userspace helper, no fork, no shell.
* Recommended engine: **dcache synthesis** (pre-instantiate synthetic
  dentry+inode pairs in the *target* superblock's dcache, merge `getdents64`
  for listings). It is inherently invisible — `/proc/mounts` is untouched and
  `st_dev` comes from the real `/system` sb — for roughly half the cost of a
  full nomount port, because it needs no `i_op` shadow tables.
* The APM button is `action.sh`. APM already renders a play button for every
  module whose directory contains one, metamodules included, so the button needs
  **no app change at all** - the script *is* the button, and its output is the
  on-screen log (see 4.4).
* We do ship `metainstall.sh` (explicitly requested). That puts us into apd's
  `check_install_safety()` branch: while the metamodule carries an
  update/remove/disable marker, APatch refuses to install modules that need
  mounting. Accepted deliberately - the price of being able to react to installs
  at all (see 2 and 4.5).

## 1. Verified: stock APatch does not mount anything

Evidence, all in the official tree:

| Fact | Where |
|---|---|
| `apd/assets/` contains only `installer.sh` — no bundled metamodule, no `nomount` | `apd/assets/` |
| Zero mount syscalls in the daemon: `MS_BIND`, `libc::mount`, `rustix::mount`, `overlay` all absent from `apd/src/` | `grep -rnE 'MS_BIND\|libc::mount\|rustix::mount\|overlay' apd/src` -> empty |
| No `kpm`/`kpatch` subcommands either; only `insmod` (jailbreak late-load) | `apd/src/cli.rs` |
| Metamodule still exists as a concept: script names + dir are defined | `apd/src/defs.rs:27-30` |
| User-facing confirmations of "no metamodule -> nothing mounted" | `app/src/main/res/values/strings.xml`: `no_meta_module_installed`, `meta_module_disabled`, `meta_module_removed` |
| Docs still describe overlayfs mounting (now stale, describes the pre-removal design) | `docs/cn/ap_module.md:143-180` |

KernelPatch does not mount anything either: the only `overlay` hits in
`/root/kp_sync` are `OVERLAYFS_SUPER_MAGIC` in the uapi header and the
`overlay.d/` ramdisk paths. `/root/kp_sync/kpms/` ships only
`demo-hello`, `demo-inlinehook`, `demo-kconfig`, `demo-syscallhook`.

So: **the mount policy slot is empty and officially ours to fill.**

## 2. The metamodule contract (stock, `apd/src/metamodule.rs`)

A module is a metamodule iff its `module.prop` has `metamodule=1` (or `true`).
It is discovered through the symlink `/data/adb/metamodule` ->
`/data/adb/modules/<id>`, and only one may be active.

Scripts APatch will call, and what they receive:

| Script | When | Environment |
|---|---|---|
| `metamount.sh` | post-fs-data, after sepolicy + `restorecon`, before module scripts | `MODULE_DIR=/data/adb/modules/`, `AP_MODULE=<meta id>`, `APATCH=true`, `APATCH_VER`, `PATH+=/data/adb/ap/bin`; run as `busybox sh`, cwd = script dir |
| `<stage>.sh` (`post-fs-data.sh`, `post-mount.sh`, ...) | same `run_stage()` machinery as normal modules, **metamodule first** | normal module env |
| `metainstall.sh` | appended to the installer of every *subsequent* regular module install | `MODULE_ID` |
| `metauninstall.sh` | when a module is uninstalled | `MODULE_ID` |

Two consequences worth spelling out:

1. `exec_mount_script()` gets `MODULE_DIR` = **the whole modules directory**,
   not one module. The script is expected to walk all active modules itself.
2. Install-time gating (`check_install_safety()`) only engages when
   `metainstall.sh` exists: no `metainstall.sh` -> early `Ok(())` at
   `metamodule.rs:93-94`, and `get_install_script()` falls through to
   `install_module_script` at `metamodule.rs:196-199`. We ship
   `metainstall.sh`, so we *are* in that branch: while the metamodule carries an
   update/remove/disable marker, `Err(false)` blocks module installs with "reboot
   first". That is the accepted cost of being notified about installs - and one
   more reason why the bootloop guard must not use the metamodule's own `disable`
   marker (4.1), because that marker would also block installs.

Official boot order in `apd/src/event.rs::on_post_data_fs()`:

```
umask(0)
report_kernel("post-fs-data", "before")   <-- KPM AUTO-LOAD HAPPENS IN HERE
init_load_su_path / magisk_rules / privilege_apd_profile
clear_all_temp_configs / (bail out if Magisk present)
log env, safe-mode checks, modules.img mount, restorecon, sepolicy.rule
metamodule::exec_mount_script("/data/adb/modules/")   <-- our metamount.sh
module::exec_stage_script("post-fs-data")             <-- every module's script
lua::exec_stage_lua("post-fs-data")
load_system_prop / remove update flag
run_stage("post-mount")
report_kernel("post-fs-data", "after")
```

## 3. Verified: how our KPM gets in, and when

`report_kernel()` is a supercall (`event <name> <args>`), handled at
`kernel/patch/common/supercmd.c:500`, which calls `report_user_event()` in
`kernel/patch/common/user_event.c`. For `("post-fs-data", "before")` that
function does, in order:

1. `load_ap_package_config()`
2. `sucompat_init()`
3. **`load_ap_kpm_modules()`** (skipped in safe mode)
4. `selinux_hide_post_fs_data("before")`
5. `extra_event_init_args("post-fs-data", "before")`

`load_ap_kpm_modules()` (`kernel/patch/android/userd.c:1458`) iterates
`/data/adb/ap/kpm/` (`AP_KPM_DIR`), takes `kpm/<id>/<id>.kpm`, skips the entry
when `kpm/<id>/disable` exists, and calls:

```c
load_module_path_event(path, 0, EXTRA_EVENT_POST_FS_DATA, 0);   // userd.c:1519
```

`load_module_path_event()` (`kernel/patch/module/module.c:561`) loads the
module and immediately calls its entry point:

```c
mod_initcall_t init(const char *args, const char *event, void *reserved);
```

so for an auto-loaded AP KPM: `args = NULL`, `event = "post-fs-data"`,
`reserved = 0`. That is the first thing our engine sees at boot.

Then step 5, `extra_event_init_args()` (`kernel/patch/patch.c:134`) calls
`notify_modules_event()` -> `kp_notify_modules_event()`
(`lkm/kpm/module.c:1008`), which fans out to every loaded module's
`.kpm.event` handler:

```c
mod_eventcall_t event(const char *event, const char *args, void *reserved);
```

So a KPM sees `("post-fs-data", "before")` and later
`("post-fs-data", "after")` — and `("boot-completed", ...)`.

Entry points a `.kpm` may export (symbol names in the ELF):
`.kpm.info`, `.kpm.init`, `.kpm.exit`, `.kpm.ctl0`, `.kpm.ctl1`, `.kpm.event`.

Relevant supercalls for userspace (`kernel/patch/include/uapi/scdefs.h`):

| Command | Value | Use |
|---|---|---|
| `SUPERCALL_KPM_LOAD` | `0x1020` | load a `.kpm` by path |
| `SUPERCALL_KPM_UNLOAD` | `0x1021` | unload |
| `SUPERCALL_KPM_CONTROL` | `0x1022` | invoke a loaded KPM's `ctl0` |
| `SUPERCALL_KPM_NUMS`/`LIST`/`INFO` | `0x1030`-`0x1032` | introspect |

All of these take the superkey as the first argument, and are wrapped as
`ver_and_cmd(cmd) = (version_code << 32) | (0x1158 << 16) | (cmd & 0xFFFF)`
on `__NR_SUPERCALL = 45` (see `apd/src/supercall.rs`).

Two things we already have that matter here:

* `susfs_kpm` registers `KPM_CTL0(susfs_ctl0)` and a syscall-hook command
  channel on `__NR_kcmp` (= 272) — `syscall(272, SUSFS_CMD_MAGIC, cmd_buf,
  out_buf, out_len, rc_out)` — which needs **no superkey**. That is the path a
  metamodule userland tool should use, because it works from any root shell.
* `KPM_NAME()` / `.kpm.info` so the loader accepts it without a version dance.

### Boot timeline, assembled

```
[init]  ... -> exec /data/adb/apd -s <key> post-fs-data
[apd]   report_kernel("post-fs-data","before")
[kern]    load_ap_package_config(); sucompat_init();
[kern]    load_ap_kpm_modules()        -> our KPM's init(args=NULL, event="post-fs-data")
[kern]    notify .kpm.event("post-fs-data","before")   <-- ENGINE POINT A
[apd]   sepolicy + restorecon
[apd]   metamodule metamount.sh        <-- ENGINE POINT B (userspace, ours)
[apd]   each module post-fs-data.sh
[apd]   report_kernel("post-fs-data","after")
[kern]    notify .kpm.event("post-fs-data","after")    <-- ENGINE POINT C
[apd]   services / boot-completed stages
```

**Point A is the one to build on**: it fires before any userspace mount script,
before the module scripts, and before zygote — and it already runs in kernel
context with the KPM loaded. Point B stays as the fallback/hot-reload API for
when the user list changes at runtime.

## 4. Design

### 4.1 Artifacts

```
metamodule/module.prop        id=kpmmount, name="KPM Mount", metamodule=1
metamodule/customize.sh       deploy the engine (only if absent) + mctl; enable
metamodule/metamount.sh       THE mount policy hook: E7 -> E4, guard logic
metamodule/metainstall.sh     appended to every later module install (records)
metamodule/metauninstall.sh   module-removal hook (records; no live unmount)
metamodule/boot-completed.sh  disarms the guard, logs what the engine reached
metamodule/action.sh          the APM Action button (see 4.4)
metamodule/uninstall.sh       last act: hand the module set to real overlayfs
kpm/                          engine, ships as the .kpm (extend susfs_kpm, or a 2nd KPM)
kpm/features/mount_*.c        new feature files, one concern each
tools/mctl                    static aarch64 client for the kcmp channel
tools/btf_offsets.py          offset extraction (already there)
```

Runtime layout, all under `/data/adb`:

```
kpmmount/enable                  mounting on (created by customize.sh)
kpmmount/force_e4                always use real overlayfs instead of the engine
kpmmount/disabled_boot           bootloop guard tripped; mounting suppressed
kpmmount/.booting                armed at post-fs-data, cleared by boot-completed
kpmmount/pending                 install/uninstall records from meta*.sh
kpmmount/mount.log               every decision the scripts made
kpmmount/rw/<part>/{upper,work}  E4 upperdir/workdir (on a tmpfs)
kpmmount/bin/mctl                userspace client
ap/kpm/susfs_kpm/susfs_kpm.kpm   the engine, in KernelPatch's autoload slot
```

Note what the guard does *not* do: it never drops `disable` inside
`/data/adb/modules/kpmmount`. That marker would also put us into apd's
`check_install_safety()` branch (refusing regular module installs) and would stop
the metamodule's own `<stage>.sh` scripts from running - i.e. exactly the scripts
that are the way out. `disabled_boot` plus the Action button's `rearm` give the
same protection with neither side effect.

`mctl` subcommands mirror nomount's `nm` so the two are interchangeable while
we migrate: `mctl version`, `mctl rule count`, `mctl rule list`,
`mctl rule clear`, and `rule add [--whiteout]` reading NUL-separated
`virtual\0target\0` pairs on stdin. One syscall per batch, not per path.

### 4.2 Engine options

| | E4: real mount + hide | E5: full nomount port | **E7: dcache synthesis** |
|---|---|---|---|
| what it does | KPM (or script) mounts overlay/bind at `/system`, then hides the mounts | shadow `i_op`/`i_fop`/`d_op`/`s_op`, pseudo inodes, lookup + iterate interception | pre-create synthetic dentry+inode pairs in `/system`'s dcache; merge `getdents64` for listings |
| `/proc/mounts` | changed, must be filtered | clean | clean |
| `st_dev` / `statfs` | changed, must be faked | correct | **correct by construction** (`i_sb` is the real one) |
| runtime cost | none | lookup + readdir on touched dirs | dcache hit; only readdir of touched dirs |
| code size | ~150 lines + hiding | ~800-1000 lines, 9 shadow structs/KMI | ~350-500 lines, 1-2 shadow structs/KMI |
| BTF offsets needed | few (mount API) | ~40 | ~15 |
| risk | detection is a moving target; hiding must be complete | most code, `d_lock` surgery on live inodes | dentry lifetime/`d_invalidate` races |
| verdict | good fallback, not "hidden" | correct but too expensive to start with | **primary** |

E7 works because of one property: a dentry+inode pair we fabricate on
`/system`'s superblock is indistinguishable from a real one to everything that
does not read the directory listing. `st_dev` is `sb->s_dev`, `st_ino` is ours
to choose, and nothing appears in `/proc/mounts`. Additions
(`/system/bin/foo`) and replacements (`/system/bin/sh`) both collapse to
"install a dentry under the right parent", and additions of whole directories
collapse to "install a pseudo dir inode whose `iterate_shared` forwards to the
module's real directory inode".

What E7 deliberately does not do in v1: whiteouts (module requests deletion)
and opaque-replace directories. Those need either a negative-dentry keeper or
a real `i_op` shadow, and they are the part most likely to be detectable and
most likely to break something. A module that needs them falls back to E4.

### 4.3 Phases

* **P0 — scaffold + E4 fallback (works end to end).** *Landed.* The metamodule
  package (`metamodule/*`, id `kpmmount`) performs the mounts the old APatch did
  (overlay per partition, E4), arms and disarms a bootloop guard, reports state
  through `boot-completed.sh`, exposes the Action button, hands the module set to
  overlayfs if it is uninstalled, and reacts to installs/removals through
  `metainstall.sh`/`metauninstall.sh`. The KPM keeps loading from
  `/data/adb/ap/kpm/susfs_kpm/susfs_kpm.kpm`, and `customize.sh` only installs it
  when it is not already there, so the two packages never fight over it. CI now
  builds a second zip (`kpmmount-<sha>.zip`). Goal: on stock APatch, modules mount
  again, under our control, with no APatch patch. This is the safety net for P1.
* **P1 — E7 engine in the KPM.** `ctl0` rule API + `mctl` client + `.kpm.event`
  hook on `post-fs-data/before` that scans `/data/adb/modules/*` on its own and
  synthesizes the dcache. `metamount.sh` then stops calling `mount` and simply
  pokes the engine (its E7 branch already speaks the `mctl rule ...` contract
  above, so nothing there has to change).
  `getdents64` hook merges listings for the touched directories only.
* **P2 — close the gaps.** Whiteout/opaque, hot add/remove without reboot,
  `statfs`/`s_ino` polish, and tighter guard reporting.

### 4.4 The APM button is `action.sh` (no app change needed)

The requested "功能按钮 in APM" costs no APatch patch, because APM already has a
generic one and it is driven by the module directory:

| Step | Where |
|---|---|
| `"action"` flag = `action.sh` (or `<id>.lua` action) exists in the module dir, for *every* directory with a `module.prop` - metamodules included | `apd/src/module.rs::_list_modules()` (`path.join(action.sh).exists()`), `defs.rs:21` |
| the Compose item draws a play button whenever that flag is set, with no metamodule filter | `app/.../ui/screen/APM.kt` (`if (module.hasActionScript) { ... FilledTonalButton ... }`) |
| the list sorts enabled metamodules first, so our entry and its button are on top | `app/.../ui/viewmodel/APModuleViewModel.kt` (`compareByDescending { it.metamodule && it.enabled }`) |
| tapping it opens `ExecuteAPMActionScreen`, which runs `apd module action kpmmount` and streams stdout+stderr into the on-screen log | `app/.../ui/screen/ExecuteAPMAction.kt` -> `util/APatchCli.kt::runAPModuleAction()` |
| apd runs `/data/adb/modules/kpmmount/action.sh` with `AP_MODULE=kpmmount`, cwd = module dir | `apd/src/module.rs::run_action()` -> `exec_script()` |

So the button *is* `metamodule/action.sh`: `status` (state / engine / KPM /
mctl / rule count / guard), a hot `apply` that rebuilds the dcache rule set when
the engine is up (and honestly says "reboot" when only E4 is available, because
real mounts cannot be redone on a live `/system`), `rearm` for the bootloop
guard, `enable`/`disable`, and an `e7`/`e4` preference switch. Everything it
prints is the log the user reads in the app.

### 4.5 Open items to check before P1 code

1. ~~Is `CONFIG_OVERLAY_FS` present?~~ **Answered, provisionally yes.** The
   GKI common tree at `/tmp/aclk/common` (6.6.144, same `android15-6.6` family
   as the device's 6.6.118) has `arch/arm64/configs/gki_defconfig:662:
   CONFIG_OVERLAY_FS=y`, and it survives into that tree's built `.config`
   together with `CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW=y` and
   `CONFIG_OVERLAY_FS_INDEX=n`. Same defconfig also has
   `CONFIG_KALLSYMS_ALL=y` (line 50), which is what makes in-KPM
   `symbol_lookup_name()` of non-exported text symbols work at all.
   Caveat: this is a desktop-side tree, not the device. `/tmp/aclk/build` is
   `6.6.144-4k-g9637ed13f1e9-dirty`, GCC-built with KASAN on and `LTO_NONE`,
   so it is *not* the device kernel and only gki_defconfig transfers. The
   device-side confirmation is one line in the engine's init:
   `get_fs_type("overlay")` (and log `OVL_FS_SUPER_MAGIC`), or
   `[ -e /sys/module/overlay ]` if we prefer to keep it out of the kernel.
   Also note `OVERLAY_FS_INDEX` is off, so a module that uses
   `redirect_dir`/`index` features will not behave like full overlayfs.
2. `inode_operations` / `file_operations` / `dentry_operations` field offsets
   for 6.6 — extend `tools/btf_offsets.py --vfs` and re-run the 18-point
   self-check before trusting any new offset.
3. Whether the synthetic dir inode's `iterate_shared` can be forwarded by
   opening the module's real directory inode (needs `vfs_open`/`dentry_open`
   on a real path) or whether we must reimplement `filldir`.
4. Where the engine gets its file list at point A: in-kernel `iterate_dir`
   over `/data/adb/modules` (the pattern `userd.c` already uses, with
   `set_priv_sel_allow(current, true)`), versus a manifest written by
   `metamount.sh`. In-kernel is fewer moving parts and lower overhead; keep
   the manifest as the hot-update path.
5. Unload story: `KPM_UNLOAD` while dentries we created are alive. Safer to
   make `exit` refuse unless every rule has been torn down first.
