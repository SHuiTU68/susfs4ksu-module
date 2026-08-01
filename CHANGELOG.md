## hookless branch (based on v1.5.2+ R28)
### Notes
This branch adapts the module for the **KernelSU-Next `susfs-hookless`** kernel
([MirahSyakilla/KSUN](https://github.com/MirahSyakilla/KSUN)), which moved SUSFS
inside KernelSU-Next and talks to userspace via the `reboot(0xDEADBEEF,
0xFAFAFAFA, cmd)` supercall — the same protocol the module's `ksu_susfs`
universal binary already uses, so the stock binary works unchanged.

### Why a separate branch
hookless SUSFS reports `version=v0.2`, `variant=hookless`, and feature names
like `sus_path` / `open_redirect` (NOT `CONFIG_KSU_SUSFS_*`). The base scripts
gate features on `>= 1.5.x` version and `CONFIG_KSU_SUSFS_*` names, so on
hookless most features were wrongly skipped. `utils.sh:susfs_hookless_normalize`
(re-run after the version/features probe in each boot script) detects hookless
and:
* bumps the decimal version to 2.5.9 so the base's v2.x code paths run for the
  features hookless supports (hide_sus_mnts, set_cmdline_or_bootconfig,
  open_redirect uid_scheme, sus_path_loop, ...);
* injects `CONFIG_KSU_SUSFS_OPEN_REDIRECT` / `CONFIG_KSU_SUSFS_SUS_MAP` so the
  feature gates recognise them.

### hookless limitations (by design)
hookless removed these commands, so they are skipped (feature-gated out):
* `add_sus_mount` / `add_try_umount` — per-path mount hiding is gone; mount
  hiding is the global `hide_sus_mnts_for_non_su_procs` toggle + KSU umount
  policy (the base already falls back from `hide_sus_mnts_for_all_procs` to
  `_for_non_su_procs`, and uses `ksud kernel umount add` on v2.x).
* `sus_su` — needs the core kprobe hooks hookless disables; `config.sh`
  defaults `sus_su=0` and the base's feature check sets it to -1 without ever
  invoking `sus_su`.
* `set_sdcard_root_path` / `set_android_data_root_path` — not wired in hookless;
  guarded with `susfs_is_hookless` to avoid noisy "not supported" errors.

### Known caveat
The WebUI frontend reads `ksu_susfs show enabled_features` directly (not through
the shell normalize), and hookless's feature names don't match the
`CONFIG_KSU_SUSFS_*` strings the WebUI checks, so some status badges may show
"Disabled" and a few custom-path editors may be hidden even though the features
work. The module scripts themselves are fully functional. Editing the path
`.txt` files directly always works.

## v1.5.2+ Revision 28
### Notes
Sorry for the very late update. This update focuses on WebUI configuration import/export, boot-stage script performance and correctness fixes, and better handling of newer susfs (v2.0.0+/v2.1.0+) kernel implementations.

For more frequent updates use the CI version [here](https://nightly.link/sidex15/susfs4ksu-module/workflows/build/v1.5.2%2B?preview)

### WebUI
* Implement SUSFS import config feature
    * Include/exclude "Auto add and umount for zygote system process" flag files in export/import depending on the detected susfs version (not applicable on susfs v2.0.0+)
    * Use `LegitSusfsConfig` to check the validity of the susfs config file.
    * Exported config files are compatible to import from v1.5.2 and above
* Hide 'try umount for zygote system process' toggle on susfs v2.1.0+ with susfs `try_umount`
* Disable `avc_log_spoofing` toggle when greyed out
* Add date to exported susfs logs gzip filename, export to `/sdcard/Download`, and fix export error by only reading the first pid of zygote64
* Refactor `index.js` into feature-based modules
* Localization
    * New Crowdin translations by GitHub Action

### Scripts
* boot-completed: reduce boot-stage overhead and fix correctness issues
    * Reuse the cached `$susfs_features` variable instead of respawning the susfs binary in post-fs-data.sh and service.sh (4 fewer binary calls per boot)
    * Capture `dmesg` once per stage instead of invoking it twice for log append and timestamp extraction
    * Skip `stat()` calls in the open_redirect loop for lines already skipped by `execute_on`
    * Replace `cat | grep` patterns with direct `grep` on `/proc/1/mountinfo`
    * Collapse the five duplicated hide_cusrom `find` blocks into a single case-driven block
    * Replace the per-entry 14-pipeline JSON sus_kstat parser with a single awk pass per object
    * Bound the previously unbounded `/sdcard/Android/data` wait to 60s to prevent boot-completed hanging indefinitely
    * Fix a typo (`sus_su_acitve` -> `sus_su_active`) and remove a duplicate echo that caused key duplication in config.sh
* boot-completed: catch sus_mount mountid tagged within 2 billion for newer susfs implementations
* boot-completed: do not enable ksud umount feature if auto try umount (userspace) is enabled
* service: only use sus_kstat spoofing when it's on susfs v2.0.0+
* customize: add `SUSFS_DECIMAL_MAIN` for checking sus_su install
* Fix GKI bootconfig spoof formatting to match the `key = "value"` bootconfig syntax instead of the compact cmdline format @okhsunrog

### [Universal SUSFS Binary](https://github.com/sidex15/susfs4ksu-binaries/tree/universal-binary)
* refactor: split monolithic main.c into modules built via Makefile
* implement have_susfs_feature function for checking features in dispatch and help menu
* Replace nested-if version parser with a data-driven lookup table.
* limit support for umount_for_zygote_iso_service to v1.5.9-v2.0.0
* reduce requirement for try_umount_for_zygote_iso_service down to susfs v1.5.9
* skip v2.0.0 sus_path layout check if it's on susfs v2.1.0+
* implement add_sus_memfd exclusive feature, port from v1.3.8 susfs (experimental)
    * This is only for custom kernels with modified susfs patches, such as [this one](https://github.com/sidex15/android_kernel_lge_sm8150/commit/bc23096b9df4d76c43bfea9e217978ecc93b94d4)

### Dev Note
Sorry for the very late update. I'm currently under thesis this year. Apologies for the very slow update 😔. I hope you understand 😊