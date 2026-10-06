# Duck-Detector: what it probes, and what this module does about it

Recon pass against `https://github.com/eltavine/Duck-Detector-Refactoring`
(tree SHA `82566ffa96bbf464aacab05486c042b1cd87eb3c`, 2026-10-06), written
because the app grew detection items that target things this module does.

Upstream is a Kotlin/Compose multi-module project (936 `.kt` files) under
`app/ build-logic/ capability/ core/ feature/ sdk/`. Probes live in
`feature/<name>/data/.../probes|detectors/`, and each feature ships an
`EVIDENCE.md` that documents the observable signal, the producing subsystem,
the mechanism, the visibility limits and the result states. Those EVIDENCE
files are the useful part: they state plainly what counts as `danger`.

## 1. Newest probes (last commits before this pass)

| Commit | Item | Detects |
| --- | --- | --- |
| `88cc5500` | `feat(memory): compare privately copied system code with its file (#162)` | private executable pages of system mappings whose bytes differ from the file on disk |
| `3c76a554` | `feat(bootloader): report a vbmeta digest of empty input as danger` | `ro.boot.vbmeta.digest` equal to SHA-256/SHA-512 of empty input |
| `f894d834` | `feat: flag abusive soter pubkey and cpuid` | faked SOTER pubkey / CPU id in TEE attestation |

New files worth knowing about:

```
feature/memory/data/src/main/cpp/memory/detectors/system_copy_detector.cpp
feature/memory/data/src/main/cpp/memory/detectors/system_copy_comparison.cpp
feature/memory/data/src/main/cpp/memory/common/page_access.cpp
feature/bootloader/data/.../repository/BootloaderPropertyFindings.kt
feature/tee/data/.../soter/SoterAbuseAnalyzer.kt
```

## 2. Shared storage: the probe our `sus_path_duck.txt` answers

`feature/dangerousapps/data/.../repository/SharedStorageProbes.kt` enumerates
`/sdcard/Android/{data,obb}` through **four** independent methods and compares
the results:

1. `File.listFiles()` on the plain path;
2. `ls <plain path>` (a process, to catch libc/FUSE differences);
3. a **zero-width bypass**: `"/sdcard/Android/data/".dropLast(1) + U+200B +
   "/"`, i.e. `"/sdcard/Android/data\u200B/"`;
4. **ignorable code points** `U+00AD U+FE02 U+FE0F U+FEFF U+FFA0` inserted at
   three positions each:

```kotlin
"$targetPath$bypassChar/"                                   // /sdcard/Android/data<cp>/
"/sdcard/${bypassChar}Android/${leaf}"                      // /sdcard/<cp>Android/data
"/sdcard$bypassChar/Android/${leaf}"                        // /sdcard<cp>/Android/data
```

The inserted character defeats a FUSE path check while still resolving to the
real directory, so the listing succeeds and leaks the package names HMA hides
from PackageManager — reported upstream as an "HMA mismatch".

**Counter-measure (in the module since before this pass, but never shipped):**
`tools/gen_sus_path_duck.py` writes `sus_path_duck.txt` with all variant
spellings (108 entries over `/sdcard`, `/storage/emulated/0`,
`/storage/self/primary`), and `boot-completed.sh` registers each line as a
`sus_path`, so the probe's `openat()` returns `-ENOENT`.

**The bug this pass fixed:** the file existed in the repo and on the dev box,
but the CI `for f in ...` list that builds the zip never named it, so the
whole block was dead code in every published release. Evidence on the device:
`/data/adb/modules/susfs4ksu/boot-completed.sh` carried the block at line 557,
but `sus_path_duck.txt` was absent from the module dir and `susfs1.log`
contained **no** `[sus_path_duck]` line. Now:

* `sus_path_duck.txt` is in the CI file list;
* the build asserts `sus_path_duck.txt` / `sus_path.txt` / `sus_mount.txt` are
  in the assembled zip and fails otherwise;
* `tools/check_sus_path_duck.py` re-derives the probe's path set (including
  the trailing-slash normalisation) and fails if any spelling is missing;
* the verifier runs as a CI step *before* the zip is assembled.

## 3. Boot properties: the contradiction this pass fixed

`feature/bootloader/EVIDENCE.md` documents a signal called *"Boot properties
and raw boot parameters"*:

> Observable signal: verified boot, lock, AVB and verity properties from
> several sources, and `androidboot.*` values in `/proc/cmdline` and
> `/proc/bootconfig`.
> Mechanism: a spoofing module that rewrites properties in one source often
> misses another.
> Interpretation: disagreement between sources is itself evidence of
> rewriting.

Sources it reads: reflection, `getprop`, native libc, `System.getProperty`,
`/proc/cmdline`, `/proc/bootconfig`.

`service.sh` spoofs the lock/AVB properties with `resetprop`:

```
ro.boot.vbmeta.device_state=locked        (check_missing_match_prop)
ro.boot.verifiedbootstate=green           (check_missing_match_prop)
ro.boot.flash.locked=1                    (check_missing_match_prop)
ro.boot.veritymode=enforcing              (check_missing_match_prop)
ro.boot.warranty_bit=0                    (check_missing_match_prop)
vendor.boot.vbmeta.device_state=locked    (check_reset_prop)
vendor.boot.verifiedbootstate=green       (check_reset_prop)
```

Those are *userspace* rewrites. The kernel's own view still carried the
bootloader's originals, and the resulting contradiction was live on this
device:

```
getprop               ro.boot.vbmeta.device_state   -> locked
/proc/bootconfig      androidboot.vbmeta.device_state = "unlocked"
getprop               ro.boot.verifiedbootstate     -> green
/proc/bootconfig      androidboot.verifiedbootstate = "orange"
```

**Counter-measure:** susfs already has
`CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG`; the module used it only for the
cosmetic product-name rewrite, behind `spoof_cmdline=1`. `boot-completed.sh`
now has `_sync_androidboot <file> <gki|cmdline>`, which:

* rewrites every `androidboot.<key>` line to repeat the live `ro.boot.<key>`
  property (`flash.locked warranty_bit vbmeta.device_state vbmeta.size
  vbmeta.digest vbmeta.hash_alg vbmeta.avb_version
  vbmeta.invalidate_on_error verifiedbootstate veritymode`);
* appends the keys the module creates as properties but that this kernel never
  put on the command line (`flash.locked`, `warranty_bit`, `vbmeta.size`,
  `vbmeta.digest`, `vbmeta.hash_alg`, `vbmeta.invalidate_on_error`);
* matches the **exact** key, so `veritymode` never rewrites
  `veritymode.managed = "yes"`;
* runs whether or not `spoof_cmdline=1`, because the inconsistency is not
  cosmetic — it exists as long as `service.sh` keeps resetprop'ing.

Verified against this device's real files (kernel `mt6991`, GKI bootconfig):

```
androidboot.vbmeta.device_state = "locked"      (was "unlocked")
androidboot.verifiedbootstate   = "green"       (was "orange")
androidboot.flash.locked        = "1"           (appended)
androidboot.warranty_bit        = "0"           (appended)
androidboot.vbmeta.size         = "12864"       (appended)
androidboot.vbmeta.digest       = "d96a3b49…"   (appended)
androidboot.vbmeta.hash_alg     = "sha256"      (appended)
androidboot.vbmeta.invalidate_on_error = "yes"  (appended)
androidboot.veritymode.managed  = "yes"         (untouched)
```

### Not addressed: the two stronger bootloader signals

* **Attested state** (`RootOfTrust.deviceLocked`, `verifiedBootState`,
  `verifiedBootKey`, `verifiedBootHash`) comes from KeyMint and is signed by
  the bootloader. Property spoofing cannot change it; on a real unlocked device
  it reports unlocked and that is `danger` regardless of what getprop says.
  This is why the property spoof is defensive only — it must not *contradict*,
  because the contradiction is a second, independent signal.
* **`ro.boot.vbmeta.digest` == digest of empty input** is `danger` (upstream
  traced it to a module that wrote `ro.boot.vbmeta.*` from a shell
  `sha256sum`). This module never writes that property, so the bootloader's
  genuine digest survives and the check passes — verified: this device reports
  `d96a3b49…`, while SHA-256 of empty input is `e3b0c442…`. The sync step above
  copies the *live property* into bootconfig, so it cannot introduce the
  empty-input value.

## 4. Not our vector (left as-is)

* `feature/memory/.../system_copy_detector.cpp` flags a system code mapping
  whose privately-copied executable page **differs from the file on disk**; it
  reads the page through a pipe precisely to dodge `process_vm_readv` /
  `/proc/self/mem`, which would trigger the forced-COW-break and copy the very
  page it reads. That targets in-process inline hooks (LSPosed/Frida), not
  path or mount hiding: a mount-hidden file compares equal to itself, which
  upstream scores as `clean` (its own EVIDENCE notes a read can create a copy
  without changing it, and that a hook installed and then removed still reads
  as equal). Worth watching only if this module ever patches pages in place.
* `feature/tee/.../SoterAbuseAnalyzer.kt` targets faked SOTER pubkeys / CPU
  ids inside attestation, which this module does not touch.
* `feature/lsposed/.../LSPosedRuntimeArtifactProbe.kt` and
  `capability/helperprocess/.../ProcMountViewScanner.kt` are LSPosed and mount
  view probes; the mount-view scanner is what `sus_mount` /
  `hide_sus_mnts_for_all_procs` answer, and upstream already had to ignore
  tmpfs capacity when comparing views (`eda92b25`).

## 5. Reproducing this recon

The GitHub *contents* API works from the device shell even when
`raw.githubusercontent.com` times out:

```sh
B=https://api.github.com/repos/eltavine/Duck-Detector-Refactoring/contents
curl -s "$B/<path>" | python3 -c 'import json,base64,sys; \
  print(base64.b64decode(json.load(sys.stdin)["content"]).decode())'
curl -s "https://api.github.com/repos/eltavine/Duck-Detector-Refactoring/commits?per_page=30"
```
