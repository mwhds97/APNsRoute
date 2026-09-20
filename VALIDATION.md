# Validation — 1.2.1

## Release scope

Release 1.2.1 promotes 1.2.1~experimental2 after the user supplied six phone snapshots and approved release. The cleanup puts the existing 2,000 ms duration in one constant shared by the runtime and doctor. Package/build identity, release documentation, activation-test upgrade cases and package gates are updated. Routing and transition policy are preserved.

## Phone evidence from experimental2

These are two independent sequences on the user's iPhone SE (2020), iOS 14.8, rootful unc0ver / Substitute 2.3.1 and Surge 5.5.3. IDs and cumulative counters apply only within each apsd process.

| Snapshot | apsd PID | Cleanup batches | Endpoint requests | Ready courier IDs |
| --- | --- | --- | --- | --- |
| 1-wifi-on-vpn-on.log | 8703 | 0 | 0 | 4 |
| 2-wifi-on-vpn-off.log | 8703 | 0 | 0 | 10, 11 |
| 3-wifi-on-vpn-on.log | 8703 | 1 | 2 | 12 |
| cellular_before (4).log | 10376 | 0 | 0 | 2 |
| wifi (6).log | 10376 | 1 | 1 | 5 |
| cellular_after (4).log | 10376 | 1 | 1 | 10 |

The VPN-on batch requests retirement of two distinct old objects once each. On return to cellular, physical change, VPN-off and VPN-on appear together in one three-observation group; normal handling cancelled the old courier and no extra automatic batch was needed. Every snapshot reports quiet idle, no older established pending objects, no awaiting responses and no tracking skips. Each sequence retains its apsd PID. Both cellular NECP samples show accepted requests with requested and returned utun2/index 21.

Historical failed attempts remain visible alongside the ready couriers. Their zero retirement-request counts do not show repeated automatic cleanup. The snapshots do not independently timestamp the two-second wait, map NW object IDs to Surge rows, or prove notification delivery. They are evidence for the tested experimental2 behavior, not a claim that this rebuilt release has already run on the phone.

## Host regressions — passed

`BLOCKS_CC=/path/to/clang sh tests/run.sh` passes. The retirement fixtures compile the actual production module and real escaping Blocks with an explicit monotonic clock/dispatch harness.

The central timing case observes physical change at t=0, VPN-off at t=0.4 s and VPN-on at t=0.9 s. No automatic request occurs before t=2.9 s. The earlier timer reschedules, a callback one nanosecond before the final deadline still produces no request, and one batch selects eligible old objects at the final deadline. Stable snapshots produce no additional batch. The reverse direction is covered.

All 17 retirement scenarios pass: main, vpn, unknown, recovery, opening, preflight, vpn-notify-failure, vpn-baseline, lifetimes, clock-failure, physical-overflow, vpn-overflow, quiet-overflow, disabled, missing, queue-failure and monitor-failure. They cover standalone toggles/replacement, three-event bursts, pre-cleanup discovery of missed events, unknown-state blocking/recovery, first baselines, late readiness, stale work, awaiting recovery, owner closure, callback reentry, capacity and bounded ownership, and nondestructive failure/overflow handling. Every mock request checks that the latest deadline elapsed, observations are reliable and the mutex is not held.

Matching, NECP input/result/exclusion, constructor, hook lookup, tunnel selection, diagnostic publication/output, connection-row and NW callback regressions pass. The doctor output fixture retains the exact displayed 2,000 ms minimum. Activation tests exercise fresh install, upgrades from 1.2.0 and both 1.2.1 experiments, release reinstall and earlier supported versions, including a previously disabled saved setting. Installation enables the tweak and requests one reload; ordinary process starts still honor the saved setting.

## Memory checks — passed

`python3 tests/sanitize.py --clang /path/to/clang` passes all 17 retirement scenarios and the NW observer fixture. Production modules and the test Blocks runtime use ASan/UBSan with `-fPIE -O1 -g -fsanitize=address,undefined` and `UBSAN_OPTIONS=halt_on_error=1`.

Leak detection is disabled (`ASAN_OPTIONS=detect_leaks=0`); no leak-detector result is claimed. Explicit reference-count fixtures cover ownership and release paths. Deterministic host tests do not reproduce live iOS concurrency or CFNetwork integration.

## Source and compiled-runtime preservation — passed

Four source files differ from experimental2: Version.h, RetirementStatus.h, Retirement.c and Diagnose.c. The other 35 source/vendor files are byte-identical. The installer/controller/configuration payload, apsd-only filter and Makefile are also unchanged.

All eleven tweak translation units produce byte-identical optimized LLVM IR on both arm64 and arm64e after normalizing only the baseline version/build identity to the release values. This includes the retirement duration cleanup. PRESERVATION.txt records the 22 matching hashes. The standalone doctor's printf format intentionally changes to use the shared duration constant; its displayed output is separately verified by the host fixture. Whole-package binary identity is not claimed.

## Cross-build and package checks — passed

The build uses the same compiler bytes as experimental2, restored from [swift-toolchain-linux v2.1.0](https://github.com/kabiroberai/swift-toolchain-linux/releases/tag/v2.1.0): `swift-5.6.1-ubuntu20.04.tar.xz`, 611901876 bytes, SHA-256 `7f7447fde0ca40e5854f732317aa66f5687ae200cb82ab08960b78a925fbcca4`. Clang revision is `f765bf5b71fd3637a6f6d1d3e6ab95ca91892a0c`; executable SHA-256 is `663ade232fdb6e28e16740b89e310de0b85afe9edc2d2e3b7801c8e6e9ed9833`.

The iPhoneOS14.5 SDK is from [theos/sdks commit 0222fd5413cf4b9af096f37b4621afa2688572f7](https://github.com/theos/sdks/tree/0222fd5413cf4b9af096f37b4621afa2688572f7/iPhoneOS14.5.sdk). The cross-build succeeds for arm64 and legacy arm64e with a standalone arm64 doctor. Eleven known legacy arm64e ABI linker warnings remain; no other warning is accepted. BUILD-REPORT.txt records compiler, dependencies, warnings and hashes. A native Xcode/Theos build remains an alternative for incompatible jailbreak environments.

`python3 tests/verify_package.py` passes. It checks release metadata and ordering above 1.2.0 and both 1.2.1 prereleases, matching source/package identity, apsd-only injection, activation scripts/modes/configuration, both dylib slices and every ad-hoc signature page hash including doctor. It requires v24 and the quiet/VPN fields, rejects the removed receive-retirement callback, and preserves checks against runtime logging, process signals, injected create/start/send/receive calls, terminal-cancel imports, callback-queue changes, proxy/parameter/DNS mutations and historical NECP result masking.

## Archive and rollback

The archive contains current source/tests/documentation, the release installer and two unchanged rollback installers:

| Installer | SHA-256 |
| --- | --- |
| 1.2.0 | `31633c7bf96312613aa52f53486db6a56e60166c32a885546af89e1e459fef11` |
| 1.2.1~experimental2 | `9b2e32f7da6a3a82aebb7510b0f2da2aa8fa53a938d922148e260627fe19a54e` |

The older experimental1 rollback payload is omitted from this release bundle. Historical entries remain in CHANGELOG.md and INVESTIGATION.md. No toolchain cache, temporary test output or raw phone logs are included. SHA256SUMS.txt covers every other archive member. ZIP CRC, manifest completeness and standalone installer/README equality are checked before delivery.

## Remaining limits

The quiet interval starts from observed state changes, not an inaccessible UI timestamp. Notifications can coalesce and timers can run late. Unknown/ambiguous states suspend automatic work. A complete off/on cycle returning to the same tunnel identity between all samples cannot be identified. Native/owner closures are not delayed. Late readiness can need later work. Coverage remains eight tracked matching apsd objects with usable handlers, and the tunnel is not authenticated as Surge-owned.

The release should load as 1.2.1 with protocol v24 after the single installation reload. Any subsequent phone check should keep apsd PID unchanged across the tested sequence and verify old Surge entries and a fresh delivered notification separately. The release label is not a guarantee of zero reconnection delay, zero init traffic or identical behavior on other devices/VPN configurations.
