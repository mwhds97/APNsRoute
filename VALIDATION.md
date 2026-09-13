# Validation — 1.2.0

## Device evidence

The user confirmed experimental6 works without the earlier crash and supplied three doctor snapshots on iPhone SE (2020), iOS 14.8, Substitute 2.3.1 and Surge 5.5.3. All snapshots identify apsd PID **10284** and protocol v22.

| Stage | Monitor generation | Ready courier | Previous courier | Endpoint requests / awaiting |
| --- | --- | --- | --- | --- |
| Cellular before | 1 | #2 | — | 0 / 0 |
| Wi-Fi | 2 | #5 | #2 failed/cancelled after one retirement request | 1 / 0 |
| Cellular after | 3 | #10 | #5 failed/cancelled through owner cancellation | 1 / 0 |

Older pending and tracking-skip counts were zero in all readings. The request count stayed at one on return to cellular because the Wi-Fi courier closed through its owner's path. The same PID and progressing generations support process continuity across the sequence; the user reported no crash. Wi-Fi also created one additional init object and several secondary attempts that failed with POSIX 50. A successful courier reached readiness on each network. Diagnostic observations are not a verified mapping to Surge rows; the user's observation supplies the practical success confirmation.

The release binary itself has not been run remotely on the phone. Confirmation applies to the experimental6 behavior and this reported round trip. Earlier experimental5's CFNetwork SIGABRT remains documented in INVESTIGATION.md; the exact private assertion was not supplied.

## Cleanup preservation

The release keeps routing predicates, NECP input changes/guards and returned bytes, the current-endpoint API, three-second timing, eight-object bound, native callback forwarding and owner-requested cancellation behavior. The controller, installer scripts and saved configuration are unchanged. Source edits clarify lifecycle names, use designated initialization and shared reference transfer, and remove an unused include. Version/build identity changes to 1.2.0 / 0x01020000; protocol v22 and its 185 fields remain.

PRESERVATION-REPORT.txt records optimized IR comparison against experimental6 for eleven runtime C units on arm64 and arm64e. Ten units match on both architectures after normalizing only the expected build ID and renamed private globals. Retirement.c differs because helper extraction and statement layout affect generated IR; it was reviewed at source level and passes the same lifecycle tests and sanitizer checks. This is not a claim of IR or binary identity for the entire release.

## Host regression coverage

`BLOCKS_CC=/path/to/clang sh tests/run.sh` passes:

- All 13 domain/CIDR rules, boundaries, hostname case/root dot, IPv4-mapped literals, arbitrary ports and unrelated endpoints.
- Actual constructor modes, invalid/missing configuration, unsupported OS, missing hook engine and missing current-endpoint capability; nine hook requests and retirement initialization only after setup. Disabled mode starts no retirement monitor.
- Actual NECP parser/ADD forwarding, exact changed-byte offsets, original exclusions/flags, agent conversion, checked delegates, malformed/conflicting layouts, native/failure passthrough and errno. Result parsing and client/flow tracking preserve returned bytes.
- Eight independent connection rows, scalar IDs, handler/address reuse, delayed stale callbacks, terminal slot reuse, capacity, saturation and retirement counts distinct from caller cancellations.
- Actual escaping state/receive Blocks with the real LLVM Blocks runtime. Original values, callbacks/errors, count and errno survive forwarding. NULL/unmatched traffic, content plus error and late callbacks are covered. Existing send completions remain untouched.
- Caller-requested cancellation upgrade and native fallback. Automatic retirement calls only current-endpoint cancellation, forwards synchronous internal cancellation without upgrading it, preserves caller counters and fabricates no callback. Missing endpoint capability causes no full cancellation.
- Retirement monitor Block with an explicit fake monotonic clock and bounded dispatch harness: both network directions, initial baseline, fresh readiness after transition, cellular spares opened on Wi-Fi, repeated starts, early data, deadline cleanup, stale queued work on flaps, single timer rescheduling, mixed/null/unsatisfied path suspension and resumed settling.
- Retirement ownership/error paths: natural closure, handler clear/replace, stale terminal callbacks, native endpoint-failure reentry that creates a replacement, path-query reentry, capacity/ID/handler skips, disabled/missing-hook initialization, queue/monitor allocation failure and clock failure. Endpoint calls run without a held registry mutex; new replacement objects remain alive and untouched.
- Endpoint requests with deferred native results: retained references, awaiting state, no duplicate request during network flaps, WAITING/READY recovery on the same NW object, rearming on the next handover, native cleanup and ignored late callbacks.
- Coherent diagnostic publication, all names, per-row/global retirement updates, partial-write recovery and denied access. The actual formatter renders normal, awaiting, suspended, disabled and unavailable retirement states with explicit limitations.
- Actual installer/controller scripts, automatic enablement and one installation reload, fresh/upgrade/reinstall, failure handling, manual disable and read-only doctor.

The sanitizer run compiles `tests/test_retirement.c` and `tests/test_nw_observer.c` with clang `-target x86_64-linux-gnu -fblocks -fPIE -O1 -g -fsanitize=address,undefined`, includes `tests/include` and the vendored Blocks runtime, and links using the host compiler with the same sanitizers. Runtime objects and Connections.c are instrumented too. Retirement's main/disabled/missing/queue-failure/monitor-failure cases and the observer case pass with `UBSAN_OPTIONS=halt_on_error=1`.

These are deterministic host fixtures, not a live iOS concurrency or integration test. They cannot establish the path monitor's interface classification under Surge, or apsd's response to an externally initiated cancellation.

## Build and package gates

The cross-build uses cached clang 13 revision f765bf5b71fd3637a6f6d1d3e6ab95ca91892a0c and the iPhoneOS14.5 SDK. Makefile and build.py share eleven C units for arm64 and legacy arm64e, with a standalone arm64 doctor. Eleven known legacy arm64e ABI warnings remain. BUILD-REPORT.txt records the compiler, dependencies and output hashes.

`python3 tests/verify_package.py` checks release name/version, upgrade ordering from 1.1.0 and experimental6, the apsd-only filter, automatic activation, shell syntax, permissions and all ad-hoc signature page hashes. It requires protocol v22 and endpoint/monitor diagnostics, and rejects runtime logging, process signals, new create/start/send/receive imports, connection-queue mutation, retired NECP result masking, DNS/proxy mutation and probes. Current-endpoint cancellation remains dynamically resolved without a terminal-cancellation fallback.

The source archive includes the release installer and unchanged working experimental6 rollback installer, source/tests/docs, BUILD-REPORT.txt and PRESERVATION-REPORT.txt. SHA256SUMS.txt covers every included member except itself. Archive CRC, member digests and equality of standalone installer/README with archived copies are verified before delivery. Obsolete experimental rollback installers are omitted from the release bundle.

## Verification scope

The host regressions and targeted lifecycle ASan/UBSan run pass. Leak detection is disabled (`ASAN_OPTIONS=detect_leaks=0`); no leak-detector result is claimed. Explicit reference-count fixtures cover release/cleanup paths. These are deterministic host tests rather than live iOS concurrency tests.

For any new handover issue, keep the same apsd PID through cellular → Wi-Fi → cellular and compare doctor status, generation, requests, awaiting state, and skips. Confirm old TCP/Surge entry closure and notification delivery separately. Object IDs can survive endpoint fallback; a zero pending count alone does not prove closure. No zero-delay or zero-init-traffic guarantee is made. The unchanged working experimental6 installer is included for rollback.
