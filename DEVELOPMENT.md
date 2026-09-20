# Development — 1.2.1

Package `local.apnsroute`; version `1.2.1`; build ID `0x01020100`; doctor protocol v24. Rootful Darwin 20 / iOS 14 only. Promotes the tested experimental2 transition policy with one shared minimum two-second quiet gate. The only runtime cleanup is a shared duration constant used by the deadline calculation and the diagnostic minimum; routing and lifecycle policy are unchanged.

## Build

```sh
BLOCKS_CC=/path/to/clang sh tests/run.sh
python3 tests/sanitize.py --clang /path/to/clang
python3 build.py --toolchain /path/to/bin --sdk /path/to/iPhoneOS14.5.sdk
python3 tests/verify_package.py
```

Makefile and build.py share eleven C translation units. The tweak contains arm64 and legacy arm64e slices and links Network/libSystem; doctor is standalone arm64. BUILD-REPORT.txt records the actual compiler/dependencies/warnings. No build command downloads dependencies or writes to the phone. The test-only LLVM Blocks runtime is included under tests/vendor. Installer/controller/configuration/filter files remain byte-identical to experimental2, including automatic activation and one installation apsd reload.

## Preserved contracts

- The apsd-only constructor reads the existing mode and checks Darwin 20. Routing uses the same 13 domain/IP rules on outgoing TCP metadata, regardless of port. Metadata is not resolved or packet-inspected.
- The same unique usable utun selection, NECP ADD input copy/guard logic, exact Cellular/Internet agent preference conversion and original interface prohibitions remain. Returned kernel bytes are unchanged.
- Original callbacks/arguments/errors/errno and connection queues are preserved. Native owner cancellation is forwarded using the existing normal-to-force policy. Automatic retirement uses only optional public `nw_connection_cancel_current_endpoint`, with no terminal-cancel fallback or synthetic callback.
- Eight connection rows own no references. The separate retirement registry owns at most eight objects, with at most eight additional temporary batch references. IDs/handler generations guard late callbacks. Missing IDs/handlers/capacity are counted. Native terminal states, owner cleanup and handler clear release registry ownership.

## Shared quiet gate

Retirement.c owns one physical monitor, one network-change subscription, one coalesced quiet timer, one one-second interface check timer and one coalesced work callback on its serial queue. Mutex-protected native state/start/owner hooks communicate with that queue. References used by a batch are acquired under the mutex; endpoint requests and releases occur outside it.

A confirmed physical type change, VPN on/off/replacement, or observed loss/recovery of reliable state calls `note_activity`. It updates one monotonic deadline using `APR_QUIET_PERIOD_MS` (2,000 ms), converted to nanoseconds. The same constant supplies the reported duration. Events before completion of the gate accumulate in the same group. An already scheduled earlier timer remains bounded and rechecks the latest deadline when it wakes, rescheduling for the remainder rather than acting on stale time or object lists. Remaining milliseconds are rounded upward. Duplicate unchanged snapshots do not reset the deadline.

Every automatic batch passes through `drain`. It first refreshes the tunnel snapshot, so a missed event discovered at cleanup time extends the deadline. It then requires both a satisfied known physical type (once that baseline has existed) and a known on/off tunnel state. Before the first physical baseline, a valid VPN transition can still use the same gate. Unknown/mixed physical paths and failed/ambiguous tunnel reads block all automatic batches. Recovery starts a fresh complete quiet period; repeated invalid samples are not interpreted as repeated VPN-off.

The first cold physical/VPN observations are baselines, not cleanup events. A first baseline arriving inside an already active transition group extends that group's wait. After the deadline, all currently eligible objects are selected together. `batches` increments only if at least one endpoint request is submitted. Native closures may make a group produce no batch.

Per-object physical first-readiness and VPN start/request generations remain separate for eligibility. Physical first readiness after a switch is protected as before. An in-flight older VPN start remains old when first ready. A post-final-change start is current and kept; a mid-group start can become old at a later VPN event. The batch stamps both current generations and marks awaiting before calling Network. No duplicate request occurs while awaiting. Native READY clears awaiting and updates physical readiness; it keeps the VPN request generation so a later VPN change can still be handled, subject to the same gate. Late readiness can legitimately produce an additional batch after the original group has settled.

The old fresh-receive trigger, current-path sample and `apr_retirement_received` callback are removed. NWObserver retains receive diagnostics and exact forwarding, but data cannot initiate cleanup. Readiness-triggered work cannot bypass a deadline changed after it was queued. This timing applies only to autonomous APNsRoute calls, not closures already requested by apsd, iOS or the VPN app.

Clock or generation overflow disables automatic work, releases owned references without cancellation and reports an error. Disabled/missing-capability startup creates no monitor/timers. Timer callbacks stop rescheduling once inactive. Hooks, monitor and notification registration otherwise have process lifetime.

## VPN observation source

`apr_tunnel_select(0, ...)` is unchanged. Unique addressed/up utun is on, no usable utun is off, different name/index is replacement. Same-interface address-family changes do not advance the VPN generation. Other outcomes retain the last valid baseline and suspend cleanup.

The `com.apple.system.config.network_change` notification is a hint, backed by [Apple configd's key definition](https://github.com/apple-oss-distributions/configd/blob/585b7f2fca293f4642d21d15c5daf187f63c4796/SystemConfiguration.fproj/SCPrivate.h) and [IPMonitor posting](https://github.com/apple-oss-distributions/configd/blob/585b7f2fca293f4642d21d15c5daf187f63c4796/Plugins/IPMonitor/ip_plugin.c). The SDK supplies notify_register_dispatch's ABI. Registration failure leaves one-second local fallback checks active. No probe packets, private SystemConfiguration calls, file/unified logs or DNS lookups are added. Coalesced/unobserved off/on cycles returning to identical identity remain undetectable; no claim of observing every UI toggle is made.

## Doctor protocol v24

Magic `0x41505248`, prefix `local.apnsroute.v24`, build ID `0x01020100`. The schema remains byte-for-byte compatible with experimental2: 200 fields (194 transport fields including the sequence). Quiet state, group, observed-event count, cause mask, remaining milliseconds at last check and actual batch count are retained, with no new counters or notifications.

Cause bits: 1 physical change, 2 VPN on, 4 VPN off, 8 tunnel replacement, 16 uncertainty/recovery. Quiet state is idle, waiting or blocked. `ret-pending` counts established eligible objects for either physical/VPN age, excluding awaiting objects. `vpn-pending` also covers older VPN objects not yet ready or still awaiting recovery. These counters are observations, not confirmed TCP closures. Group event counts include reliability changes, not only VPN toggles.

Publication retains the odd/even coherent snapshot and dirty-field retry mechanism. Runtime observation timestamps/counters are read-only to doctor; its remaining-time line is not a live countdown. The independent socket snapshot and connection rows retain their limitations. No payload data, pointer identities or destination strings are added to diagnostic publication.
