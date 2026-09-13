# Development — 1.2.0

Package ID `local.apnsroute`; release version `1.2.0`, build ID `0x01020000`. Rootful Darwin 20 / iOS 14 only. This release promotes the user-confirmed experimental6 behavior. It retains all 13 rules, endpoint retirement, native callback forwarding, automatic installation enablement and doctor protocol v22.

The cleanup centralizes held-reference transfer in `detach_connection`, names first-readiness generation `ready_epoch`, names the retirement callback explicitly, and clarifies the native cancellation reentry guard. Designated initialization and separate statements improve the lifecycle state updates; an unused include is removed. Eligibility, deadlines, bounds, lock/release boundaries and callback order are retained. See PRESERVATION-REPORT.txt and VALIDATION.md for the comparison and regression scope.

## Build

```sh
BLOCKS_CC=/path/to/linux/iphone/bin/clang sh tests/run.sh
python3 build.py --toolchain /path/to/linux/iphone/bin --sdk /path/to/iPhoneOS14.5.sdk
python3 tests/verify_package.py
```

The host suite uses a C compiler, Python 3 and a Blocks-capable clang. Its LLVM Blocks runtime is a test dependency. The cross-build uses cached clang 13 revision f765bf5b71fd3637a6f6d1d3e6ab95ca91892a0c and the iPhoneOS14.5 SDK. Compiler SHA-256 is 663ade232fdb6e28e16740b89e310de0b85afe9edc2d2e3b7801c8e6e9ed9833. The compiler came from the [swift-toolchain-linux v2.1.0 distribution](https://github.com/kabiroberai/swift-toolchain-linux/releases/tag/v2.1.0). build.py downloads nothing and performs no phone operations.

Both build entrypoints read the same literal source lists in Makefile and select eleven C units: Tweak, HookEngine, Diagnostics, Connections, Retirement, NECPHooks, NECPResults, TunnelSelector, InterfaceCheck, NWHooks and NWObserver. The tweak links Network and the system C runtime, with no direct Objective-C or CoreFoundation dependency. Doctor uses Diagnose and LiveSockets. Native Xcode/Theos is an alternative (`make clean package FINALPACKAGE=1`); it was not run here.

Build/package metadata comes from control. build.py and the package verifier check its version against src/Version.h; the compiled doctor uses APR_VERSION. The shell controller delegates its version banner to doctor, and postinst has no hard-coded release text. The cross-builder accepts literal source-list assignments, without evaluating arbitrary Makefile code.

The source archive contains the active runtime, tests, documentation and the unchanged working experimental6 rollback installer. Historical socket, CFStream, SOCKS and private-parameter experiments are documented in CHANGELOG.md and INVESTIGATION.md; their runtime code is absent.

## Runtime

The apsd-only constructor checks Darwin 20 and reads the saved mode. `unbind` enables routing; `disabled` and legacy `observe` select native routing. Missing/invalid configuration or an unsupported OS requests no hooks. Postinst enables routing on every `configure` action (fresh install, upgrade, reinstall or explicit reconfiguration) by invoking `/usr/bin/apnsroutectl enable`. The existing controller writes `unbind` atomically before sending one SIGTERM to apsd. Later ordinary apsd starts honor the saved value, including a manual disable.

The shipped mode conffile intentionally retains its legacy `observe\n` bytes and registration. This avoids a dpkg content-change prompt on an already-edited configuration. It is not the final installed default: postinst writes `unbind` after package extraction, then requests the restart. No C constructor fallback or new hook is needed.

If activation fails, postinst reads the resulting mode. Failure to save `unbind` returns a configuration error. If enabled mode is already saved, a failed/unavailable restart leaves the package configured and prints explicit restart/doctor instructions, without retrying or reporting successful loading. Non-configure maintainer-script actions do nothing. This installer behavior is covered by tests/test_activation.py against both layout and the extracted package.

Both modes request nine hooks: Network create/start/state-handler/send/cancel/force-cancel/receive/receive-message and NECP client action. The existing jailbreak hook engine is resolved through its compatibility API; its global symbol need not be visible if a library lookup succeeds. Network create always forwards the original endpoint and parameters.

## Matching and routing contract

Policy, TunnelSelector, InterfaceCheck, NECPHooks, NECPResults and NWHooks remain byte-identical to experimental6. The routing and callback machinery retains its tested contracts. Compiler comparison matches ten runtime translation units on both architectures after normalizing the build ID and private symbol names; Retirement.c has expected IR changes from its reference-transfer helper and statement layout and is covered by source review and lifecycle regressions. Full-module IR identity is not claimed for Retirement.c.

Policy.h is shared by NECP routing, Network endpoint observations and doctor CIDR annotation. README.md contains the exact 13 built-in rules. Domain rules use case-insensitive exact, dot-boundary suffix and literal substring matching; valid names permit one trailing root dot. There is no port-based eligibility or 5223 fallback. IP rules compare network-order bytes, including partial-byte IPv4 prefixes and the four IPv6 /48 prefixes. IPv4-mapped IPv6 uses the embedded IPv4 address. Literal parsing uses inet_pton without DNS queries; no CNAME traversal, reverse DNS or NAT64 inference is performed.

NECP inspection combines hostname/literal matches with remote-address CIDR matches using OR. Darwin IPv4 address bytes begin at sockaddr offset 4, IPv6 at offset 8. The legacy type-13 field prepends a prefix byte to the 28-byte sockaddr union; type 201 starts with that union. Only validated IPv4/IPv6 layouts supply IP bytes; AF_UNSPEC name endpoints are not treated as addresses. Duplicate nonzero ports retain their consistency guard, but port values never establish eligibility. Conflicting duplicate IP addresses/families preserve the original request, preventing a later field from replacing the address that qualified it. Domains, addresses and ports are never rewritten. Known non-TCP, listener and inbound clients remain native.

Network host endpoints use the same domain/literal matcher; address endpoints use the same binary CIDR matcher. Network observations can miss an IP-only match when only an unmatched hostname is available at that stage, even if a later NECP request supplies the matching IP. No resolver is added to fill missing metadata.

NECP ADD uses a five-byte TLV header. An eligible input is copied, receives BOUND_INTERFACE type 9 with a NUL-terminated utun name, and must fit the 1024-byte kernel parameter limit. Only exact canonical Cellular / Internet type-113 fields become type 123 preferences. All 64 value bytes and every other original byte remain unchanged. The original ADD executes once with its result and errno preserved. Kernel rejection is not retried.

Selection requires exactly one up utun with a usable, non-link-local address and the observed remote family. Records of one interface are combined, and its name/index/family are checked again before submission. The choice is not authenticated as Surge-owned and is not atomic with interface changes.

Existing bound names, interface/agent UUID requirements, prohibited agents/agent types, unrelated required-agent pairs, explicit local endpoints, guarded flags and unsupported layouts remain native. Agent conversion is limited to four nonempty fields, counting an inert 64-byte entry toward capacity. Existing preferred-agent lists are not merged. Noncanonical padding, unterminated/control names, different case, wildcard or mixed requirements block the copy. All-zero agent values stay inert. Valid PARENT_ID is preserved resolver metadata.

Every one-byte PROHIBIT_IF_TYPE value is collected into eight uint32 words. Original TLVs are retained verbatim. Zero is inactive; duplicates and later inert values cannot erase restrictions. Darwin stores four entries and stops matching at zero, while the tweak conservatively checks all nonzero occurrences, including later values. It may decline a bind that Darwin would allow.

InterfaceCheck uses read-only COPY_INTERFACE action 9 through the original NECP descriptor. Its input is a four-byte index, and zero return means success. A zeroed 256-byte buffer covers the declared 100-byte result. The validated prefix is name[24], index, generation, functional type and delegate index. The first name/index must match the selected tunnel, and every returned index/name must be valid. Known nonzero types matching the prohibition set reject the copy; unknown returned types above 7 also reject. Cycles and chains beyond eight interfaces reject. A failure discards all edits and forwards native input.

These contracts follow Apple's [Darwin 20 client implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-7195.141.2/bsd/net/necp_client.c), [parameter declarations](https://github.com/apple-oss-distributions/xnu/blob/xnu-7195.141.2/bsd/net/necp.h), and [functional interface types](https://github.com/apple-oss-distributions/xnu/blob/xnu-7195.141.2/bsd/net/if.h).

## Observations

NECPResults tracks at most 64 client/flow identifiers privately, keyed by descriptor and UUID. ADD_FLOW aliases inherit the diagnostic generation and requested index. Removal forgets corresponding entries; capacity limits observations, not routing. Descriptor reuse without observed removal remains a limitation. Result parsing respects returned lengths, keeps top-level policy/interface separate from nested results, and rejects conflicting or malformed output.

NWObserver uses public iOS 12/13 receive/state APIs and a dynamically resolved public iOS 14.2 path-reason API. Network parameters and connection callback queues are never changed. A synchronous hook may copy/release an endpoint or path while the caller owns the connection. State wrappers capture the original block and scalar connection/handler IDs; receive wrappers capture the original block and a scalar connection ID. The system copies the wrapper and its nested block. Completion arguments, original-call count and errno are preserved; data/context/errors are forwarded as received. `dispatch_data_get_size` reads only aggregate size, including when a completion also contains an error. Retirement receives state/data information after the original application callback returns. NULL completions and unmatched traffic pass through unchanged. No additional start/send/receive is requested. Send completions remain untouched.

Public establishment reports remain send-triggered, with one request in flight and at least five seconds between requests. Their proxy configured/used booleans remain independent of all per-connection records. The thread-local `native_cancel_dispatch` reentry guard retains the existing behavior: enabled matching normal calls use the force-cancel trampoline once, disabled/unmatched/missing-trampoline calls use normal cancellation, and apsd's explicit force calls pass through. Autonomous retirement instead uses the public current-endpoint API under that guard, without a force-cancel fallback. Diagnostic rows themselves own no references.

Connections.c has eight fixed rows under a mutex. Pointer values are identity keys only, never ownership or actions. New creates at a reused address assign a fresh scalar ID. Late callbacks with removed IDs or replaced handler IDs are ignored for diagnostics but still delivered to the app. IDs do not wrap. Empty rows are preferred; the oldest terminal/handler-cleared row may be reused when no empty row remains. Full capacity skips new records and increments a counter. Deallocation is not intercepted, so a row may outlive its object; a ready row is not proof of a live connection. Failed/cleared objects can still have outstanding callbacks; discarding their records cannot affect those callbacks. Concurrent handlers/cancels/receives serialize publication, not the application's original operations. Publication takes Connections -> Diagnostics or Retirement -> Diagnostics; these registry locks are never nested, and Diagnostics calls neither registry nor Network.

Per-row byte and call counters saturate at UINT32_MAX; normal/explicit-force cancellation counts saturate separately at 65535. Content-completion flags are not interpreted as TCP EOF. Last errors are retained across successful callbacks; state-history bits reset on handler replacement/clear. `init` and `courier` labels are diagnostic hostname hints only, never eligibility. All matches continue to use Policy.h. NECP request/result IDs and NW connection/handler IDs are independent namespaces with no claimed cross-layer identity mapping.

## Individual endpoint retirement

Retirement.c creates one public `nw_path_monitor` and a dedicated serial queue only in enabled mode with start/state/cancel/force-cancel trampolines and the current-endpoint API available. NWObserver resolves `nw_connection_cancel_current_endpoint` with its exact public iOS 12 signature; there is no direct import or private fallback. Missing capability leaves routing intact and reports native lifetime. The monitor captures no connections. Only satisfied paths using Wi-Fi XOR cellular identify a network. Unknown/mixed/unsatisfied paths suspend new requests; the first known path establishes generation 1 without action. Network-type changes increment the generation, and a three-second monotonic deadline resets on change or resumption. Monitor latency/order remain limitations.

An eight-slot registry owns references acquired during intercepted matched starts. It records scalar object ID, current handler generation, first-ready network generation and ready/ever-ready/awaiting flags. Repeated starts do not refresh an established object's age. First readiness after a monitor change dates a still-establishing object to the current generation. After establishment it becomes eligible on later transitions regardless of its own path, including cellular spares opened during Wi-Fi. Missing IDs/handlers or capacity skip tracking with a counter.

One delayed callback checks/reschedules to the latest deadline. One coalesced work callback can request earlier cleanup if a fresh ready matched connection receives nonempty, error-free data and its copied path identifies the current network. At most one path query runs at a time; generation, identity and readiness are rechecked afterward. Old data, loopback paths and stale queued work do not trigger early cleanup. This does not pair services or verify an APNs session; the deadline permits a request without a replacement.

Under the mutex, a request batch takes temporary references, stamps the current generation and marks each eligible entry awaiting/not-ready. Entries stay in the registry because native fallback may keep the NW object. Outside the mutex, it records the request, calls `apr_nw_retire`, and releases the temporary reference. That function calls current-endpoint cancellation under the thread-local native-delegation guard. It does not call the full-cancel trampoline, synthesize state/error events or change callback queues. A native owner-requested cancellation, failed/cancelled state or handler clear removes registry ownership. A native READY callback clears awaiting and dates the object to the current generation, rearming later transitions. While awaiting, no additional request is made even if networks change again. An ignored request remains observable rather than triggering a more aggressive fallback.

References remain valid during synchronous callback reentry, natural closure, owner cleanup and replacement creation. The registry owns at most eight references, a batch temporarily up to eight, and one path sample one more. One batch executes on the serial monitor queue. Clock/generation failure releases ownership without teardown; resource/capability failures preserve native lifetime. Concurrent native cancellation can affect the same retained object as a queued request; this is not a live iOS concurrency guarantee. Disabled mode creates no monitor or held objects.

Global/per-row counters now mean endpoint requests, not confirmed transport retirement. A doctor object ID can survive endpoint replacement and cannot be used as a TCP/Surge row identifier. There is no automatic process signal, new create/start/send/receive, socket mutation, CFStream hook, callback fabrication or NECP result overlay. The existing owner-requested normal-to-force cancellation upgrade is unchanged.

The local iPhoneOS14.5 SDK `Network.framework/Headers/connection.h` documents endpoint cancellation as advancing to another endpoint or failing when none remains. It is primarily intended for protocols without reliable handshakes, such as UDP; the user confirmed the established apsd TCP handover on experimental6. The test covers one reported round trip on the stated device, not every protocol or configuration. `nw_connection_restart` only retries waiting connections, so it does not retire an established spare. The exact CFNetwork assertion is unavailable; host fixtures test our ownership and dispatch contracts, not CFNetwork internals. See INVESTIGATION.md for the matched crash UUID and inference boundary.

## Doctor protocol v22

Release 1.2.0 retains protocol 22, prefix and magic (`0x41505246`) and uses build ID `0x01020000`. Experimental2/3 fields and code remain absent. DiagnosticFields.h, ConnectionSchema.h and RetirementStatus.h define names and positions shared by publisher and reader.

| Field group | Count |
| --- | --- |
| Startup/status, two event banks, engine, version and first malformed-input example | 6 |
| Publication sequence | 1 |
| Existing public Network samples and cancellation counters | 12 |
| Eight connection records, 14 scalar fields each | 112 |
| Connection-record skip counter | 1 |
| Retirement status, network/generation, ownership/pending/awaiting, requests/reason/error/skips | 11 |
| Latest NECP request/result/constraint/agent/edit/check scalars, including original flags | 18 |
| First readable agent domain/type words | 16 |
| Complete original interface prohibition words | 8 |
| Total | 185 |

The transport snapshot is 179 fields, including its sequence. Under the diagnostic mutex, the publisher writes an odd sequence, changed fields, then an even sequence only if every pending field was published. Failed or initially unpublished fields remain dirty for the next transaction. If the opening sequence fails, no data is written. This avoids rewriting 178 values on every receive while preserving complete-snapshot recovery after partial failure. The reader requires matching even sequences around all fields and allows three attempts. New requests reset their paired fields; old generations cannot replace them. Diagnostic errors do not alter original network arguments, results, completion forwarding or errno. Retirement and individual rows publish separate coherent transactions, not one atomic global network event.

Two event banks retain 41 flags. Doctor prints retirement status first, eight rows, routing flags, unchanged kernel results and caller cancellation counters. No runtime file/unified logging, proxy injection, probes, payload capture or resolver calls exist. Retirement has the single bounded delayed callback described above; diagnostics add no timers. Notification-state keys include apsd PID/start time. No UUIDs, resolver tags, destination strings or pointers are published; agent metadata remains bounded and sanitized. The independent LiveSockets snapshot may display socket addresses, up to 16 readable TCP sockets on any port, with CIDR annotation. It cannot cover all Network.framework/Nexus flows or supply missing hostnames.
