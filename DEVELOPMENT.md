# Development — 1.1.0 release

Package ID `local.apnsroute`; version `1.1.0`. Rootful Darwin 20 / iOS 14 only. This promotes the approved experimental17 implementation with automatic installer activation and retained doctor diagnostics.

## Build

```sh
BLOCKS_CC=/path/to/linux/iphone/bin/clang sh tests/run.sh
python3 build.py --toolchain /path/to/linux/iphone/bin --sdk /path/to/iPhoneOS14.5.sdk
python3 tests/verify_package.py
```

The host suite uses a C compiler, Python 3 and a Blocks-capable clang. Its LLVM Blocks runtime is a test dependency. The cross-build uses cached clang 13 revision f765bf5b71fd3637a6f6d1d3e6ab95ca91892a0c and the iPhoneOS14.5 SDK. Compiler SHA-256 is 663ade232fdb6e28e16740b89e310de0b85afe9edc2d2e3b7801c8e6e9ed9833. The compiler came from the [swift-toolchain-linux v2.1.0 distribution](https://github.com/kabiroberai/swift-toolchain-linux/releases/tag/v2.1.0). build.py downloads nothing and performs no phone operations.

Both build entrypoints read the same literal source lists in Makefile and select nine C units: Tweak, HookEngine, Diagnostics, NECPHooks, NECPResults, TunnelSelector, InterfaceCheck, NWHooks and NWObserver. The tweak links Network and the system C runtime, with no direct Objective-C or CoreFoundation dependency. Doctor uses Diagnose and LiveSockets. Native Xcode/Theos is an alternative (`make clean package FINALPACKAGE=1`); it was not run here.

Build/package metadata comes from control. build.py and the package verifier check its version against src/Version.h; the compiled doctor uses APR_VERSION. The shell controller delegates its version banner to doctor, and postinst has no hard-coded release text. The cross-builder accepts literal source-list assignments, without evaluating arbitrary Makefile code.

Retired socket, CFStream, SOCKS, proxy mutation, private parameter inspection and associated test files remain absent. The unused apr_necp_record_client wrapper is removed; production and test callers use apr_necp_record_binding directly. InterfaceName.h holds the unchanged decimal-suffix interface-name helper, keeping Policy.h focused on domain/IP rules. Source history is documented in CHANGELOG.md.

## Runtime

The apsd-only constructor checks Darwin 20 and reads the saved mode. `unbind` enables routing; `disabled` and legacy `observe` select native routing. Missing/invalid configuration or an unsupported OS requests no hooks. Postinst enables routing on every `configure` action (fresh install, upgrade, reinstall or explicit reconfiguration) by invoking `/usr/bin/apnsroutectl enable`. The existing controller writes `unbind` atomically before sending one SIGTERM to apsd. Later ordinary apsd starts honor the saved value, including a manual disable.

The shipped mode conffile intentionally retains its legacy `observe\n` bytes and registration. This avoids a dpkg content-change prompt on an already-edited configuration. It is not the final installed default: postinst writes `unbind` after package extraction, then requests the restart. No C constructor fallback or new hook is needed.

If activation fails, postinst reads the resulting mode. Failure to save `unbind` returns a configuration error. If enabled mode is already saved, a failed/unavailable restart leaves the package configured and prints explicit restart/doctor instructions, without retrying or reporting successful loading. Non-configure maintainer-script actions do nothing. This installer behavior is covered by tests/test_activation.py against both layout and the extracted release package.

Both modes request seven hooks: Network create/start/state-handler/send/cancel/force-cancel and NECP client action. The existing jailbreak hook engine is resolved through its compatibility API; its global symbol need not be visible if a library lookup succeeds. Network create always forwards the original endpoint and parameters.

## Matching and routing contract

NECPHooks now names the existing Darwin parameter IDs and address families and expands dense statements. The predicates, wire values, order of mutations, original-call forwarding and errno behavior are retained. A two-architecture optimized LLVM IR comparison against experimental16 passed for NECPHooks, NWHooks, NWObserver, TunnelSelector and InterfaceCheck. See VALIDATION.md.

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

NWObserver uses public APIs. It never changes parameters or a callback queue, initiates a start/send/cancellation, inspects payloads, or retains a connection. State wrappers capture the caller Block and a generation; caller arguments and errno are preserved. Public establishment reports use existing sends, one request in flight, and at least five seconds between requests. Only configured/used proxy booleans are retained. Cancellation paths are read synchronously before forwarding the caller's cancel.

The NECP request/result generation and the NW handler generation are independent. Start, report and cancellation samples are also independent; they are not a connection history. Handler replacement/clearing can make the recorded state historical.

## Doctor protocol v16

The release retains the existing field layout, event numbering, protocol prefix and magic. Version.h supplies the new package/build identifiers; Diagnostics.h defines the shared protocol label. An old loaded dylib remains distinguishable by its build ID until apsd restarts. The release build ID is distinct from the experimental builds.

DiagnosticFields.h defines all field identifiers, names and counts once. Diagnostics, TransportSnapshot and Diagnose use those identifiers instead of duplicated arrays and numeric positions. There are 56 fixed Darwin notification fields keyed by PID/start time and tagged with version magic:

| Field group | Count |
| --- | --- |
| Startup/status, two event banks, engine, version and first malformed-input example | 6 |
| Publication sequence | 1 |
| Public Network create/error, start, handler state/error/ID, report and cancellation path | 8 |
| Latest NECP request, result, constraint/agent/edit/check scalars | 17 |
| First readable agent domain/type words | 16 |
| Complete original interface prohibition words | 8 |

The 50-field transport snapshot consists of one sequence and 49 data fields. Under a mutex, the publisher writes an odd sequence, all data fields, then an even sequence only after every write succeeds. The reader requires matching even sequences and permits three retries. A complete later publication repairs a partial failure. New requests reset paired fields; stale generations cannot replace them. Generation counters do not wrap at exhaustion. Diagnostic failure never changes the network call.

Two event banks hold 41 active event flags. Retired events, capabilities, SOCKS probes, proxy/family readback and wrapper details have no fields or code. Doctor prints 12 routing-relevant flags, full original prohibitions, actual submissions, matched results and public connection state/errors. No UUIDs, resolver tags, destinations, pointers, payloads or history are published. Agent strings are bounded and sanitized. No file/unified logging or active network probes exist.

Doctor labels samples as matched requests/connections, since init and other endpoints now qualify. The latest sample need not be a courier. The independent LiveSockets snapshot no longer filters ports: up to 16 readable TCP sockets are displayed with a CIDR-match annotation. No domain inference is possible from that socket snapshot.
