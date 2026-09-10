# Changelog

## 1.1.0

- Promotes the approved experimental17 source to release, using the APNsRoute package name and a distinct release build ID.
- Automatically saves enabled mode and requests one apsd restart on installation, upgrade, reinstall or package reconfiguration. Manual disable remains available afterward.
- Retains the legacy conffile payload to avoid an upgrade prompt; postinst applies enablement after extraction through the existing controller. Failed settings writes fail configuration, while unavailable restarts with enabled mode saved produce explicit recovery instructions.
- Keeps all 13 domain/CIDR rules, apsd scope, routing guards, seven hooks and doctor protocol v16 with no runtime logging or active probes. Runtime source changes are limited to version/build identity and doctor release wording.
- Adds staged actual-script activation tests, including fresh/upgrade/reinstall, disabled and missing settings, non-configure actions, write/root/restart failures, manual disable and read-only doctor. Full regressions, cross-build and package/signature checks pass.

## 1.1.0~experimental17

- Records the user-confirmed experimental16 result: matched request #15 accepted on utun2/index 19, returned index 19, original exclusions 4/7 retained, one Cellular / Internet conversion and independent handler #4 ready without errors.
- Reformats the NECP implementation and names existing Darwin fields/address families. Keeps routing and all 13 matching rules unchanged.
- Moves interface-name checking out of Policy.h, removes the unused client-registration wrapper and redundant native-hook mask alias, and removes an unused constructor include.
- Shares Makefile source lists with build.py, derives package filenames from control, checks the canonical compiled version header, and removes duplicated/stale installation/doctor text.
- Retains nine active C units, seven hooks, protocol v16 with 56 fields/41 events, doctor-only diagnostics and no logging or active probes.
- Existing regressions, the two-architecture optimized-IR preservation comparison, cross-build and package checks pass. This rebuilt package still needs device confirmation.

## 1.1.0~experimental16

- Records the user confirmation that experimental15 works. Replaces courier-specific matching and the port-5223 fallback with the requested four domain rules, five IPv4 CIDRs and four IPv6 CIDRs. Rules combine with OR, independent of port.
- Shares hostname and binary IP matching across NECP, public Network observations and socket CIDR annotation. Supports case/root-dot normalization, domain boundaries, literal keywords and IPv4-mapped IPv6. No DNS queries or CNAME traversal.
- Reads validated Darwin legacy/modern remote addresses and rejects conflicting duplicate IP metadata. Retains apsd scope, outgoing TCP/protocol guards and the successful tunnel, agent and exclusion mechanism.
- Renames doctor samples as matched connections and removes its 443/5223 socket filter. Protocol v16 retains 56 fields with 41 active events; no logging, proxy injection or active probes.
- Adds independent rule/CIDR boundary and real-hook fixtures, port independence, OR matching, disabled-mode checks and malformed/conflicting endpoint coverage. Host tests, sanitizers, cross-build and package verification pass; this new binary still needs device validation.

## 1.1.0~experimental15

- Records the user's successful cellular courier capture with experimental14. The report preserved AWDL (4) and Companion Link (7), converted Cellular / Internet, and returned the requested utun2 index with a ready courier handler.
- Keeps all eleven routing/matching/result/selection/check source and header files byte-for-byte unchanged.
- Removes 29 obsolete socket, CFStream, SOCKS, proxy, private-inspection and test files. Nine C units remain; direct Objective-C/CoreFoundation dependencies are removed.
- Shares one diagnostic field definition across publisher, reader and doctor. Removes retired fields/events and private proxy/family readback: 56 fields and 42 active events remain.
- Preserves the request/result pair, complete exclusions, agent edit, public state/errors, establishment report and cancellation observation. No logging, probes or extra diagnostic commands.
- Updates the regression suite, actual doctor-output fixture, package import/signature gates and documentation. Host checks pass; the cleanup binary has not yet been tested on the phone.

## 1.1.0~experimental14

- Records experimental13's skipped request and confirmed required agent Cellular / Internet. The remaining type-101 blocker implies another nonzero prohibition after the first reported value 7; its value is not recoverable from the old report.
- Replaces the Companion-only guard with a complete unique set of all one-byte interface prohibitions. Preserves every original exclusion byte and checks the selected utun and its delegates against the set. A real conflict or unavailable/unsupported check discards the entire edited copy.
- Narrows type-113 to type-123 conversion to the exact canonical Cellular / Internet pair. Unrelated, wildcard, case-mismatched or mixed agent requirements remain native. Existing capacity and other constraint guards remain.
- Adds eight protocol-v14 prohibition words, for 66 fixed notification states. Doctor prints all unique original types and observed interface/delegate types with the same request generation. Zero is inactive; the union conservatively checks values beyond Darwin's four-entry limit or zero terminator.
- Extends actual-hook/query tests for combined exclusions, all byte values, exact agent matching, unmodified fallback, publication/reset/partial-write recovery and errno. Keeps eleven active C units, no logging/probes/proxy injection, and doctor-only diagnostics. Device capture remains unconfirmed; no release promotion.

## 1.1.0~experimental13

- Records experimental12's exact blockers: Companion Link exclusion (101=7) and required agent type (113); parent metadata no longer blocks and no tunnel bind was attempted.
- Converts eligible courier required-agent-type fields (113) to preferred-agent-type fields (123) only on the tunnel-bound copy. Retains their value bytes, the Companion Link exclusion, identity, endpoint, parent/resolver data and every unrelated input byte.
- Adds read-only Darwin COPY_INTERFACE queries to verify the chosen utun and delegates do not violate Companion Link exclusion. Missing/changed/unknown interfaces, cycles, depth limits and query errors discard the full copy; the original ADD runs once.
- Preserves other restrictions, existing preferred-type lists, unsupported names/widths and more than four required-type fields. Disabled mode stays native without extra interface queries.
- Adds protocol v13 request-paired edit/query details and the first readable agent domain/type. Fifty-eight fixed notification states; no UUIDs, packet history, logging or network probes.
- Adds direct changed-byte and interface-query regression fixtures, publication/reset/failure coverage and sanitizer checks. Both build entrypoints select eleven C units. Phone capture and notification delivery remain unverified; no release promotion.

## 1.1.0~experimental12

- Records experimental11's enabled result: courier reached ready on cellular, but the guard skipped tunnel binding. No binding was accepted or rejected. The prior report cannot identify which field triggered that skip.
- Corrects the guard that treated every nonempty PARENT_ID as a routing restriction. Valid parent UUID/resolver metadata stay byte-for-byte and no longer prevent an otherwise eligible tunnel request.
- Recognizes zero-length fields and declared-width all-zero interface/agent fields as inert. Nonzero restrictions and unsupported layouts remain native; later empty fields cannot clear an earlier blocker.
- Adds five fixed protocol-v12 fields, paired atomically with the latest NECP request/result: seen, nonzero, inert and unsupported type masks, plus first blocking type/length and interface-type scalar. No UUIDs, agent names, resolver tags or payloads are published.
- Extends direct hook tests for metadata preservation, all guarded types, duplicate fields, native mode and unknown lengths; extends diagnostic transaction/reset/failure tests. Keeps the same ten-unit build and seven hooks, doctor-only diagnostics, no logging/probes/proxy injection and no release promotion.

## 1.1.0~experimental11

- Records the experimental10 control: native courier reaches ready and sends; enabled proxy injection fails before ready with ENETDOWN. The exact internal proxy failure remains unresolved.
- Removes proxy injection, stream/socket routing hooks and active SOCKS probing from the built tweak. Network create forwards the original endpoint and parameter object in both modes.
- Adds courier-only Darwin 20 NECP bound-interface input on a copy, with a unique usable utun, matching-family and recheck guard. Preserves all original bytes; skips explicit restrictions, local bindings, unsupported flags, ambiguous/missing tunnels and inputs that would exceed the 1024-byte kernel limit.
- Adds protocol-v11 paired NECP request/results and generation checks, keeping the separate NW handler pair. Doctor now focuses on the active experiment and distinguishes accepted requests from returned interfaces.
- Both modes install seven hooks; disabled remains a native-routing control. Logging and retired commands remain absent. No release promotion or device capture claim.
- Updates both build entrypoints, active host tests, package checks and documents; prior proxy implementations remain unbuilt reference source.


## 1.1.0~experimental10

- Experimental9 device feedback: required family was already any (0); no family change occurred and courier still failed with ENETDOWN. The cause remains unresolved.
- Disabled mode now requests native routing with seven forwarding Network/NECP observers. No routing setters or SOCKS probes execute in that mode. Four BSD/CFStream hooks remain uninstalled. Enabled routing is unchanged from experimental9.
- Pair the latest handler's parameter inspection with its registration/state/error, and retain bounded ready/waiting/failed/cancelled flags for that handler. Reject delayed updates from older registrations.
- Protocol v10 adds one fixed state (25 slots total). No logs or new diagnostic commands.
- Add actual constructor mode tests, disabled bound-courier forwarding coverage, paired-handler/state publication cases and updated comparison/unload instructions.
- This is a diagnostic revision pending disabled/enabled phone comparison, not a confirmed routing fix.


## 1.1.0~experimental9

- Records experimental8's absent covered constraints, satisfied cellular cancellation-path sample and continuing courier ENETDOWN; preserves the distinction between independent samples.
- Adds a runtime-checked unsigned-char address-family getter/setter. Conditionally changes Darwin AF_INET6 (30) to AF_UNSPEC (0) on the eligible IPv4 local-proxy copy and verifies fresh-wrapper readback. Any, IPv4, unknown values and incompatible APIs remain unchanged.
- Discards the complete proxy copy after missing/unexpected final family readback; retains original endpoint, TLS, identity and other settings.
- Adds paired Proxy IP family details and an independent start-time family value to doctor protocol v9: 24 fixed states, 96 events and eleven hooks. No logging, extra APNs sends or initiated cancellations.
- Adds actual adapter/observer/IPC regression cases and memory checks; updates documentation. Family restriction and cellular capture remain unverified on the phone.

## 1.1.0~experimental8

- Records experimental7's enabled courier ENETDOWN failure before readiness and the user's Wi-Fi/cellular capture difference; does not equate missing capture with a failed disabled native courier.
- Conditionally removes required Wi-Fi/cellular interfaces/types, prohibited cellular/loopback interfaces/types, and prohibit-expensive from the guarded local-proxy copy. Preserves TLS, IP options, local endpoint, constrained-path restrictions and unrelated interface exclusions.
- Verifies exact remaining lists and flags, retaining iterator interface objects until cleanup; rejects incomplete reads or partial/mismatched changes by discarding the whole proxy copy.
- Adds before/after constraint details, POSIX error text and a path snapshot before the caller's cancel/force-cancel. Adds no initiated cancellation, timed polling, connection retention or APNs sends.
- Expands doctor to protocol v8, 23 fixed states, 94 events and eleven hooks. Diagnostics remain doctor-only, without file or unified logging.
- Adds actual-module constraint/ownership/cancellation tests and expanded diagnostic transaction coverage; updates documentation. Device capture and notification delivery remain unverified.

## 1.1.0~experimental7

- Records that experimental6 verified proxy parameter setup on-device but still failed the user capture test. Retains its routing; does not claim a new routing fix.
- Adds public Network create/start observations, wrapped caller state/error callbacks and send-triggered establishment reports with configured/used/proxy-endpoint results.
- Preserves NULL handler removal, cancellation callbacks, original arguments/errno, caller queues and connection lifetimes. Adds no payload inspection, new APNs sends, timers or logging.
- Preserves signed errors across later error-free callbacks for the latest registered handler. Rejects stale handler updates without suppressing the original callbacks.
- Adds coherent protocol-v7 transport snapshots, partial-publication recovery, nine hook flags, and interpretation near the top of doctor. Samples are explicitly not a per-connection trace.
- Adds real C Blocks ownership tests and diagnostic race/partial-write tests; updates install messages and documentation.

## 1.1.0~experimental6

- Fixes the early wrapper-identity rejection observed in experimental5 before any NW proxy setter ran.
- Uses runtime-checked setInternalParameters: to attach the known disposable C copy when the factory returns a different object or no underlying parameters. Repeats attachment for fresh-wrapper verification.
- Checks identity after proxy access and discards unsupported or partially modified proxy copies. Retains the original endpoint, TLS/options, identity, errno and original function result.
- Adds protocol-v6 doctor details for attachment failure, later parameter replacement, distinct/nil factory objects, and whether proxy-bypass flags were examined. Eleven fixed states remain; no logging is added.
- Adds a copying-factory regression that fails before the fix and passes afterward, plus attachment failure, object ownership and settings-preservation checks.
- Actual phone capture and notification delivery still require testing.

## 1.1.0~experimental5

- Responds to the experimental4 device failure: reachable local SOCKS5 listener, unconfirmed CFStream proxy readback, and scoped cellular/Nexus courier results.
- Adds a courier proxy path at nw_connection_create using copied parameters and runtime-checked NWParameters methods. Clears copied noProxy/preferNoProxy flags and verifies configuration through a fresh wrapper before use.
- Discards partial or unsupported proxy copies; retains the original endpoint, TLS/options, identity, return value and errno. Preserves different existing proxies and extra keys in matching dictionaries.
- Adds explicit SOCKSEnable=1 without claiming its earlier absence caused the failure. Reports the precise CFStream readback class.
- Adds protocol-v5 state with three event banks and last CF/NW proxy details near the top of doctor. Logging remains absent and doctor is the sole diagnostic command.
- Adds actual NW wrapper/adapter contract tests for ignored setters, stuck flags, identity/ABI mismatch, copied configuration, failure rollback, ownership and original API behavior.
- Builds for rootful iOS 14 with the existing toolchain. Actual cellular capture and notification delivery still need device testing.

## 1.1.0~experimental4

- Addresses the observed no-binding cellular/Nexus path with explicit courier CFStream SOCKS5 routing to 127.0.0.1:6153.
- Verifies the local no-auth SOCKS5 method before applying the property, with one 150 ms deadline, no proxy CONNECT in the probe, and no APNs payload or credentials.
- Preserves different existing stream proxies, TLS and open contracts. Reports listener, setter, readback, allocation and already-open outcomes through doctor only.
- Adds protocol-v4 state and distinguishes top-level NECP interface/policy results from other interface references.
- Adds actual loopback protocol tests and stream property ownership/failure tests; retains all previous matching and unbinding tests.
- No file or unified logging and no diagnostic command other than doctor.

## 1.1.0~experimental3

- Fixes rejection of Darwin-supported one-byte IP-protocol fields and adds legacy packed remote-address parsing. Separates unspecified IP protocol from the TCP transport field.
- Handles empty TLVs and zero-padded text without changing identity, endpoints, or unrelated policy fields. Invalid/conflicting inputs still pass unchanged.
- Adds bounded, read-only NECP result/flow observations for courier clients, including interface/Nexus/tunnel-policy flags; never rewrites results or issues extra queries.
- Clarifies CFStream service-already-Internet and BSD snapshot limitations. Adds protocol-v3 state and a bounded first-rejection reason/type/length.
- Keeps doctor-only diagnostics and no file/unified logging; adds ABI regression and result-parser tests.

## 1.1.0~experimental2

- Corrects the shared courier hostname matcher to accept `courier*` and `*-courier*` variants beneath `push.apple.com`, including nonnumeric prefixes, text after `courier`, and sandbox labels.
- Keeps strict DNS hostname/domain boundaries, initialization exclusion, case-insensitive matching, and optional trailing-dot support. The port-5223 rule is unchanged.
- Adds regression coverage for variant classification and actual CFStream/NECP routing changes at port 443 or without a port. Confirms TLS-peer matching retains the original peer name.
- Retains doctor as the only diagnostic command, without restoring logging. Updates installation and diagnostic documentation.

## 1.1.0~experimental1

- Addresses gaps exposed by the unsuccessful 1.0.0 cellular test: separate initialization from courier detection, add CFStream service/binding handling and NECP client-creation unbinding.
- Restores doctor as the only diagnostic command, without file or unified logging.
- Adds process-start-aware diagnostic state and optional, read-only live TCP socket inspection.
- Preserves the successful Substitute library lookup fallback, TLS and connection contracts, and existing configuration on upgrade.
- Adds host coverage for the new hooks, failure paths, and doctor state; updates evidence and device-test instructions.

## 1.0.0

Packaged the 0.1.2 routing logic as a release and removed logging and diagnostics. The user subsequently reported initialization visible but cellular courier traffic still absent from Surge.

## 0.1.2

Fixed hook-engine discovery through explicit library handles. The user confirmed loading and all three original hook trampolines; actual cellular unbinding was not established.

## 0.1.1 and 0.1.0

Earlier diagnostic and initial routing prototypes, preserved in the historical experimental checkpoint.
