# Investigation — routing and handover cleanup

## 1.2.0 release confirmation

Experimental6's subsequent three snapshots retain apsd PID 10284 while the monitor advances cellular generation 1 → Wi-Fi generation 2 → cellular generation 3. The initial courier #2 becomes failed/cancelled after one current-endpoint request; Wi-Fi courier #5 is ready. On return, #5 is cancelled through the owner's path and fresh cellular courier #10 is ready. Total endpoint requests stay at one, awaiting/pending counts are zero and no tracking skips are recorded. The user reports that the sequence works without the earlier crash.

Wi-Fi created another init and several failed secondary attempts (POSIX 50), so success does not mean all init traffic or unsuccessful attempts disappeared. No process restart is indicated in this sequence. These records and the user's observation support promoting the tested endpoint behavior, while not proving the exact assertion that caused experimental5 to abort or long-term behavior on other setups.

Release 1.2.0 makes lifecycle naming/reference-transfer cleanup and updates build identity. Timing, rules, callback order, cancellation APIs, bounds and NECP bytes are preserved. VALIDATION.md separates the device evidence from host/source/build verification. The sections below record the earlier investigation chronologically, including uncertainties as understood at that time.

## 1.1.1 experimental6: reproduced abort and lifecycle revision

The user clarified that apsd was restarted only before the first cellular reading. The experimental5 readings therefore cannot be treated as one successful handover: PID 9314 on the first cellular sample becomes PID 9711 on Wi-Fi, and the monitor returns to generation 1 with zero retirement calls. A later cellular sample keeps PID 9711 and advances to generation 2, still with zero requests. Those counters do not reconstruct the terminated process's final action.

The separate reproduced crash report supplies direct evidence:

| Evidence | Value |
| --- | --- |
| Process / device | apsd PID 9902; iPhone12,8; iOS 14.8 (18H17) |
| Launch to crash | About 80.8 seconds |
| Exception | EXC_CRASH (SIGABRT) |
| Crashed thread | 5, queue `com.apple.CFNetwork.Connection` |
| Highest framework frame | CFNetwork image offset 0xb0474, below libc abort frames |
| Loaded APNsRoute UUID | `00d6c619-2f86-32ae-932a-0423b05d4d85` |
| Matching delivered slice | Exact LC_UUID match for experimental5 arm64e |
| Missing evidence | Assertion text and symbolicated private CFNetwork function; no APNsRoute frame on the crashing stack |

This establishes an abort, not an ordinary handover restart. The module contains no automatic process signal. The asynchronous stack does not prove which earlier operation triggered CFNetwork's abort. The new unsolicited full NW force-cancel introduced in experimental5 is the leading suspect: the higher-level CFNetwork owner may not permit a terminal cancelled state before it has initiated its own teardown. This is a lifecycle hypothesis, not a known assertion string or a proven use-after-free.

Experimental6 changes that operation to public `nw_connection_cancel_current_endpoint`. The local iPhoneOS14.5 SDK contract describes trying another endpoint or failing if none remains. It is primarily useful for protocols without reliable handshakes, such as UDP; established TCP behavior still needs verification. The original CFNetwork callbacks are forwarded unchanged, without synthetic failure/EOF, private stream hooks, queue replacement, assertion bypass or NECP result masking. A missing API leaves automatic retirement unavailable; there is no terminal-cancel fallback.

A bounded entry remains owned and awaiting until a native ready/terminal event or owner cleanup is observed. It cannot receive another retirement request while awaiting, even through additional network changes. Native READY rearms the same NW object for a later handover; an unchanged scalar object ID is not a TCP-connection identity. If the API does not produce a usable TCP outcome, doctor exposes that pending native response instead of escalating. Existing owner-requested normal cancellations retain experimental1's force-cancel dispatch.

Validation must keep the same apsd PID through cellular → Wi-Fi → cellular, confirm old TCP/Surge entries close and fresh transports deliver notifications, and check request/awaiting counters. Host tests exercise dispatch, references and callback forwarding; they cannot reproduce the private CFNetwork assertion or establish its resolution. Experimental5 is withdrawn as a working fix. Experimental4 and experimental1 installers are retained unchanged as rollback options, with their known retained-connection behavior.

## 1.1.1 experimental5: historical attempt, withdrawn after abort

The experimental4 samples share apsd PID 9008 and show the following observations. These are local NW record IDs, not verified Surge row IDs or NECP client IDs.

| Stage | Cellular courier #2 | Wi-Fi courier #4 |
| --- | --- | --- |
| Cellular before | Ready; receive callbacks=2, bytes=38; no cancel | Not yet observed |
| Wi-Fi | Same last ready/read values; no cancel | Ready; receive callbacks=2, bytes=38; no cancel |
| Cellular after | Same last ready/read values; no cancel | Cancelled; receive callbacks=4, bytes=38; one normal cancel; receive error=89 (ECANCELED on iOS 14) |

The user then confirmed notification arrival, while explicitly rejecting reuse of previous connections. This supports a lifetime-policy change rather than treating every open row as a failed network flow. The snapshots do not themselves prove which connection carried the later notification.

Experimental5 keeps experimental4's routing/NECP behavior and initiates cancellation of older established, rule-matched NW objects after observed Wi-Fi/cellular transitions. The first monitor observation establishes a baseline. Later transitions use a three-second window, allowing earlier cancellation if a fresh matched connection receives data on the new network. Tracking generation follows first readiness and observed monitor callbacks; it is not a service-specific replacement map. Native callback delivery and object lifetime are retained, and apsd is never restarted by this module. Unknown paths, missing handlers and tracking limits are exposed by doctor.

The local iPhoneOS14.5 SDK documents that `nw_connection_restart` retries a waiting connection and ignores a ready connection, while `nw_connection_force_cancel` terminates a connection without graceful negotiation. That motivated the historical experiment but did not establish whether CFNetwork accepts an unsolicited terminal cancellation. The later abort invalidates treating that experiment as a successful handover fix. Host tests can validate references, callback forwarding and scheduling, but only the phone can establish Surge closure and notification recovery. A short reconnect delay and ordinary apsd init requests remain possible. No release promotion is made.

Experimental2's automatic apsd restart stays removed. Experimental3's caller-visible NECP viability masking also stays removed: it failed to close the original clients and was followed by failed recovery in the user's earlier test. The unchanged experimental4 and experimental1 installers are retained as rollback options.

## 1.1.1 experimental1: open entries after Wi-Fi handover

The new report says connections captured on cellular remain marked open in Surge after switching to Wi-Fi. No doctor snapshot or packet trace for that transition accompanied this report. It does not establish whether those connections remain active in apsd, are stuck negotiating teardown, or are retained in Surge's connection display/upstream state.

Source inspection confirms release 1.1.0 only observes the public cancellation path; it always calls the original normal-cancel trampoline. The local iPhoneOS14.5 SDK Network/connection.h declarations distinguish negotiated asynchronous `nw_connection_cancel` from `nw_connection_force_cancel`, which requests immediate non-graceful teardown (TCP RST). Both are public iOS 12 APIs. Reference: [Apple force-cancel API](https://developer.apple.com/documentation/network/nw_connection_force_cancel(_:)). This API distinction supports a teardown hypothesis, not a confirmed root cause for the user's session.

The smallest testable change is to upgrade a cancellation that apsd already requests for a matching connection. This avoids taking over apsd's decision about when a healthy connection should reconnect. Protocol v17 records normal calls, substituted dispatches and apsd force calls so paired doctor readings can establish whether the hook is reached during the transition. Without observed cancellation, a separate investigation of the preserved utun path and apsd's lifecycle decision is needed; this build deliberately does not guess that an open entry is stale.

The existing NECP binding and exact Cellular/Internet preference change are not modified. The working release is retained as the baseline, and the new package is experimental pending device validation.


## 1.1.0 release promotion

The user approved moving the cleaned revision to release, retaining diagnostics and enabling it automatically. Release 1.1.0 keeps the approved experimental17 runtime source, apart from version/build identification and the doctor release label. Installation now enables the saved mode and requests one apsd restart through the existing controller. This applies even when a prior installation was disabled. Doctor and protocol v16 are retained; no logging or probes are introduced.

Activation was verified with staged copies of the actual installer/controller and mocked process control; no phone processes were contacted. Existing routing regressions and package/signature checks were retained. The historical sections below document the path to the approved implementation.

## Experimental16 confirmation and experimental17 cleanup

The user reported that experimental16 works and supplied a doctor snapshot for apsd PID 5883. The latest matched NECP request was #15: a tunnel-bound ADD accepted with original prohibitions 4 (AWDL) and 7 (Companion Link) retained. One exact Cellular / Internet required-agent field became a preference. Two interface checks observed functional types 0 and 5. The requested and returned interface was index 19, displayed as utun2, with returned policy 12.

The independent latest Network handler #4 was ready with no error. Its public establishment report had proxy configured/used set to yes. A separate pre-cancellation path sample used cellular, with Wi-Fi false. These samples are independent and need not identify the same connection. The user's report supplies the practical success confirmation.

Experimental17 is a maintenance cleanup of that working implementation. It improves NECP readability and build metadata, removes unused helpers, and retains protocol v16. Optimized IR comparisons on both supported architectures confirm unchanged matching, routing, tunnel-selection/exclusion and Network-observer code. The rebuilt package has not yet been run on the phone.

## Experimental16 matching revision (historical)

The user confirmed experimental15 works, then requested the exact domain/CIDR rules listed in README.md. Experimental16 replaces the courier/port predicate with that shared matcher. The routing edits, selection checks and exclusion checks are retained. Known non-TCP/listener/inbound guards remain. Doctor now describes matched connections, which may include init or other endpoints. Device confirmation was supplied later, as recorded above.

The sections and source fingerprints below document the earlier experimental14/15 preservation comparison; they are historical, not fingerprints for experimental16.

## Experimental14 device evidence

The user reported that cellular courier was finally captured in Surge. The supplied doctor output identified experimental14, apsd PID 2731, with enabled routing and all seven hooks present.

| Evidence | Observed value |
| --- | --- |
| Latest courier NECP request | #3, edited ADD accepted |
| Original interface prohibitions | 4 (Wi-Fi AWDL), 7 (Companion Link) |
| Required agent | Cellular / Internet |
| Converted agent fields | One REQUIRE -> PREFER field supplied; accepted |
| Exclusion check | Passed; two interfaces queried; functional types 0 and 5 |
| Requested interface | Index 19, displayed as utun2 |
| Returned interface | Index 19, displayed as utun2; matches request |
| Returned policy | 12 |
| Independent NW handler | #1 reached ready, no error observed |
| Public establishment report | Proxy configured=yes, proxy used=yes |

The successful report confirms the previously hidden additional prohibition was AWDL (4). Experimental13 permitted only Companion Link (7) and stopped at its guard. Experimental14 checks every original prohibition against the candidate and delegates while retaining the original bytes; the observed utun/cellular delegate chain satisfied both exclusions.

The accepted copied request also converted the exact Cellular / Internet agent requirement to a preference and appended the utun binding. The user confirmed capture after this combined intervention. The observations do not isolate which edit was independently necessary. The public establishment report is independent of the NECP sample and does not identify a proxy implementation by itself.

## Experimental15 cleanup boundary

Eleven files were compared byte-for-byte with the successful source: NECPHooks.c/h, NECPResults.c/h, TunnelSelector.c/h, InterfaceCheck.c/h, Policy.h, ConstraintStatus.h and BindingStatus.h. They are unchanged. Existing constraint handling, complete exclusion checks, one original ADD call, original input immutability and errno forwarding remain covered by the regression suite.

The cleanup removes retired socket/CFStream/SOCKS/proxy experiments, private parameter wrappers and their test infrastructure. It preserves the seven public hooks and their caller-owned callback/start/send/cancellation behavior. The public state/error and establishment reports remain; obsolete proxy readback, family and hard-coded loopback endpoint diagnostics are removed.

Doctor now uses one versioned field definition for its producer, reader and formatter. The schema has 56 fields and two event banks. It retains the atomic request/result/agent/exclusion snapshot and rejects stale generations or partial publication. No logging or active probes were introduced.

## Primary contracts

The routing contracts remain those reviewed in Apple's xnu-7195.141.2 sources:

| Source | Relevant contract |
| --- | --- |
| [if.h](https://github.com/apple-oss-distributions/xnu/blob/xnu-7195.141.2/bsd/net/if.h) | Functional types 0–7; AWDL=4, cellular=5, Companion Link=7. |
| [necp.h](https://github.com/apple-oss-distributions/xnu/blob/xnu-7195.141.2/bsd/net/necp.h) | Required/preferred agent type IDs 113/123 and the interface-details layout. |
| [necp_client.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-7195.141.2/bsd/net/necp_client.c) | TLV parsing, matching, delegation, explicit binding and COPY_INTERFACE ABI. |
| [necp.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-7195.141.2/bsd/net/necp.c) | Policy evaluation can supersede an interface request. |

Retained source fingerprints:

```text
d22700957a7fb8fcf474ab6de5875cef889c2398a67ce66bbf7495f1a94df2c3  if.h
c98ea8d907ff5f5e4d677224e0fed116d25dbc5f7feafe03db7612bddbf426e0  necp.h
12eac9e3e52c69959cc59ac5ef3b7e48c4adcdfdc6185ff8275fdc622b773c3a  necp_client.c
d255ea32ae681c1519d183011ef54678d5d571d5179a296a5d66c63d39090f71  necp.c
```

The COPY_INTERFACE implementation uses a four-byte index despite a UUID comment in the header. Success returns zero, and removed interfaces can produce empty output. The retained checker validates the prefix before treating a result as usable.

## What is and is not validated

Cellular capture was reported on the user's experimental14 setup. The cleanup passes host regression, diagnostic-format, sanitizer and package/signature checks. It has not been run on the phone. Long-term push delivery, reconnect behavior, other iOS versions and other VPN configurations were not established by the single successful report. Older experiments remain documented in CHANGELOG.md; their code is no longer distributed in this source tree.
