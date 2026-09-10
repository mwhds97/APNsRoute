# Investigation — successful routing, cleanup and rule matching

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
