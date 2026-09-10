# Validation — 1.1.0 release

The release promotes the approved experimental17 source and adds automatic installation activation. Existing device evidence and the earlier cleanup comparison are recorded in INVESTIGATION.md. The new release installer was exercised locally in a staged environment; no remote phone installation was performed.

## Runtime preservation

Thirty-one source/header/vendor files were compared byte-for-byte with experimental17 and are unchanged. The remaining source changes are the package/build identifiers in Version.h and removal of the word experimental from doctor's enabled-mode description. APNsRoute.plist and Makefile are unchanged.

All 13 domain/IP rules, outgoing apsd scope, endpoint/constraint handling, exact Cellular / Internet conversion, complete interface exclusions, tunnel selection, result tracking and public Network observers remain. The seven hooks and doctor protocol v16 retain their field layout, event numbers, magic and prefix. The release build ID is distinct from prior packages.

## Automatic activation

The actual postinst and apnsroutectl scripts were exercised with only their fixed install paths mapped into a temporary directory. Process control was replaced by a recorder that accepts only `killall -TERM apsd`; no host or phone daemon was signaled. Standard setting-file operations ran against the staged files.

The cases cover:

- Fresh installation and missing configuration, enabled/disabled experimental upgrades, invalid legacy settings, release reinstall and repeated configure invocations.
- Saving `unbind` with mode 0644 before one restart request, without temporary-file leftovers.
- Non-configure maintainer-script actions leaving settings/process state untouched.
- Failed/unavailable restart retaining enabled mode, returning an otherwise configured package and printing recovery instructions without retrying.
- Failed writes and non-root attempts preserving a disabled setting, returning a configuration error and sending no TERM.
- Manual disable after activation, status and doctor remaining read-only, and rejected logs/observe commands.

The same test runs against the scripts extracted from the final .deb, verifying the packaged activation behavior. The packaged conffile bytes remain identical to experimental17 to avoid a content-change prompt; postinst applies enablement after extraction. The package version comparison confirms that 1.1.0 upgrades 1.1.0~experimental17.

## Regression suite

The complete existing host suite passed. Independent rule fixtures cover all domains/CIDRs, boundary addresses, name lengths, mapped IPv4, arbitrary ports and unmatched port-5223 traffic. Actual NECP tests cover OR matching, missing metadata, native mode, protocol/listener/inbound guards, malformed/conflicting endpoints and exact copied-byte edits.

Existing cases retain coverage for original input/errno, one original ADD, agent/parent/resolver semantics, complete exclusions, denied/unknown/changed interfaces, delegate cycles, capacity, allocation failure and kernel rejection. Tunnel/result tests cover family, ambiguity, disappearance, nested results, aliases and generations.

Constructor modes and actual hook-engine lookup pass. Diagnostic publisher/reader fixtures cover shared names, both event banks, paired data, stale generations, failed publication and recovery. Public Network/Blocks fixtures verify caller-owned argument/callback behavior, report gating and cancellation observation. The actual doctor formatter still renders routing and connection-state diagnostics without retired logging/proxy output.

No new routing algorithm was introduced, so prior sanitizer evidence was not represented as a new sanitizer run. Runtime source preservation and the complete regression suite are the release gates for existing behavior.

## Build and package checks

The cached clang 13 / iPhoneOS14.5 SDK build produced arm64 and arm64e tweak slices and an arm64 doctor. Binaries are ad-hoc signed, without added doctor entitlements. Nine known legacy arm64e ABI linker warnings remain from the same working toolchain; other warnings and Objective-C/CFString metadata are rejected.

Package checks passed for release name/version, source version agreement, apsd-only filtering, conffile registration, executable permissions, shell syntax, automatic activation and every signature page hash. Import/string checks retain doctor observation APIs and reject runtime logging, DNS lookups, port classification, private parameter inspection, proxy injection, active probes and initiated connection cancellation.

The source archive includes the installer, BUILD-REPORT.txt and SHA256SUMS.txt. ZIP CRC, every manifest hash and the archived installer/README match are checked before saving. User-provided logs, caches and staged test data are excluded.

## Limits

Staged scripts verify activation decisions and command order, not iOS launchd, hook injection or live notification delivery. The user should inspect doctor after installation. Existing tunnel-ownership, interface-race and independent-sample limitations remain unchanged. Doctor itself does not enable routing or restart apsd, and it produces no file or unified logs.
