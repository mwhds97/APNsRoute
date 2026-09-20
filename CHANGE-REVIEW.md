# Change review — 1.2.1

Baseline: the delivered 1.2.1~experimental2 archive, SHA-256 `ec266994b8099704ced67a0e02bb4d89de6dce5ba5abf38c52acfedd09a6951b`. The user approved release after six phone snapshots showed the expected grouping/recovery behavior.

## Runtime cleanup

- Version.h changes package identity to `1.2.1` and build ID to `0x01020100`.
- RetirementStatus.h defines the existing 2,000 ms quiet duration once.
- Retirement.c derives its nanosecond deadline and diagnostic remaining-time initialization from that constant.
- Diagnose.c displays the same constant. Output remains `minimum=2000 ms`.

No state-machine, event source, timing value, eligibility, reference ownership, cancellation API, callback order, matching or routing change is introduced. Protocol v24 and its field layout remain unchanged. All eleven tweak units match optimized LLVM IR on both architectures after baseline version/build identity normalization; see PRESERVATION.txt. Doctor formatting is covered by its output fixture.

## Packaging and documentation

The package is named APNsRoute and sorts above 1.2.0 and the two 1.2.1 prereleases. Package checks require release identity; activation tests add those upgrade paths and a 1.2.1 reinstall. Existing filter, configuration, controller and installation/removal scripts are byte-identical. Installation still enables the tweak and requests one reload; network/VPN changes do not restart apsd.

README, developer notes, changelog, investigation and validation now describe the release and actual phone evidence. The package's generated build report records the rebuilt binaries. The archive carries only the current installer plus unchanged 1.2.0 and tested experimental2 rollback packages; no build cache or raw phone logs are distributed.

## Source preservation

Changed source files:

- `src/Diagnose.c`
- `src/Retirement.c`
- `src/RetirementStatus.h`
- `src/Version.h`

The remaining 35 source/vendor files are byte-identical:

- `src/BindingStatus.h`
- `src/ConnectionSchema.h`
- `src/ConnectionStatus.h`
- `src/Connections.c`
- `src/Connections.h`
- `src/ConstraintStatus.h`
- `src/DiagnosticFields.h`
- `src/Diagnostics.c`
- `src/Diagnostics.h`
- `src/HookEngine.c`
- `src/HookEngine.h`
- `src/InterfaceCheck.c`
- `src/InterfaceCheck.h`
- `src/InterfaceName.h`
- `src/LiveSockets.c`
- `src/LiveSockets.h`
- `src/NECPHooks.c`
- `src/NECPHooks.h`
- `src/NECPResults.c`
- `src/NECPResults.h`
- `src/NWHooks.c`
- `src/NWHooks.h`
- `src/NWObserver.c`
- `src/NWObserver.h`
- `src/Policy.h`
- `src/Process.h`
- `src/Retirement.h`
- `src/TransportSnapshot.h`
- `src/TunnelSelector.c`
- `src/TunnelSelector.h`
- `src/Tweak.c`
- `src/vendor/APSL-2.0.txt`
- `src/vendor/proc_info.h`
- `src/vendor/sys/kern_control.h`
- `src/vendor/sys/kern_event.h`

Host regressions, all 17 lifecycle sanitizer cases plus the NW observer, cross-build, package signatures and compiled-runtime comparisons pass. Existing phone evidence applies to experimental2; the rebuilt release has not yet run on the phone. See VALIDATION.md for detailed scope.
