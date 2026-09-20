#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
test_output="$(mktemp -d)"
trap 'rm -rf "$test_output"' EXIT HUP INT TERM
${CC:-cc} -std=c11 -Wall -Wextra -Werror -O2 tests/test_policy.c -o "$test_output/test_policy"
"$test_output/test_policy"
${CC:-cc} -std=c11 -Wall -Wextra -Werror -O2 -shared -fPIC \
    tests/hook_fixture.c -o "$test_output/hook_fixture.so"
${CC:-cc} -std=c11 -Wall -Wextra -Werror -O2 tests/test_hook_engine.c -ldl \
    -o "$test_output/test_hook_engine"
for scenario in global local unloaded framework missing-symbol all-missing; do
    "$test_output/test_hook_engine" "$test_output/hook_fixture.so" "$scenario"
done

${CC:-cc} -std=c11 -Wall -Wextra -Werror -O2 -Itests/include tests/test_init.c -o "$test_output/test_init"
for mode in disabled observe unbind invalid missing-config wrong-os missing-engine missing-endpoint; do
    "$test_output/test_init" "$mode"
done

${CC:-cc} -std=c11 -Wall -Wextra -Werror -O2 tests/test_necp.c src/NECPResults.c src/InterfaceCheck.c -pthread -o "$test_output/test_necp"
"$test_output/test_necp"
${CC:-cc} -std=c11 -Wall -Wextra -Werror -O2 tests/test_interface_check.c -o "$test_output/test_interface_check"
"$test_output/test_interface_check"
${CC:-cc} -std=c11 -Wall -Wextra -Werror -O2 tests/test_necp_results.c -pthread -o "$test_output/test_necp_results"
"$test_output/test_necp_results"
${CC:-cc} -std=c11 -Wall -Wextra -Werror -O2 -Itests/include tests/test_diagnostics.c src/Diagnostics.c -pthread -o "$test_output/test_diagnostics"
"$test_output/test_diagnostics"
"$test_output/test_diagnostics" denied
${CC:-cc} -std=c11 -Wall -Wextra -Werror -O2 tests/test_connections.c -pthread -o "$test_output/test_connections"
"$test_output/test_connections"
python3 tests/test_doctor_output.py
python3 tests/test_activation.py

${CC:-cc} -std=c11 -Wall -Wextra -Werror -O2 tests/test_tunnel_selector.c -o "$test_output/test_tunnel_selector"
"$test_output/test_tunnel_selector"
${CC:-cc} -std=c11 -Wall -Wextra -Werror -O2 -Itests/include tests/test_nw_hooks.c -o "$test_output/test_nw_hooks"
"$test_output/test_nw_hooks"

# C Blocks are exercised with the real host runtime, including escaped nested
# handlers. The runtime source is a test-only LLVM dependency, not packaged code.
${CC:-cc} -std=c11 -O2 -Itests/vendor/BlocksRuntime -c tests/vendor/BlocksRuntime/runtime.c -o "$test_output/blocks-runtime.o"
${CC:-cc} -std=c11 -O2 -Itests/vendor/BlocksRuntime -c tests/vendor/BlocksRuntime/data.c -o "$test_output/blocks-data.o"
"${BLOCKS_CC:-clang}" -target x86_64-linux-gnu --ld-path=/usr/bin/ld \
    -std=c11 -Wall -Wextra -Werror -O2 -fblocks -Itests/include -Itests/vendor/BlocksRuntime \
    tests/test_nw_observer.c src/Connections.c "$test_output/blocks-runtime.o" "$test_output/blocks-data.o" \
    -pthread -o "$test_output/test_nw_observer"
"$test_output/test_nw_observer"
"${BLOCKS_CC:-clang}" -target x86_64-linux-gnu --ld-path=/usr/bin/ld \
    -std=c11 -Wall -Wextra -Werror -O2 -fblocks -Itests/include -Itests/vendor/BlocksRuntime \
    tests/test_retirement.c "$test_output/blocks-runtime.o" "$test_output/blocks-data.o" \
    -pthread -o "$test_output/test_retirement"
for scenario in main vpn unknown recovery opening preflight vpn-notify-failure vpn-baseline lifetimes clock-failure physical-overflow vpn-overflow quiet-overflow disabled missing queue-failure monitor-failure; do
    "$test_output/test_retirement" "$scenario"
done
