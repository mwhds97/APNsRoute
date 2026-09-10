# Host test dependency

Unmodified BlocksRuntime sources from LLVM compiler-rt, tag `llvmorg-13.0.0`:
https://github.com/llvm/llvm-project/tree/llvmorg-13.0.0/compiler-rt/lib/BlocksRuntime

`config.h` is the local Linux configuration using compiler atomic builtins.
The included license and source copyright notices apply. This runtime is linked
only into the host test. The iOS package uses Apple's system Blocks runtime.
