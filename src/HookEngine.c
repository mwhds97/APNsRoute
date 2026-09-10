#include "HookEngine.h"
#include "Diagnostics.h"
#include <dlfcn.h>
#include <errno.h>

static APRHookFunction apr_hook_function;
static void *apr_hook_library;

APRHookFunction apr_find_hook_engine(void) {
    int saved = errno;
    if (apr_hook_function) return apr_hook_function;
    apr_hook_function = (APRHookFunction)dlsym(RTLD_DEFAULT, "MSHookFunction");
    apr_diag_engine(APR_HOOK_GLOBAL, apr_hook_function ? APR_LOOKUP_FOUND : APR_LOOKUP_SYMBOL_MISSING);
    if (!apr_hook_function) {
        for (unsigned source = APR_HOOK_SUBSTRATE; source < APR_HOOK_SOURCE_COUNT; ++source) {
            /* A global-only lookup misses an unloaded shim, or one opened
               locally by the injector. Resolve directly on the returned handle.
               Do not use RTLD_GLOBAL or change any system library on disk. */
            void *library = dlopen(apr_hook_source_name(source), RTLD_NOW | RTLD_LOCAL);
            if (!library) {
                apr_diag_engine(source, APR_LOOKUP_OPEN_FAILED);
                continue;
            }
            APRHookFunction function = (APRHookFunction)dlsym(library, "MSHookFunction");
            apr_diag_engine(source, function ? APR_LOOKUP_FOUND : APR_LOOKUP_SYMBOL_MISSING);
            if (function) {
                /* Retain this handle for the process lifetime. The hook engine
                   and its trampolines must remain mapped after startup. */
                apr_hook_library = library;
                apr_hook_function = function;
                break;
            }
            dlclose(library);
        }
    }
    errno = saved;
    return apr_hook_function;
}
