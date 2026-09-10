/* Exercise the real resolver with actual RTLD_LOCAL / RTLD_GLOBAL libraries.
   Only the filesystem paths are redirected to a tiny test fixture. */
#include "../src/HookEngine.h"
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static const char *fixture, *scenario;
static unsigned opens, closes, results[APR_HOOK_SOURCE_COUNT];

void apr_diag_engine(unsigned source, unsigned result) {
    assert(source < APR_HOOK_SOURCE_COUNT);
    results[source] = result;
    errno = EIO;
}

static void *test_dlopen(const char *path, int flags) {
    ++opens;
    assert(flags == (RTLD_NOW | RTLD_LOCAL));
    unsigned source = 0;
    for (unsigned i = 1; i < APR_HOOK_SOURCE_COUNT; ++i)
        if (!strcmp(path, apr_hook_source_name(i))) source = i;
    assert(source);
    errno = EIO;
    if (!strcmp(scenario, "all-missing")) return NULL;
    if (!strcmp(scenario, "framework") && source == APR_HOOK_SUBSTRATE) return NULL;
    if (!strcmp(scenario, "missing-symbol") && source == APR_HOOK_SUBSTRATE)
        return dlopen("libc.so.6", flags);
    return dlopen(fixture, flags);
}

static int test_dlclose(void *handle) {
    ++closes;
    return dlclose(handle);
}

#define dlopen test_dlopen
#define dlclose test_dlclose
#include "../src/HookEngine.c"
#undef dlopen
#undef dlclose

int main(int argc, char **argv) {
    assert(argc == 3);
    fixture = argv[1];
    scenario = argv[2];
    if (!strcmp(scenario, "global")) assert(dlopen(fixture, RTLD_NOW | RTLD_GLOBAL));
    if (!strcmp(scenario, "local")) assert(dlopen(fixture, RTLD_NOW | RTLD_LOCAL));
    if (strcmp(scenario, "global")) assert(!dlsym(RTLD_DEFAULT, "MSHookFunction"));
    errno = EDOM;
    APRHookFunction function = apr_find_hook_engine();
    assert(errno == EDOM);
    if (!strcmp(scenario, "all-missing")) {
        assert(!function && opens == APR_HOOK_SOURCE_COUNT - 1 && closes == 0);
        assert(results[APR_HOOK_GLOBAL] == APR_LOOKUP_SYMBOL_MISSING);
        for (unsigned i = 1; i < APR_HOOK_SOURCE_COUNT; ++i)
            assert(results[i] == APR_LOOKUP_OPEN_FAILED);
    } else {
        assert(function);
        unsigned found = !strcmp(scenario, "global") ? APR_HOOK_GLOBAL :
            (!strcmp(scenario, "framework") || !strcmp(scenario, "missing-symbol")) ?
            APR_HOOK_FRAMEWORK : APR_HOOK_SUBSTRATE;
        assert(results[found] == APR_LOOKUP_FOUND);
        assert(opens == found);
        assert(closes == (!strcmp(scenario, "missing-symbol") ? 1u : 0u));
        if (!strcmp(scenario, "missing-symbol"))
            assert(results[APR_HOOK_SUBSTRATE] == APR_LOOKUP_SYMBOL_MISSING);
        if (!strcmp(scenario, "framework"))
            assert(results[APR_HOOK_SUBSTRATE] == APR_LOOKUP_OPEN_FAILED);
        if (strcmp(scenario, "global")) assert(!dlsym(RTLD_DEFAULT, "MSHookFunction"));
        int target = 42;
        void *original = NULL;
        function(&target, NULL, &original);
        assert(original == &target); /* Resolved pointer calls the correct export. */
        unsigned previous_opens = opens;
        errno = EDOM;
        assert(apr_find_hook_engine() == function && errno == EDOM && opens == previous_opens);
    }
    printf("PASS: hook engine discovery: %s\n", scenario);
}
