#ifndef APNSROUTE_HOOK_ENGINE_H
#define APNSROUTE_HOOK_ENGINE_H

typedef void (*APRHookFunction)(void *, void *, void **);
enum apr_hook_source {
    APR_HOOK_GLOBAL = 0,
    APR_HOOK_SUBSTRATE,
    APR_HOOK_FRAMEWORK,
    APR_HOOK_SUBSTITUTE,
    APR_HOOK_SUBSTITUTE_ZERO,
    APR_HOOK_SOURCE_COUNT
};
enum apr_lookup_result {
    APR_LOOKUP_NOT_TRIED = 0,
    APR_LOOKUP_OPEN_FAILED,
    APR_LOOKUP_SYMBOL_MISSING,
    APR_LOOKUP_FOUND
};

static inline const char *apr_hook_source_name(unsigned source) {
    switch (source) {
        case APR_HOOK_GLOBAL: return "RTLD_DEFAULT";
        case APR_HOOK_SUBSTRATE: return "/usr/lib/libsubstrate.dylib";
        case APR_HOOK_FRAMEWORK: return "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate";
        case APR_HOOK_SUBSTITUTE: return "/usr/lib/libsubstitute.dylib";
        case APR_HOOK_SUBSTITUTE_ZERO: return "/usr/lib/libsubstitute.0.dylib";
        default: return "unknown";
    }
}

/* Resolve the existing jailbreak's compatibility API. Does not install hooks,
   replace the hook engine, or change process-wide symbol visibility. */
APRHookFunction apr_find_hook_engine(void);
#endif
