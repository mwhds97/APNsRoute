#ifndef APNSROUTE_INTERFACE_NAME_H
#define APNSROUTE_INTERFACE_NAME_H
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Interface names must end in one or more decimal digits. */
static inline bool apr_index_name(const char *name, const char *prefix) {
    if (!name || !prefix) return false;
    size_t n = strlen(prefix);
    if (strncmp(name, prefix, n) || !name[n]) return false;
    for (const char *p = name + n; *p; ++p)
        if (*p < '0' || *p > '9') return false;
    return true;
}
#endif
