#ifndef APNSROUTE_POLICY_H
#define APNSROUTE_POLICY_H
#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

/* The supplied rules are alternatives, independent of destination port.
   Match available endpoint metadata only: no DNS queries or CNAME traversal. */
static inline size_t apr_host_length(const char *host) {
    if (!host) return 0;
    size_t n = 0;
    while (n <= 254 && host[n]) ++n;
    if (n && host[n - 1] == '.') --n;
    if (!n || n > 253) return 0;
    size_t start = 0;
    for (size_t i = 0; i <= n; ++i) {
        if (i == n || host[i] == '.') {
            size_t length = i - start;
            if (!length || length > 63 || host[start] == '-' || host[i - 1] == '-')
                return 0;
            start = i + 1;
        } else {
            unsigned char c = (unsigned char)host[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-')) return 0;
        }
    }
    return n;
}

static inline bool apr_domain_target(const char *host) {
    size_t n = apr_host_length(host);
    if (!n) return false;
    const char exact[] = "identity.apple.com";
    if (n == sizeof(exact) - 1 && !strncasecmp(host, exact, n)) return true;
    const char *suffixes[] = {"push.apple.com", "akadns.net"};
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(*suffixes); ++i) {
        size_t s = strlen(suffixes[i]);
        if (n >= s && !strncasecmp(host + n - s, suffixes[i], s) &&
            (n == s || host[n - s - 1] == '.')) return true;
    }
    /* DOMAIN-KEYWORD means literal substring, not a suffix/label boundary. */
    const char keyword[] = "apple.com.edgekey.net";
    size_t k = sizeof(keyword) - 1;
    for (size_t i = 0; i + k <= n; ++i)
        if (!strncasecmp(host + i, keyword, k)) return true;
    return false;
}

/* Addresses are network-order bytes; no unaligned integer loads or
   host-endian masks. Every table prefix has zero host bits. */
static inline bool apr_prefix_match(const uint8_t *address,
                                    const uint8_t *network, unsigned bits) {
    unsigned bytes = bits / 8, remainder = bits % 8;
    if (memcmp(address, network, bytes)) return false;
    return !remainder || !((address[bytes] ^ network[bytes]) & (0xffU << (8 - remainder)));
}

static inline bool apr_ipv4_target(const void *address) {
    static const struct { uint8_t network[4]; unsigned bits; } rules[] = {
        {{17, 249, 0, 0}, 16},
        {{17, 252, 0, 0}, 16},
        {{17, 57, 144, 0}, 22},
        {{17, 188, 128, 0}, 18},
        {{17, 188, 20, 0}, 23}
    };
    if (!address) return false;
    for (size_t i = 0; i < sizeof(rules) / sizeof(*rules); ++i)
        if (apr_prefix_match(address, rules[i].network, rules[i].bits)) return true;
    return false;
}

static inline bool apr_ipv6_target(const void *address) {
    static const uint8_t prefixes[][6] = {
        {0x26, 0x20, 0x01, 0x49, 0x0a, 0x44}, /* 2620:149:a44::/48 */
        {0x24, 0x03, 0x03, 0x00, 0x0a, 0x42}, /* 2403:300:a42::/48 */
        {0x24, 0x03, 0x03, 0x00, 0x0a, 0x51}, /* 2403:300:a51::/48 */
        {0x2a, 0x01, 0xb7, 0x40, 0x0a, 0x42}  /* 2a01:b740:a42::/48 */
    };
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (!address) return false;
    const uint8_t *bytes = address;
    if (!memcmp(bytes, mapped, sizeof(mapped))) return apr_ipv4_target(bytes + 12);
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(*prefixes); ++i)
        if (apr_prefix_match(bytes, prefixes[i], 48)) return true;
    return false;
}

static inline bool apr_host_target(const char *host) {
    if (!host) return false;
    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, host, &v4) == 1) return apr_ipv4_target(&v4);
    if (inet_pton(AF_INET6, host, &v6) == 1) return apr_ipv6_target(&v6);
    return apr_domain_target(host);
}
#endif
