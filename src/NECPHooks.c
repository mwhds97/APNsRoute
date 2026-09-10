/* Darwin 20 necp_client_action ABI: xnu-7195.141.2/bsd/net/necp.h
   and necp_client_parse_parameters in necp_client.c. Rewrite only validated
   rule-matched ADD input bindings. Preserve identity, addresses and other actions. */
#include "NECPHooks.h"
#include "NECPResults.h"
#include "Diagnostics.h"
#include "Policy.h"
#include "InterfaceName.h"
#include "TunnelSelector.h"
#include "BindingStatus.h"
#include "InterfaceCheck.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

extern bool apr_can_modify(void);
int (*apr_original_necp)(int, uint32_t, uint8_t *, size_t, uint8_t *, size_t);

/* Values belong to Darwin's wire ABI, including its address-family numbers. */
enum {
    ADD = 1,
    DOMAIN = 3,
    BOUND = 9,
    PROTOCOL = 11,
    LOCAL_ADDRESS = 12,
    REMOTE_ADDRESS = 13,
    PROHIBIT_INTERFACE = 100,
    PROHIBIT_TYPE = 101,
    PROHIBIT_AGENT = 102,
    PROHIBIT_AGENT_TYPE = 103,
    REQUIRE_TYPE = 111,
    REQUIRE_AGENT = 112,
    REQUIRE_AGENT_TYPE = 113,
    PREFER_AGENT_TYPE = 123,
    PARENT = 150,
    LOCAL_ENDPOINT = 200,
    REMOTE_ENDPOINT = 201,
    TRANSPORT = 221,
    FLAGS = 250,
    CELLULAR_TYPE = 5,
    DARWIN_INET = 2,
    DARWIN_INET6 = 30
};

typedef struct {
    bool target, cellular, protocol8, legacy_address, tunnel_prohibited;
    bool local, unsupported_flags;
    unsigned family, agent_fields;
    APRConstraints constraints;
} Inspection;

static bool readable_agent_name(const uint8_t *p) {
    const uint8_t *end = memchr(p, 0, 32);
    if (!end) return false;
    for (const uint8_t *q = p; q < end; ++q)
        if (*q < 32 || *q > 126) return false;
    for (const uint8_t *q = end; q < p + 32; ++q)
        if (*q) return false;
    return true;
}

static bool cellular_internet_agent(const uint8_t *p) {
    /* Exact canonical Darwin agent_type value, including zero padding. */
    static const uint8_t expected[64] = {
        'C', 'e', 'l', 'l', 'u', 'l', 'a', 'r',
        [32] = 'I', 'n', 't', 'e', 'r', 'n', 'e', 't'
    };
    return !memcmp(p, expected, sizeof(expected));
}

static void inspect_agent(const uint8_t *p, uint32_t n, Inspection *found) {
    APRConstraints *c = &found->constraints;
    ++found->agent_fields;
    c->agent_info = (c->agent_info & ~255U) |
        (found->agent_fields < 255 ? found->agent_fields : 255);
    if (found->agent_fields > 4) c->agent_info |= APR_AGENT_TOO_MANY;
    if (n != 64) return; /* Width rejection is already represented in constraints. */
    if (!readable_agent_name(p) || !readable_agent_name(p + 32)) {
        c->unsupported |= APR_C_REQUIRE_AGENT_TYPE;
        c->agent_info |= APR_AGENT_BAD_NAME;
        return;
    }
    if (!p[0] && !p[32]) return;
    if (!cellular_internet_agent(p)) c->agent_info |= APR_AGENT_OTHER;
    if (!(c->agent_info & APR_AGENT_NAMES)) {
        memcpy(c->agent, p, 64);
        c->agent_info |= APR_AGENT_NAMES;
    } else if (memcmp(c->agent, p, 64)) c->agent_info |= APR_AGENT_MULTIPLE;
}

static void inspect_constraint(uint8_t type, const uint8_t *value, uint32_t n,
                               APRConstraints *c) {
    unsigned bit = 0, width = 0;
    switch (type) {
        case BOUND:               bit = APR_C_BOUND; break;
        case PROHIBIT_INTERFACE:  bit = APR_C_PROHIBIT_INTERFACE; break;
        case PROHIBIT_TYPE:       bit = APR_C_PROHIBIT_TYPE; width = 1; break;
        case PROHIBIT_AGENT:      bit = APR_C_PROHIBIT_AGENT; width = 16; break;
        case PROHIBIT_AGENT_TYPE: bit = APR_C_PROHIBIT_AGENT_TYPE; width = 64; break;
        case REQUIRE_TYPE:        bit = APR_C_REQUIRE_TYPE; width = 1; break;
        case REQUIRE_AGENT:       bit = APR_C_REQUIRE_AGENT; width = 16; break;
        case REQUIRE_AGENT_TYPE:  bit = APR_C_REQUIRE_AGENT_TYPE; width = 64; break;
        case PARENT:              bit = APR_C_PARENT; width = 16; break;
        default: return;
    }
    c->seen |= bit;
    /* Darwin skips zero-length TLVs. Recognize only the declared fixed widths
       (or bounded interface names); unfamiliar layouts remain native. */
    if (!n) {
        c->inert |= bit;
        return;
    }
    /* IFXNAMSIZ is IFNAMSIZ(16)+8. Agent types contain two 32-byte arrays.
       See xnu-7195.141.2 if_var.h, network_agent.h and necp.h. */
    bool supported = width ? n == width : n <= 24;
    if (!supported) c->unsupported |= bit;
    else if (type == PARENT) {
        /* Darwin 20 uses PARENT_ID only for resolver-answer validation here.
           It is metadata, not a requested interface/agent. Keep it untouched. */
        return;
    } else {
        bool nonzero = false;
        for (uint32_t i = 0; i < n; ++i) {
            if (value[i]) {
                nonzero = true;
                break;
            }
        }
        if (!nonzero) {
            c->inert |= bit;
            return;
        }
        c->restricted |= bit;
    }
    if (!c->first) {
        c->first = (uint32_t)type | (n << 8) |
            ((type == PROHIBIT_TYPE || type == REQUIRE_TYPE) ? (uint32_t)value[0] << 24 : 0);
    }
}

static bool text_field(const uint8_t *p, size_t n, char *dst, size_t capacity) {
    const uint8_t *end = memchr(p, 0, n);
    if (end) {
        size_t length = (size_t)(end - p);
        for (size_t i = length; i < n; ++i)
            if (p[i]) return false;
        n = length;
    }
    if (!n || n >= capacity) return false;
    memcpy(dst, p, n);
    dst[n] = 0;
    return true;
}

static bool is_cellular(uint8_t type, const uint8_t *value, size_t n) {
    if (type == REQUIRE_TYPE) return n >= 1 && value[0] == CELLULAR_TYPE;
    char name[16];
    return type == BOUND && text_field(value, n, name, sizeof(name)) &&
        apr_index_name(name, "pdp_ip");
}

static bool reject(enum apr_necp_reject reason, unsigned type, uint32_t length) {
    apr_diag_necp_reject(reason, type, length);
    return false;
}

static bool remote_port(const uint8_t *p, size_t n, bool legacy, unsigned *port) {
    /* Packed remote-address: prefix byte + 28-byte sockaddr union.
       Remote-endpoint: 28-byte union, optionally followed by name data. */
    if (n < (legacy ? 29U : 28U)) return false;
    if (legacy) {
        ++p;
        --n;
    }
    if ((p[1] == DARWIN_INET && p[0] == 16) ||
        (p[1] == DARWIN_INET6 && p[0] == 28) ||
        (!legacy && p[1] == 0 && n >= 28)) {
        *port = ((unsigned)p[2] << 8) | p[3];
        return true;
    }
    return false;
}

static bool wildcard_local(const uint8_t *p, size_t n, bool legacy) {
    if (n < (legacy ? 29U : 28U)) return false;
    if (legacy) {
        ++p;
        --n;
    }
    if (!((p[0] == 16 && p[1] == DARWIN_INET) ||
          (p[0] == 28 && p[1] == DARWIN_INET6) || (!p[0] && !p[1]))) return false;
    for (size_t i = 2; i < n; ++i)
        if (p[i]) return false;
    return true;
}

static bool inspect(const uint8_t *buffer, size_t size, Inspection *result) {
    char domain[256] = {0};
    unsigned port = 0, protocol = 0, transport = 0;
    uint8_t remote[16] = {0};
    size_t remote_size = 0;
    bool have_domain = false, have_protocol = false, have_transport = false;
    uint32_t flags = 0;
    *result = (Inspection){0};

    for (size_t at = 0; at < size;) {
        if (size - at < 5) return reject(APR_REJECT_TLV, 0, (uint32_t)(size - at));
        uint8_t type = buffer[at];
        uint32_t n;
        memcpy(&n, buffer + at + 1, 4);
        if (n > size - at - 5) return reject(APR_REJECT_TLV, type, n);
        const uint8_t *p = buffer + at + 5;
        inspect_constraint(type, p, n, &result->constraints);
        if (!n) { /* Darwin ignores empty values. */
            at += 5;
            continue;
        }
        if (type == PROHIBIT_TYPE && n == 1)
            result->constraints.prohibited_types[*p / 32] |= UINT32_C(1) << (*p % 32);
        if (type == REQUIRE_AGENT_TYPE) inspect_agent(p, n, result);
        if (type == PREFER_AGENT_TYPE)
            result->constraints.agent_info |= APR_AGENT_EXISTING_PREFERENCE;
        if (type == LOCAL_ADDRESS || type == LOCAL_ENDPOINT) {
            if (!wildcard_local(p, n, type == LOCAL_ADDRESS)) result->local = true;
        }

        if (type == DOMAIN) {
            char value[256];
            if (!text_field(p, n, value, sizeof(value))) return reject(APR_REJECT_TEXT, type, n);
            if (have_domain && strcmp(domain, value)) return reject(APR_REJECT_CONFLICT, type, n);
            memcpy(domain, value, strlen(value) + 1);
            have_domain = true;
        } else if (type == REMOTE_ENDPOINT || type == REMOTE_ADDRESS) {
            unsigned value = 0;
            if (!remote_port(p, n, type == REMOTE_ADDRESS, &value))
                return reject(APR_REJECT_ENDPOINT, type, n);
            if (port && value && port != value) return reject(APR_REJECT_CONFLICT, type, n);
            if (value) port = value;
            if (type == REMOTE_ADDRESS) result->legacy_address = true;
            const uint8_t *address = p + (type == REMOTE_ADDRESS ? 1 : 0);
            unsigned family = address[1] == DARWIN_INET ? APR_TUN_V4 :
                address[1] == DARWIN_INET6 ? APR_TUN_V6 : 0;
            if (family && result->family && family != result->family)
                return reject(APR_REJECT_CONFLICT, type, n);
            if (family) {
                size_t width = family == APR_TUN_V4 ? 4 : 16;
                const uint8_t *ip = address + (family == APR_TUN_V4 ? 4 : 8);
                /* A later endpoint must not replace the address that qualified
                   the request. Conflicting duplicate address fields stay native. */
                if (remote_size && memcmp(remote, ip, width))
                    return reject(APR_REJECT_CONFLICT, type, n);
                memcpy(remote, ip, width);
                remote_size = width;
                result->family = family;
            }
        } else if (type == PROTOCOL || type == TRANSPORT) {
            unsigned v = 0;
            if (type == PROTOCOL) {
                /* Kernel accepts uint8 as well as the header's uint16 form. */
                if (n == 1) {
                    v = *p;
                    result->protocol8 = true;
                } else {
                    uint16_t raw;
                    memcpy(&raw, p, 2);
                    v = raw;
                }
                if (have_protocol && protocol != v) return reject(APR_REJECT_CONFLICT, type, n);
                have_protocol = true;
                protocol = v;
            } else {
                v = *p;
                if (have_transport && transport != v) return reject(APR_REJECT_CONFLICT, type, n);
                have_transport = true;
                transport = v;
            }
        } else if (type == FLAGS) {
            if (n < 4) return reject(APR_REJECT_FLAGS, type, n);
            uint32_t raw;
            memcpy(&raw, p, 4);
            flags |= raw;
        } else if (type == PROHIBIT_INTERFACE) {
            char name[16];
            if (text_field(p, n, name, sizeof(name)) && apr_index_name(name, "utun"))
                result->tunnel_prohibited = true;
        }
        if (is_cellular(type, p, n)) result->cellular = true;
        at += 5 + n;
    }

    /* IP and transport protocol are separate; zero means unspecified.
       Do not change known non-TCP, listener, or inbound clients. */
    if ((have_protocol && protocol && protocol != 6) ||
        (have_transport && transport && transport != 6) || (flags & (0x0008 | 0x4000)))
        return true;
    /* No multipath/browse/custom-channel or cost/constrained-policy changes.
       Unknown Darwin-20 flag bits are also preserved by declining the bind. */
    result->unsupported_flags =
        (flags & (0x0001 | 0x0002 | 0x0004 | 0x0200 | 0x0400 | 0x0800 | 0x1000)) ||
        (flags & ~0x7fffU);
    result->target = apr_host_target(domain) ||
        (remote_size == 4 && apr_ipv4_target(remote)) ||
        (remote_size == 16 && apr_ipv6_target(remote));
    APRConstraints *c = &result->constraints;
    c->blocked = c->restricted | c->unsupported;
    /* Keep every exclusion byte. A nonzero one-byte prohibition is eligible
       only after checking the tunnel and all observed delegates below. */
    if (!(c->unsupported & APR_C_PROHIBIT_TYPE)) c->blocked &= ~APR_C_PROHIBIT_TYPE;
    /* Convert only the observed Cellular / Internet pair, at most the kernel's
       four slots. Keep other/wildcard requirements and existing preference
       lists native instead of changing their ordering/capacity semantics. */
    if (!(c->unsupported & APR_C_REQUIRE_AGENT_TYPE) && result->agent_fields <= 4 &&
        !(c->agent_info & (APR_AGENT_EXISTING_PREFERENCE | APR_AGENT_OTHER)))
        c->blocked &= ~APR_C_REQUIRE_AGENT_TYPE;
    return true;
}

int apr_necp(int fd, uint32_t action, uint8_t *client, size_t client_length,
             uint8_t *buffer, size_t size) {
    int entry = errno;
    if (action != ADD) {
        uint8_t id[16] = {0};
        bool have_id = client && client_length == sizeof(id);
        if (have_id) memcpy(id, client, sizeof(id));
        int result = apr_original_necp(fd, action, client, client_length, buffer, size);
        int saved = errno;
        if (have_id && result >= 0) apr_necp_result_action(fd, action, id, buffer, size, result);
        errno = saved;
        return result;
    }

    apr_diag_event(APR_NECP_CALL);
    Inspection found = {0};
    uint8_t *copy = NULL;
    size_t selected_size = size;
    bool valid = false;
    APRTunnel tunnel = {0};
    unsigned binding = APR_BIND_NATIVE;
    int binding_error = 0;
    if (!buffer || !size || size > 65536)
        (void)reject(APR_REJECT_BUFFER, 0, size > UINT32_MAX ? UINT32_MAX : (uint32_t)size);
    else valid = inspect(buffer, size, &found);
    if (!valid) apr_diag_event(APR_NECP_INVALID);
    else {
        apr_diag_event(APR_NECP_PARSED);
        if (found.protocol8) apr_diag_event(APR_NECP_IPPROTO8);
        if (found.legacy_address) apr_diag_event(APR_NECP_LEGACY_ADDRESS);
        if (found.target) {
            apr_diag_event(APR_NECP_MATCHED);
            if (found.tunnel_prohibited) apr_diag_event(APR_NECP_TUNNEL_PROHIBITED);
            apr_diag_event(found.cellular ? APR_NECP_CELLULAR : APR_NECP_NO_CELLULAR);
            if (client && client_length == 16 && apr_can_modify()) {
                if (found.constraints.blocked) binding = APR_BIND_CONSTRAINT;
                else if (found.local) binding = APR_BIND_LOCAL;
                else if (found.unsupported_flags) binding = APR_BIND_UNSUPPORTED_FLAGS;
                else {
                    enum apr_tunnel_choice choice = apr_tunnel_select(found.family, &tunnel, &binding_error);
                    if (choice != APR_TUN_UNIQUE) {
                        binding = choice == APR_TUN_NONE ? APR_BIND_NO_TUNNEL :
                            choice == APR_TUN_AMBIGUOUS ? APR_BIND_AMBIGUOUS :
                            choice == APR_TUN_FAMILY ? APR_BIND_FAMILY :
                            choice == APR_TUN_CHANGED ? APR_BIND_CHANGED : APR_BIND_SELECTION;
                    } else {
                        uint32_t length = (uint32_t)strlen(tunnel.name) + 1;
                        if (size > 1024 - 5 - length) binding = APR_BIND_CAPACITY;
                        else if (!(copy = malloc(size + 5 + length))) {
                            binding = APR_BIND_ALLOCATION;
                            binding_error = ENOMEM;
                        } else {
                            /* Exact Darwin-20 BOUND_INTERFACE TLV. Only eligible
                               required-agent type bytes change, 113 -> 123.
                               Their values and every other original byte stay. */
                            memcpy(copy, buffer, size);
                            copy[size] = BOUND;
                            memcpy(copy + size + 1, &length, 4);
                            memcpy(copy + size + 5, tunnel.name, length);
                            for (size_t at = 0; at < size;) {
                                uint32_t n;
                                memcpy(&n, copy + at + 1, 4);
                                if (copy[at] == REQUIRE_AGENT_TYPE && n == 64 &&
                                    cellular_internet_agent(copy + at + 5)) {
                                    copy[at] = PREFER_AGENT_TYPE;
                                    ++found.constraints.edit;
                                }
                                at += 5 + n;
                            }
                            selected_size = size + 5 + length;
                            binding = APR_BIND_ACCEPTED;
                        }
                    }
                }
            }
        }
    }

    if (copy) {
        /* Recheck the name/index and address family just before the syscall.
           This narrows a tunnel-restart race; it cannot make kernel interface
           lifetime atomic with a userspace observation. */
        APRTunnel current = {0};
        int error = 0;
        if (apr_tunnel_select(found.family, &current, &error) != APR_TUN_UNIQUE ||
            current.index != tunnel.index || strcmp(current.name, tunnel.name)) {
            free(copy);
            copy = NULL;
            selected_size = size;
            binding = APR_BIND_CHANGED;
            binding_error = error;
        }
        if (copy && (found.constraints.restricted & APR_C_PROHIBIT_TYPE)) {
            APRInterfaceEvidence evidence = {0};
            enum apr_interface_check check = apr_check_interface_exclusions(
                fd, &current, found.constraints.prohibited_types, &evidence, &binding_error);
            found.constraints.check = evidence.detail;
            found.constraints.check_index = evidence.index;
            if (check != APR_IF_ALLOWED) {
                free(copy);
                copy = NULL;
                selected_size = size;
                binding = APR_BIND_INTERFACE_CHECK;
            }
        }
        if (!copy) found.constraints.edit = 0;
    }
    if (copy) found.constraints.edit |= APR_EDIT_SUBMITTED;
    errno = entry;
    int result = apr_original_necp(fd, action, client, client_length, copy ? copy : buffer, selected_size);
    int saved = errno;
    if (copy) {
        if (!result) found.constraints.edit |= APR_EDIT_ACCEPTED;
        apr_diag_event(result == 0 ? APR_NECP_CHANGED : APR_NECP_FAILED);
        if (result) {
            binding = APR_BIND_KERNEL;
            binding_error = saved;
        }
        free(copy);
    }
    if (valid && found.target && client && client_length == 16) {
        uint32_t generation = apr_diag_binding(
            binding | (tunnel.count << 8) | (tunnel.families << 16),
            tunnel.index, binding_error, &found.constraints);
        if (!result && client && client_length == 16)
            apr_necp_record_binding(fd, client, generation, binding == APR_BIND_ACCEPTED ? tunnel.index : 0);
    }
    errno = saved;
    return result;
}
