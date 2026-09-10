#include "NWHooks.h"
#include "Diagnostics.h"
#include "Policy.h"
#include <errno.h>
#include <netinet/in.h>
nw_connection_t (*apr_original_nw_create)(nw_endpoint_t,nw_parameters_t);

bool apr_nw_target(nw_endpoint_t endpoint) {
    if (!endpoint) return false;
    nw_endpoint_type_t type = nw_endpoint_get_type(endpoint);
    if (type == nw_endpoint_type_host) {
        return apr_host_target(nw_endpoint_get_hostname(endpoint));
    }
    if (type == nw_endpoint_type_address) {
        const struct sockaddr *a = nw_endpoint_get_address(endpoint);
        if (!a) return false;
        if (a->sa_family == AF_INET)
            return apr_ipv4_target(&((const struct sockaddr_in *)a)->sin_addr);
        if (a->sa_family == AF_INET6)
            return apr_ipv6_target(&((const struct sockaddr_in6 *)a)->sin6_addr);
    }
    return false;
}

nw_connection_t apr_nw_create(nw_endpoint_t endpoint, nw_parameters_t parameters) {
    int entry_errno = errno;
    apr_diag_event(APR_NW_ANY);
    if (!parameters || !apr_nw_target(endpoint)) {
        errno = entry_errno;
        return apr_original_nw_create(endpoint, parameters);
    }

    apr_diag_event(APR_NW_MATCHED);
    /* Network create leaves endpoint and parameters exactly as supplied.
       Rule-matched tunnel selection happens in NECP ADD input. */
    errno = entry_errno;
    nw_connection_t result = apr_original_nw_create(endpoint, parameters);
    int result_errno = errno;
    apr_diag_nw_created(result!=NULL,result ? 0 : result_errno);
    if(!result) apr_diag_event(APR_NW_CREATE_FAILED);
    errno = result_errno;
    return result;
}
