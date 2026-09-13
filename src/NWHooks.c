#include "NWHooks.h"
#include "Diagnostics.h"
#include "Policy.h"
#include "Connections.h"
#include <errno.h>
#include <netinet/in.h>
nw_connection_t (*apr_original_nw_create)(nw_endpoint_t,nw_parameters_t);

/* Diagnostic labels only. Routing continues to use the user's complete rules,
   independently of ports or these optional hostname hints. */
unsigned apr_nw_role(nw_endpoint_t endpoint) {
    if(!endpoint) return APR_ROLE_UNKNOWN;
    if(nw_endpoint_get_type(endpoint)==nw_endpoint_type_address) return APR_ROLE_ADDRESS;
    if(nw_endpoint_get_type(endpoint)!=nw_endpoint_type_host) return APR_ROLE_UNKNOWN;
    const char *host=nw_endpoint_get_hostname(endpoint);
    size_t n=apr_host_length(host);
    if(n==19 && !strncasecmp(host,"init.push.apple.com",19)) return APR_ROLE_INIT;
    const char suffix[]=".push.apple.com";
    size_t s=sizeof(suffix)-1;
    if(n>s && !strncasecmp(host+n-s,suffix,s)) {
        size_t label=0;while(label<n && host[label]!='.') ++label;
        for(size_t i=0;i+7<=label;++i)
            if(!strncasecmp(host+i,"courier",7)) return APR_ROLE_COURIER;
    }
    return APR_ROLE_HOST;
}

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
    if(result) (void)apr_connection_observe((uintptr_t)result,apr_nw_role(endpoint),true);
    if(!result) apr_diag_event(APR_NW_CREATE_FAILED);
    errno = result_errno;
    return result;
}
