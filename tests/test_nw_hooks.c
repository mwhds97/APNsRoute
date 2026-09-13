/* Exercise the actual public create hook with opaque, caller-owned parameters. */
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include "../src/Diagnostics.h"
#include "../src/NWHooks.h"

struct Endpoint { nw_endpoint_type_t type; const char *host; uint16_t port; const struct sockaddr *address; };
struct Parameters { const void *tls, *identity, *local, *protocols, *prohibitions; };
static nw_endpoint_t expected_endpoint;
static nw_parameters_t expected_parameters;
static unsigned calls, reports, observed;
uint32_t apr_connection_observe(uintptr_t key,unsigned role,bool new_object) {
    assert(key==99 && role && new_object);++observed;errno=EIO;return 1;
}
static bool failed, events[APR_EVENT_COUNT];
nw_endpoint_type_t nw_endpoint_get_type(nw_endpoint_t e) { return e->type; }
const char *nw_endpoint_get_hostname(nw_endpoint_t e) { return e->host; }
uint16_t nw_endpoint_get_port(nw_endpoint_t e) { return e->port; }
const struct sockaddr *nw_endpoint_get_address(nw_endpoint_t e) { return e->address; }
void apr_diag_event(enum apr_event event) { assert(event < APR_EVENT_COUNT); events[event] = true; errno = EIO; }
void apr_diag_nw_created(bool created, int error) {
    ++reports;
    assert(created == !failed && error == (failed ? ETIMEDOUT : 0));
    errno = EIO;
}
#include "../src/NWHooks.c"
static nw_connection_t original(nw_endpoint_t endpoint, nw_parameters_t parameters) {
    assert(endpoint == expected_endpoint && parameters == expected_parameters && errno == EDOM);
    ++calls;
    errno = failed ? ETIMEDOUT : EALREADY;
    return failed ? NULL : (void *)99;
}
static void run(nw_endpoint_t endpoint, nw_parameters_t parameters, bool matched) {
    struct Parameters before = {0};
    if (parameters) before = *parameters;
    expected_endpoint = endpoint; expected_parameters = parameters;
    calls = reports = observed = 0; memset(events, 0, sizeof(events)); errno = EDOM;
    assert(apr_nw_create(endpoint, parameters) == (failed ? NULL : (void *)99));
    assert(errno == (failed ? ETIMEDOUT : EALREADY) && calls == 1);
    assert(reports == (unsigned)matched && events[APR_NW_MATCHED] == matched);
    assert(observed==(unsigned)(matched && !failed));
    if (parameters) assert(!memcmp(parameters, &before, sizeof(before)));
}
int main(void) {
    apr_original_nw_create = original;
    struct Parameters p = {(void *)1, (void *)2, (void *)3, (void *)4, (void *)5};
    struct Endpoint host = {nw_endpoint_type_host, "37-courier9.push.apple.com", 443, NULL};
    assert(apr_nw_role(&host)==APR_ROLE_COURIER);
    host.host="INIT.PUSH.APPLE.COM.";assert(apr_nw_role(&host)==APR_ROLE_INIT);
    host.host="COURier.sandbox.push.apple.com";assert(apr_nw_role(&host)==APR_ROLE_COURIER);
    host.host="courier.push.apple.com.evil.net";assert(apr_nw_role(&host)==APR_ROLE_HOST);
    host.host="identity.apple.com";assert(apr_nw_role(&host)==APR_ROLE_HOST);
    assert(apr_nw_role(NULL)==APR_ROLE_UNKNOWN);
    const char *matched[]={"identity.apple.com","init.push.apple.com","akadns.net",
        "x.apple.com.edgekey.net.example","17.249.1.2","2403:300:a51::123"};
    const unsigned ports[]={0,1,80,443,5223,8443,65535};
    for(unsigned i=0;i<sizeof(matched)/sizeof(*matched);++i)
        for(unsigned j=0;j<sizeof(ports)/sizeof(*ports);++j) {
            host.host=matched[i];host.port=ports[j];run(&host,&p,true);
        }
    run(NULL, &p, false); run(&host, NULL, false);
    failed = true; run(&host, &p, true); failed = false;
    host.host="example.net";host.port=5223;run(&host,&p,false);
    struct sockaddr_in v4 = {.sin_family = AF_INET, .sin_port = htons(12345)};
    struct sockaddr_in6 v6 = {.sin6_family = AF_INET6, .sin6_port = htons(80)};
    assert(inet_pton(AF_INET,"17.188.21.42",&v4.sin_addr)==1);
    assert(inet_pton(AF_INET6,"2a01:b740:a42::42",&v6.sin6_addr)==1);
    struct Endpoint address = {nw_endpoint_type_address, NULL, 0, (struct sockaddr *)&v4};
    run(&address, &p, true);
    address.address = (struct sockaddr *)&v6; run(&address, &p, true);
    v6.sin6_port=htons(5223);assert(inet_pton(AF_INET6,"2a01:b740:a43::42",&v6.sin6_addr)==1);
    run(&address,&p,false);
    v4.sin_port=htons(5223);assert(inet_pton(AF_INET,"17.188.22.42",&v4.sin_addr)==1);
    address.address=(struct sockaddr *)&v4;run(&address,&p,false);
    address.address = NULL; run(&address, &p, false);
    puts("PASS: actual public create hook domain/IP matching on arbitrary ports, opaque parameter identity, result, errno and NULL handling");
}
