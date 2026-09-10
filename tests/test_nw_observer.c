#define _POSIX_C_SOURCE 200809L
#include <Network/Network.h>
#include "../src/NWObserver.h"
#include "../src/Diagnostics.h"
#include "../src/ConnectionStatus.h"
#include "../src/Policy.h"
#include <Block.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct Endpoint {int tag,refs;nw_endpoint_type_t type;const char *host;uint16_t port;struct sockaddr_in address;};
struct Connection {nw_endpoint_t endpoint;nw_connection_state_changed_handler_t handler;nw_path_t path;};
struct TestPath {int tag,refs;nw_path_status_t status;nw_path_unsatisfied_reason_t reason;bool cellular,loopback,expensive,constrained;};
struct TestError {nw_error_domain_t domain;int code;};
struct TestReport {bool configured,used;};
static bool events[APR_EVENT_COUNT],clock_fail,missing_reason;
static unsigned cancel_detail,cancel_calls,force_calls;
static unsigned start_detail,state_generation,state_value,state_domain,report_detail,report_requests;
static unsigned registrations,start_calls,send_calls;
static int state_error,handler_calls,handler_tag,handler_incoming;
static nw_error_t handler_error;
static nw_connection_state_t handler_state;
static uint64_t seconds=10;
static nw_establishment_report_access_block_t pending_report;
static nw_connection_state_changed_handler_t last_handler_input;
static nw_connection_t expected_connection;
static dispatch_data_t expected_content;
static nw_content_context_t expected_context;
static nw_connection_send_completion_t expected_completion;
static bool expected_complete;

void apr_diag_event(enum apr_event e) {assert(e<APR_EVENT_COUNT);events[e]=true;errno=EIO;}
void apr_diag_nw_cancel_path(unsigned detail) {cancel_detail=detail;errno=EIO;}
void apr_diag_nw_start(unsigned v) {start_detail=v;errno=EIO;}
uint32_t apr_diag_nw_handler(void) {errno=EIO;return ++registrations;}
void apr_diag_nw_state(uint32_t generation,unsigned state,unsigned domain,int code) {
    state_generation=generation;state_value=state;state_domain=domain;state_error=code;errno=EIO;
}
void apr_diag_nw_report(unsigned detail) {report_detail=detail;errno=EIO;}
bool apr_nw_target(nw_endpoint_t e) {return e && apr_host_target(e->host);}
nw_endpoint_type_t nw_endpoint_get_type(nw_endpoint_t e) {return e->type;}
const char *nw_endpoint_get_hostname(nw_endpoint_t e) {return e->host;}
uint16_t nw_endpoint_get_port(nw_endpoint_t e) {return e->port;}
const struct sockaddr *nw_endpoint_get_address(nw_endpoint_t e) {return (const struct sockaddr *)&e->address;}
nw_endpoint_t nw_connection_copy_endpoint(nw_connection_t object) {
    struct Connection *c=object;if(c->endpoint)++c->endpoint->refs;errno=EIO;return c->endpoint;
}
void nw_release(void *object) {
    int tag=*(int *)object;
    if(tag==1) {struct Endpoint *e=object;assert(e->refs>1);--e->refs;}
    else if(tag==3) {struct TestPath *p=object;assert(p->refs>1);--p->refs;}
    else abort();
    errno=EIO;
}
nw_error_domain_t nw_error_get_error_domain(nw_error_t e) {errno=EIO;return e->domain;}
int nw_error_get_error_code(nw_error_t e) {errno=EIO;return e->code;}
dispatch_queue_t dispatch_get_global_queue(long priority,unsigned long flags) {
    assert(!priority && !flags);return (void *)1;
}
void nw_connection_access_establishment_report(nw_connection_t c,dispatch_queue_t q,nw_establishment_report_access_block_t block) {
    assert(c==expected_connection && q==(void *)1 && !pending_report);
    pending_report=Block_copy(block);++report_requests;errno=EIO;
}
bool nw_establishment_report_get_proxy_configured(nw_establishment_report_t r) {return r->configured;}
bool nw_establishment_report_get_used_proxy(nw_establishment_report_t r) {return r->used;}
static int fake_clock(clockid_t clock,struct timespec *now) {
    assert(clock==CLOCK_MONOTONIC);if(clock_fail) {errno=EIO;return -1;}
    now->tv_sec=(time_t)seconds;now->tv_nsec=0;return 0;
}
nw_path_t nw_connection_copy_current_path(nw_connection_t object) {
    struct Connection *c=object;if(c->path)++c->path->refs;errno=EIO;return c->path;
}
nw_path_status_t nw_path_get_status(nw_path_t p) {return p->status;}
bool nw_path_uses_interface_type(nw_path_t p,nw_interface_type_t type) {
    return type==nw_interface_type_cellular?p->cellular:type==nw_interface_type_loopback?p->loopback:false;
}
bool nw_path_is_expensive(nw_path_t p) {return p->expensive;}
bool nw_path_is_constrained(nw_path_t p) {return p->constrained;}
static nw_path_unsatisfied_reason_t fake_reason(nw_path_t p) {return p->reason;}
static void *fake_dlsym(void *handle,const char *name) {
    (void)handle;assert(!strcmp(name,"nw_path_get_unsatisfied_reason"));return missing_reason?NULL:(void *)fake_reason;
}
#define dlsym fake_dlsym
#define clock_gettime fake_clock
#include "../src/NWObserver.c"
#undef clock_gettime
#undef dlsym

static void original_cancel(nw_connection_t object) {
    struct Connection *c=object;assert(c==expected_connection && errno==EDOM);++cancel_calls;c->path=NULL;errno=EBUSY;
}
static void original_force(nw_connection_t object) {
    struct Connection *c=object;assert(c==expected_connection && errno==EDOM);++force_calls;c->path=NULL;errno=EBUSY;
}
static void original_start(nw_connection_t c) {
    assert(c==expected_connection && errno==EDOM);++start_calls;errno=EBUSY;
}
static void original_handler(nw_connection_t object,nw_connection_state_changed_handler_t handler) {
    struct Connection *c=object;assert(c==expected_connection && errno==EDOM);
    last_handler_input=handler;
    nw_connection_state_changed_handler_t owned=handler?Block_copy(handler):NULL;
    if(c->handler)Block_release(c->handler);
    c->handler=owned;errno=EBUSY;
}
static void original_send(nw_connection_t c,dispatch_data_t data,nw_content_context_t context,bool complete,
                          nw_connection_send_completion_t completion) {
    assert(c==expected_connection && data==expected_content && context==expected_context &&
        complete==expected_complete && completion==expected_completion && errno==EDOM);
    ++send_calls;errno=EBUSY;
}
static void install(struct Connection *c,int tag) {
    /* Both nested blocks escape this stack frame using the real Blocks runtime. */
    nw_connection_state_changed_handler_t handler=^(nw_connection_state_t state,nw_error_t error) {
        ++handler_calls;handler_tag=tag;handler_state=state;handler_error=error;handler_incoming=errno;errno=EAGAIN;
    };
    expected_connection=c;errno=EDOM;apr_nw_state_handler(c,handler);assert(errno==EBUSY);
}
static void send_one(struct Connection *c) {
    expected_connection=c;expected_content=(void *)0x11;expected_context=(void *)0x22;
    expected_complete=true;expected_completion=^(nw_error_t e){(void)e;abort();};
    errno=EDOM;apr_nw_send(c,expected_content,expected_context,expected_complete,expected_completion);assert(errno==EBUSY);
}
static void report_complete(nw_establishment_report_t r) {
    assert(pending_report);nw_establishment_report_access_block_t block=pending_report;pending_report=NULL;
    errno=EDOM;block(r);assert(errno==EDOM);Block_release(block);
}
int main(void) {
    apr_original_nw_cancel=original_cancel;apr_original_nw_force_cancel=original_force;apr_nw_observer_init();
    apr_original_nw_start=original_start;apr_original_nw_state_handler=original_handler;apr_original_nw_send=original_send;
    struct Endpoint courier={.tag=1,.refs=1,.type=nw_endpoint_type_host,.host="17-courier8.push.apple.com",.port=5223};
    struct Endpoint init={.tag=1,.refs=1,.type=nw_endpoint_type_host,.host="unmatched.example.net",.port=443};
    struct Connection c={.endpoint=&courier};
    struct Connection other={.endpoint=&init};
    install(&c,42);assert(events[APR_NW_STATE_HANDLER] && registrations==1);
    struct TestError error={nw_error_domain_tls,-9807};
    errno=EDOM;c.handler(nw_connection_state_waiting,&error);
    assert(errno==EAGAIN && handler_incoming==EDOM && handler_tag==42 && handler_calls==1);
    assert(handler_state==nw_connection_state_waiting && handler_error==&error && state_error==-9807 && state_domain==3);
    assert(state_value==1 && state_generation==1);
    nw_connection_state_changed_handler_t old=Block_copy(c.handler);
    install(&c,73);errno=EDOM;old(nw_connection_state_failed,&error);assert(handler_tag==42 && state_generation==1);
    Block_release(old);errno=EDOM;c.handler(nw_connection_state_ready,NULL);assert(handler_tag==73 && state_generation==2);
    errno=EDOM;c.handler(nw_connection_state_cancelled,NULL);assert(handler_tag==73 && events[APR_NW_STATE_CANCELLED]);
    expected_connection=&c;errno=EDOM;apr_nw_state_handler(&c,NULL);
    assert(errno==EBUSY && !c.handler && !last_handler_input && events[APR_NW_STATE_CLEAR]);
    unsigned previous=registrations;
    nw_connection_state_changed_handler_t raw=^(nw_connection_state_t s,nw_error_t e){(void)s;(void)e;};
    expected_connection=&other;errno=EDOM;apr_nw_state_handler(&other,raw);
    assert(last_handler_input==raw && registrations==previous);Block_release(other.handler);other.handler=NULL;
    expected_connection=&c;errno=EDOM;apr_nw_start(&c);
    assert(errno==EBUSY && start_calls==1 && start_detail==APR_START_SEEN);
    expected_connection=&other;errno=EDOM;apr_nw_start(&other);
    assert(errno==EBUSY && start_calls==2);
    send_one(&other);assert(!report_requests);
    send_one(&c);assert(report_requests==1 && report_detail==APR_REPORT_REQUESTED);
    seconds+=10;send_one(&c);assert(report_requests==1); /* only one in flight */
    report_complete(NULL);assert(report_detail==(APR_REPORT_REQUESTED|APR_REPORT_RETURNED));
    send_one(&c);assert(report_requests==2);
    struct TestReport report={true,true};report_complete(&report);
    assert((report_detail&APR_REPORT_USED) && (report_detail&APR_REPORT_CONFIGURED));
    send_one(&c);assert(report_requests==2); /* rate limit */
    seconds+=5;send_one(&c);assert(report_requests==3);report.used=false;report_complete(&report);
    assert((report_detail&APR_REPORT_CONFIGURED) && !(report_detail&APR_REPORT_USED));
    clock_fail=true;seconds+=5;send_one(&c);assert(report_requests==3);clock_fail=false;
    struct TestPath path={.tag=3,.refs=1,.status=nw_path_status_unsatisfied,
        .reason=nw_path_unsatisfied_reason_cellular_denied,.cellular=true,.expensive=true};
    c.path=&path;expected_connection=&c;errno=EDOM;apr_nw_cancel(&c);
    assert(errno==EBUSY && !c.path && path.refs==1 && cancel_calls==1);
    assert((cancel_detail&APR_PATH_PRESENT) && (cancel_detail&255)==nw_path_status_unsatisfied && ((cancel_detail>>8)&255)==1);
    assert((cancel_detail&APR_PATH_CELL) && (cancel_detail&APR_PATH_REASON_API));
    missing_reason=true;apr_nw_observer_init();c.path=&path;errno=EDOM;apr_nw_force_cancel(&c);
    assert(errno==EBUSY && force_calls==1 && (cancel_detail&APR_PATH_FORCE) && !(cancel_detail&APR_PATH_REASON_API) && path.refs==1);
    errno=EDOM;apr_nw_cancel(&c);assert(cancel_detail==APR_PATH_SEEN && events[APR_NW_CANCEL_PATH_MISSING]);
    unsigned previous_cancel=cancel_detail;other.path=&path;expected_connection=&other;errno=EDOM;apr_nw_cancel(&other);
    assert(cancel_detail==previous_cancel && path.refs==1);
    assert(send_calls==7 && courier.refs==1 && init.refs==1);
    puts("PASS: actual escaping Blocks, callback replacement/removal and cancellation, exact arguments/errno, public-only async report gating and connection-state diagnostics");
}
