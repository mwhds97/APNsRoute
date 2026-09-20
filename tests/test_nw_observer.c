#define _POSIX_C_SOURCE 200809L
#include <Network/Network.h>
#include "../src/NWObserver.h"
#include "../src/Diagnostics.h"
#include "../src/ConnectionStatus.h"
#include "../src/Policy.h"
#include "../src/Connections.h"
#include "../src/Retirement.h"
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
static bool events[APR_EVENT_COUNT],clock_fail,missing_reason,missing_endpoint,enabled,nested_cancel;
static unsigned normal_requests,immediate_requests,app_force_requests,cancel_action;
static unsigned cancel_detail,cancel_calls,force_calls,endpoint_requests;
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
static uint32_t connection_rows[APR_CONNECTION_COUNT][APR_CONNECTION_FIELD_COUNT];
void apr_diag_connection(unsigned slot,const uint32_t v[APR_CONNECTION_FIELD_COUNT]) {
    assert(slot<APR_CONNECTION_COUNT);memcpy(connection_rows[slot],v,sizeof(connection_rows[slot]));errno=EIO;
}
void apr_diag_connection_overflow(void) {abort();}
static const uint32_t *row_for(uint32_t id) {
    for(unsigned i=0;i<APR_CONNECTION_COUNT;++i) if(connection_rows[i][APR_R_ID]==id) return connection_rows[i];
    return NULL;
}
unsigned apr_nw_role(nw_endpoint_t endpoint) {(void)endpoint;return APR_ROLE_COURIER;}
size_t dispatch_data_get_size(dispatch_data_t data) {errno=EIO;return *(size_t *)data;}
static nw_connection_receive_completion_t pending_receive,last_receive_input;
static unsigned receive_calls,receive_message_calls,receive_callbacks;
static uint32_t expected_minimum,expected_maximum;
static nw_error_t expected_receive_error;
static void original_receive(nw_connection_t c,uint32_t minimum,uint32_t maximum,
                             nw_connection_receive_completion_t completion) {
    assert(c==expected_connection && minimum==expected_minimum && maximum==expected_maximum && errno==EDOM);
    assert(!pending_receive);last_receive_input=completion;
    pending_receive=completion?Block_copy(completion):NULL;++receive_calls;errno=EBUSY;
}
static void original_receive_message(nw_connection_t c,nw_connection_receive_completion_t completion) {
    assert(c==expected_connection && errno==EDOM && !pending_receive);last_receive_input=completion;
    pending_receive=completion?Block_copy(completion):NULL;++receive_message_calls;errno=EBUSY;
}
static void receive_one(struct Connection *c,bool message,nw_connection_receive_completion_t completion) {
    expected_connection=c;expected_minimum=3;expected_maximum=4096;errno=EDOM;
    if(message) apr_nw_receive_message(c,completion);
    else apr_nw_receive(c,expected_minimum,expected_maximum,completion);
    assert(errno==EBUSY);
}
static void finish_receive(dispatch_data_t data,bool complete,nw_error_t error) {
    expected_content=data;expected_context=(void *)0x55;expected_complete=complete;expected_receive_error=error;
    assert(pending_receive);nw_connection_receive_completion_t callback=pending_receive;pending_receive=NULL;
    errno=EDOM;callback(data,expected_context,complete,error);assert(errno==EAGAIN);Block_release(callback);
}
static void receive_tests(struct Connection *c,struct Connection *other,struct TestPath *path) {
    apr_original_nw_receive=original_receive;apr_original_nw_receive_message=original_receive_message;
    nw_connection_receive_completion_t callback=^(dispatch_data_t data,nw_content_context_t context,bool complete,nw_error_t error) {
        assert(data==expected_content && context==expected_context && complete==expected_complete && error==expected_receive_error);
        assert(errno==EDOM);++receive_callbacks;errno=EAGAIN;
    };
    uint32_t id=apr_connection_find((uintptr_t)c);assert(id);c->path=path;
    unsigned prev_reads=row_for(id)[APR_R_READS];
    receive_one(c,false,callback);assert(last_receive_input!=callback && path->refs==1);
    size_t data_size=137;finish_receive(&data_size,false,NULL);
    assert(row_for(id)[APR_R_READS]==prev_reads+1 && row_for(id)[APR_R_RECEIVED]==1);
    assert(row_for(id)[APR_R_BYTES]==137 && !row_for(id)[APR_R_COMPLETES]);
    receive_one(c,true,callback);struct TestError error={nw_error_domain_posix,54};
    finish_receive(NULL,true,&error);
    assert(row_for(id)[APR_R_RECEIVED]==2 && row_for(id)[APR_R_COMPLETES]==1);
    assert(row_for(id)[APR_R_ERROR_INFO]==((APR_ERROR_RECEIVE<<8)|1));
    assert((row_for(id)[APR_R_PATH]&APR_PATH_CELL) && row_for(id)[APR_R_ERROR_CODE]==54);
    receive_one(c,true,callback);finish_receive(&data_size,false,&error);
    assert(row_for(id)[APR_R_BYTES]==274); /* Content and error may coexist. */
    receive_one(c,false,NULL);assert(!pending_receive && !last_receive_input);
    receive_one(c,true,NULL);assert(!pending_receive && !last_receive_input);
    receive_one(other,false,callback);assert(last_receive_input==callback);finish_receive(NULL,false,NULL);
    receive_one(other,true,callback);assert(last_receive_input==callback);finish_receive(NULL,false,NULL);
    /* A completion from an older object must still reach its original caller,
       but cannot alter records for a new object at the same address. */
    receive_one(c,false,callback);
    uint32_t fresh=apr_connection_observe((uintptr_t)c,APR_ROLE_COURIER,true);assert(fresh!=id);
    finish_receive(&data_size,true,NULL);
    assert(!row_for(id) && row_for(fresh)[APR_R_RECEIVED]==0 && row_for(fresh)[APR_R_BYTES]==0);
    assert(receive_calls==4 && receive_message_calls==4 && receive_callbacks==6);
    assert(path->refs==1);
}


static unsigned retire_starts,retire_states,retire_forgets;
void apr_retirement_start(nw_connection_t c,uint32_t id,uint32_t handler) {
    assert(c && id);(void)handler;++retire_starts;errno=EIO;
}
void apr_retirement_handler(uint32_t id,uint32_t handler) {assert(id);(void)handler;errno=EIO;}
void apr_retirement_state(uint32_t id,uint32_t handler,unsigned state) {
    assert(id && handler && state<=5);++retire_states;errno=EIO;
}
void apr_retirement_forget(uint32_t id) {assert(id);++retire_forgets;errno=EIO;}
void apr_diag_event(enum apr_event e) {assert(e<APR_EVENT_COUNT);events[e]=true;errno=EIO;}
void apr_diag_nw_cancel_path(unsigned detail) {cancel_detail=detail;errno=EIO;}
bool apr_can_modify(void) {errno=EIO;return enabled;}
void apr_diag_nw_cancel(unsigned action) {
    cancel_action=action;
    if(action==APR_CANCEL_APP_FORCE) ++app_force_requests;
    else ++normal_requests;
    if(action==APR_CANCEL_IMMEDIATE) ++immediate_requests;
    errno=EIO;
}
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
static void fake_endpoint(nw_connection_t);
static void *fake_dlsym(void *handle,const char *name) {
    (void)handle;
    if(!strcmp(name,"nw_path_get_unsatisfied_reason"))return missing_reason?NULL:(void *)fake_reason;
    assert(!strcmp(name,"nw_connection_cancel_current_endpoint"));
    return missing_endpoint?NULL:(void *)fake_endpoint;
}
#define dlsym fake_dlsym
#define clock_gettime fake_clock
#include "../src/NWObserver.c"
#undef clock_gettime
#undef dlsym

static void fake_endpoint(nw_connection_t object) {
    assert(object==expected_connection && errno==EDOM);++endpoint_requests;
    if(nested_cancel)apr_nw_cancel(object);
    errno=EBUSY;
}
static void original_cancel(nw_connection_t object) {
    struct Connection *c=object;assert(c==expected_connection && errno==EDOM);++cancel_calls;c->path=NULL;errno=EBUSY;
}
static void original_force(nw_connection_t object) {
    struct Connection *c=object;assert(c==expected_connection && errno==EDOM);++force_calls;
    if(nested_cancel) apr_nw_cancel(object);
    c->path=NULL;errno=EBUSY;
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
    assert(normal_requests==2 && immediate_requests==0 && app_force_requests==1);
    assert(cancel_action==APR_CANCEL_NATIVE);
    enabled=true;expected_connection=&c;c.path=&path;
    unsigned normal_before=cancel_calls,force_before=force_calls;
    errno=EDOM;apr_nw_cancel(&c);
    assert(errno==EBUSY && cancel_calls==normal_before && force_calls==force_before+1);
    assert(normal_requests==3 && immediate_requests==1 && cancel_action==APR_CANCEL_IMMEDIATE);
    assert((cancel_detail&APR_PATH_FORCE) && !c.path && path.refs==1);

    /* A live replacement receives callbacks/sends without being cancelled.
       A later old-connection cancel must target exactly the caller's object. */
    struct Connection replacement={.endpoint=&courier,.path=&path};
    install(&replacement,90);
    errno=EDOM;replacement.handler(nw_connection_state_ready,NULL);
    assert(handler_tag==90 && handler_state==nw_connection_state_ready);
    expected_connection=&replacement;errno=EDOM;apr_nw_start(&replacement);
    assert(errno==EBUSY && replacement.path==&path && force_calls==force_before+1);
    expected_connection=&c;errno=EDOM;apr_nw_cancel(&c); /* missing old path still retires */
    assert(errno==EBUSY && cancel_detail==(APR_PATH_SEEN|APR_PATH_FORCE));
    assert(replacement.path==&path && force_calls==force_before+2 && immediate_requests==2);
    assert(normal_requests==4);
    errno=EDOM;replacement.handler(nw_connection_state_ready,NULL);
    assert(handler_tag==90 && replacement.path==&path); /* handler untouched */
    expected_connection=&replacement;errno=EDOM;apr_nw_state_handler(&replacement,NULL);
    assert(errno==EBUSY && !replacement.handler);

    /* Disabled mode and a missing trampoline preserve normal cancellation. */
    expected_connection=&c;apr_original_nw_force_cancel=NULL;c.path=&path;
    errno=EDOM;apr_nw_cancel(&c);
    assert(errno==EBUSY && cancel_action==APR_CANCEL_UNAVAILABLE);
    assert(cancel_calls==normal_before+1 && immediate_requests==2 && normal_requests==5);
    apr_original_nw_force_cancel=original_force;enabled=false;c.path=&path;
    errno=EDOM;apr_nw_cancel(&c);
    assert(errno==EBUSY && cancel_action==APR_CANCEL_NATIVE && normal_requests==6);
    assert(cancel_calls==normal_before+2 && force_calls==force_before+2);

    /* Unmatched traffic stays normal in enabled mode. */
    enabled=true;expected_connection=&other;other.path=&path;
    errno=EDOM;apr_nw_cancel(&other);
    assert(errno==EBUSY && cancel_calls==normal_before+3 && normal_requests==6);
    assert(force_calls==force_before+2 && path.refs==1);

    /* Explicit force-cancel is counted separately and forwarded once. */
    expected_connection=&c;c.path=&path;errno=EDOM;apr_nw_force_cancel(&c);
    assert(errno==EBUSY && app_force_requests==2 && normal_requests==6);
    assert(cancel_action==APR_CANCEL_APP_FORCE && force_calls==force_before+3);

    /* Internal synchronous cancel delegation cannot recurse into force-cancel. */
    nested_cancel=true;c.path=&path;errno=EDOM;apr_nw_cancel(&c);
    assert(errno==EBUSY && normal_requests==7 && immediate_requests==3);
    assert(force_calls==force_before+4 && cancel_calls==normal_before+4);
    errno=EDOM;apr_nw_force_cancel(&c);
    assert(errno==EBUSY && app_force_requests==3 && normal_requests==7);
    assert(force_calls==force_before+5 && cancel_calls==normal_before+5);
    /* Autonomous retirement requests endpoint failure/fallback, never terminal
       force-cancel or synthetic state callbacks. Internal delegation is native. */
    int handlers_before=handler_calls;
    assert(apr_nw_retirement_available());
    errno=EDOM;apr_nw_retire(&c);
    assert(errno==EBUSY && app_force_requests==3 && normal_requests==7);
    assert(endpoint_requests==1 && force_calls==force_before+5 && cancel_calls==normal_before+6);
    nested_cancel=false;
    errno=EDOM;apr_nw_retire(&c);
    assert(errno==EBUSY && endpoint_requests==2 && force_calls==force_before+5 && cancel_calls==normal_before+6);
    missing_endpoint=true;apr_nw_observer_init();assert(!apr_nw_retirement_available());
    errno=EDOM;apr_nw_retire(&c);assert(errno==EDOM);
    assert(endpoint_requests==2 && force_calls==force_before+5 && cancel_calls==normal_before+6);
    assert(handler_calls==handlers_before && app_force_requests==3 && normal_requests==7);
    assert(send_calls==7 && courier.refs==1 && init.refs==1 && path.refs==1);
    receive_tests(&c,&other,&path);
    assert(courier.refs==1 && init.refs==1 && path.refs==1);
    assert(retire_starts==2 && retire_states && retire_forgets);
    puts("PASS: actual escaping Blocks, callback replacement/removal and cancellation, exact arguments/errno, public-only report gating, cancellation upgrade/fallback/reentry and live replacement preservation");
}
