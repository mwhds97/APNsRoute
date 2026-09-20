#define _POSIX_C_SOURCE 200809L
#include <Network/Network.h>
#include <Block.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../src/Retirement.h"
#include "../src/Diagnostics.h"
#include "../src/TunnelSelector.h"

struct TestPath {int tag,refs;nw_path_status_t status;bool wifi,cell;};
struct TestMonitor {int tag,refs;void (^handler)(nw_path_t);};
struct Object {int tag,refs;uint32_t id,handler;nw_path_t path;unsigned requests;};
static struct TestMonitor test_monitor={2,1,NULL};
static struct TestPath cell={3,1,nw_path_status_satisfied,false,true};
static struct TestPath wifi={3,1,nw_path_status_satisfied,true,false};
static struct TestPath mixed={3,1,nw_path_status_satisfied,true,true};
static APRRetirementStatus snapshot;
static unsigned monitor_starts,queues,queue_releases,request_calls,request_ids[32];
static bool queue_fail,monitor_fail,clock_fail,defer_result;
static struct Object *spawn_on_request;
static uint64_t test_time=UINT64_C(1000000000),timer_when;
static void (*timer_callback)(void *),(*work_callback)(void *);
static void *timer_context,*work_context;
static void request_endpoint(nw_connection_t);
static void vpn_tick(void *);
static void (*vpn_callback)(void *);
static uint64_t vpn_when;
static void (^network_notification)(int);
static uint32_t registration_error;
static unsigned snapshots;
static enum apr_tunnel_choice tunnel_choice=APR_TUN_NONE;
static APRTunnel test_tunnel;
static int tunnel_error;
enum apr_tunnel_choice apr_tunnel_select(unsigned family,APRTunnel *out,int *error) {
    assert(!family);++snapshots;*out=test_tunnel;*error=tunnel_error;return tunnel_choice;
}
uint32_t notify_register_dispatch(const char *name,int *token,dispatch_queue_t q,void (^handler)(int)) {
    assert(!strcmp(name,"com.apple.system.config.network_change") && q==(void *)1 && !network_notification);
    if(registration_error)return registration_error;
    *token=73;network_notification=Block_copy(handler);errno=EIO;return 0;
}

void apr_diag_retirement(const APRRetirementStatus *s) {snapshot=*s;errno=EIO;}
void apr_connection_retire_requested(uint32_t id) {assert(id<32);++request_ids[id];errno=EIO;}
void nw_retain(void *object) {
    int *v=object;assert(v && v[1]>0);++v[1];errno=EIO;
}
void nw_release(void *object) {
    int *v=object;assert(v && v[1]>0);--v[1];errno=EIO;
}
nw_path_monitor_t nw_path_monitor_create(void) {errno=EIO;return monitor_fail?NULL:&test_monitor;}
void nw_path_monitor_set_queue(nw_path_monitor_t m,dispatch_queue_t q) {
    assert(m==&test_monitor && q==(void *)1);errno=EIO;
}
void nw_path_monitor_set_update_handler(nw_path_monitor_t m,void (^handler)(nw_path_t)) {
    assert(m==&test_monitor && !m->handler);m->handler=Block_copy(handler);errno=EIO;
}
void nw_path_monitor_start(nw_path_monitor_t m) {assert(m==&test_monitor && m->handler);++monitor_starts;errno=EIO;}
dispatch_queue_t dispatch_queue_create(const char *label,void *attr) {
    assert(!strcmp(label,"local.apnsroute.retirement") && !attr);++queues;errno=EIO;return queue_fail?NULL:(void *)1;
}
void dispatch_release(void *queue) {assert(queue==(void *)1);++queue_releases;errno=EIO;}
dispatch_time_t dispatch_time(dispatch_time_t base,int64_t delta) {
    assert(!base && delta>=0);return test_time+(uint64_t)delta;
}
void dispatch_after_f(dispatch_time_t when,dispatch_queue_t q,void *context,void (*function)(void *)) {
    if(function==vpn_tick) {assert(q==(void *)1 && !context && !vpn_callback);vpn_when=when;vpn_callback=function;return;}
    assert(q==(void *)1 && !timer_callback);timer_when=when;timer_callback=function;timer_context=context;
}
void dispatch_async_f(dispatch_queue_t q,void *context,void (*function)(void *)) {
    if(function==vpn_tick) {assert(q==(void *)1 && !context && !vpn_callback);vpn_when=test_time;vpn_callback=function;return;}
    assert(q==(void *)1 && !work_callback);work_callback=function;work_context=context;
}
nw_path_status_t nw_path_get_status(nw_path_t p) {assert(p->refs>0);errno=EIO;return p->status;}
bool nw_path_uses_interface_type(nw_path_t p,nw_interface_type_t type) {
    assert(p->refs>0);return type==nw_interface_type_wifi?p->wifi:type==nw_interface_type_cellular?p->cell:false;
}
static int test_clock(clockid_t clock,struct timespec *now) {
    assert(clock==CLOCK_MONOTONIC);
    if(clock_fail) {errno=EIO;return -1;}
    now->tv_sec=(time_t)(test_time/UINT64_C(1000000000));now->tv_nsec=(long)(test_time%UINT64_C(1000000000));return 0;
}
#define clock_gettime test_clock
#include "../src/Retirement.c"
#undef clock_gettime
static void request_endpoint(nw_connection_t object) {
    struct Object *c=object;assert(c->refs>0);
    assert(pthread_mutex_trylock(&retirement_lock)==0);pthread_mutex_unlock(&retirement_lock);
    assert(test_time>=deadline && snapshot.quiet_state==APR_QUIET_IDLE && observations_known());
    ++c->requests;++request_calls;
    /* Network may synchronously re-enter callback/forget paths. The reference
       must remain alive throughout, without a held registry lock. */
    if(!defer_result) {
        apr_retirement_state(c->id,c->handler,nw_connection_state_failed);
        apr_retirement_forget(c->id);
    }
    assert(c->refs>0);errno=EBUSY;
    if(spawn_on_request) {
        struct Object *fresh=spawn_on_request;spawn_on_request=NULL;
        apr_retirement_start(fresh,fresh->id,fresh->handler);
        apr_retirement_state(fresh->id,fresh->handler,nw_connection_state_ready);
    }
}
static void change(nw_path_t p) {errno=EDOM;test_monitor.handler(p);assert(errno==EDOM);}
static void ready(struct Object *c) {
    errno=EDOM;apr_retirement_start(c,c->id,c->handler);assert(errno==EDOM);
    apr_retirement_state(c->id,c->handler,nw_connection_state_ready);assert(errno==EDOM);
}
static void fire_timer(void) {
    assert(timer_callback);if(test_time<timer_when)test_time=timer_when;
    void (*callback)(void *)=timer_callback;timer_callback=NULL;
    errno=EDOM;callback(timer_context);assert(errno==EDOM);
}
static void fire_work(void) {
    assert(work_callback);void (*callback)(void *)=work_callback;work_callback=NULL;
    errno=EDOM;callback(work_context);assert(errno==EDOM);
}
static void fire_vpn(void) {
    assert(vpn_callback);if(test_time<vpn_when)test_time=vpn_when;
    void (*callback)(void *)=vpn_callback;vpn_callback=NULL;
    errno=EDOM;callback(NULL);assert(errno==EDOM);
}
static void tunnel(enum apr_tunnel_choice choice,uint32_t index) {
    tunnel_choice=choice;test_tunnel=(APRTunnel){.index=index,.families=APR_TUN_V4,.count=index?1:0};
    if(index)snprintf(test_tunnel.name,sizeof(test_tunnel.name),"utun%u",index);
    tunnel_error=choice==APR_TUN_UNAVAILABLE?EACCES:0;
    if(network_notification) {errno=EDOM;network_notification(73);assert(errno==EDOM);}
    else fire_vpn();
}
static void baseline(void) {
    fire_vpn();change(&cell);
    assert(snapshot.epoch==1 && snapshot.vpn_epoch==1 && !snapshot.quiet_epoch && !timer_callback);
}
static void settle(void) {
    unsigned limit=0;
    while(timer_callback || work_callback) {
        assert(++limit<10);
        if(work_callback)fire_work();else fire_timer();
    }
}
static void cleanup(void) {
    for(unsigned i=0;i<RETIRE_LIMIT;++i) if(held[i].id)apr_retirement_forget(held[i].id);
    if(work_callback)fire_work();
    if(timer_callback)fire_timer();
    assert(!snapshot.held && cell.refs==1 && wifi.refs==1 && mixed.refs==1);
    if(network_notification)Block_release(network_notification);
    Block_release(test_monitor.handler);nw_release(&test_monitor);dispatch_release((void *)1);
}
static void test_burst(void) {
    baseline();
    struct Object a={1,1,1,1,&cell,0},b={1,1,2,2,&cell,0},opening={1,1,3,3,&cell,0};
    struct Object mid={1,1,4,4,&wifi,0},fresh={1,1,5,5,&wifi,0},replacement={1,1,6,6,&wifi,0};
    ready(&a);ready(&b);apr_retirement_start(&opening,opening.id,opening.handler);
    uint64_t start=test_time;change(&wifi);
    assert(snapshot.quiet_events==1 && timer_when==start+QUIET_NS && !request_calls && !work_callback);
    test_time+=UINT64_C(400000000);tunnel(APR_TUN_NONE,0);
    ready(&mid);test_time+=UINT64_C(500000000);tunnel(APR_TUN_UNIQUE,8);
    uint64_t last=test_time;ready(&fresh);
    apr_retirement_state(opening.id,opening.handler,nw_connection_state_ready);
    apr_retirement_start(&a,a.id,a.handler); /* repeated start must not refresh age */
    assert(snapshot.quiet_epoch==1 && snapshot.quiet_events==3 && snapshot.quiet_causes==7);
    assert(!request_calls && !work_callback && snapshot.pending==4);
    fire_timer(); /* timer for first change is now too early */
    assert(test_time==start+QUIET_NS && !request_calls && timer_when==last+QUIET_NS);
    /* An early timer/work callback cannot round a sub-millisecond remainder down. */
    test_time=last+QUIET_NS-1;
    void (*early)(void *)=timer_callback;timer_callback=NULL;errno=EDOM;early(NULL);assert(errno==EDOM);
    assert(!request_calls && snapshot.quiet_remaining_ms==1 && timer_when==last+QUIET_NS);
    spawn_on_request=&replacement;fire_timer();
    assert(test_time==last+QUIET_NS && snapshot.batches==1 && snapshot.requests==4);
    assert(a.requests==1 && b.requests==1 && opening.requests==1 && mid.requests==1);
    assert(a.refs==1 && b.refs==1 && opening.refs==1 && mid.refs==1);
    assert(!fresh.requests && !replacement.requests && fresh.refs==2 && replacement.refs==2);
    assert(snapshot.quiet_state==APR_QUIET_IDLE && !snapshot.pending && !snapshot.vpn_pending);
    change(&wifi);tunnel(APR_TUN_UNIQUE,8);fire_vpn();
    assert(!timer_callback && !work_callback && snapshot.quiet_events==3 && snapshot.batches==1);
    /* Reverse physical direction, with off/on again, forms one further batch. */
    change(&cell);test_time+=UINT64_C(400000000);tunnel(APR_TUN_NONE,0);
    test_time+=UINT64_C(600000000);tunnel(APR_TUN_UNIQUE,9);settle();
    assert(snapshot.quiet_epoch==2 && snapshot.quiet_events==3 && snapshot.batches==2);
    assert(fresh.requests==1 && replacement.requests==1 && !snapshot.held);
    puts("PASS: network/off/on burst in both directions, shared two-second minimum, stale/early timer recheck, one batch, mid-switch and fresh records, native reentry");
}
static void test_vpn(void) {
    baseline();struct Object a={1,1,1,1,&cell,0};ready(&a);
    tunnel(APR_TUN_NONE,0);assert(timer_callback && !work_callback && !request_calls);
    uint64_t last=test_time;fire_timer();assert(test_time==last+QUIET_NS && a.requests==1 && a.refs==1);
    ready(&a);tunnel(APR_TUN_UNIQUE,8);last=test_time;fire_timer();
    assert(test_time==last+QUIET_NS && a.requests==2 && snapshot.batches==2 && snapshot.epoch==1);
    ready(&a);tunnel(APR_TUN_UNIQUE,9);last=test_time;fire_timer();
    assert(test_time==last+QUIET_NS && a.requests==3 && snapshot.reason==APR_RET_VPN_REPLACED);
    puts("PASS: isolated same-network VPN off/on/replacement all wait at least two seconds");
}
static void test_unknown(void) {
    baseline();struct Object a={1,1,1,1,&cell,0};ready(&a);
    change(&wifi);test_time+=UINT64_C(500000000);change(&mixed);fire_timer();
    assert(!request_calls && snapshot.quiet_state==APR_QUIET_BLOCKED && !timer_callback);
    test_time+=UINT64_C(5000000000);fire_vpn();assert(!request_calls && !timer_callback);
    change(&wifi);uint64_t resumed=test_time;
    assert(timer_when==resumed+QUIET_NS && snapshot.quiet_epoch==1);
    test_time+=UINT64_C(500000000);tunnel(APR_TUN_UNAVAILABLE,0);
    assert(snapshot.vpn_epoch==1 && snapshot.vpn_error==EACCES);fire_timer();
    assert(!request_calls && snapshot.quiet_state==APR_QUIET_BLOCKED);
    tunnel(APR_TUN_AMBIGUOUS,9);fire_timer();assert(!request_calls && snapshot.vpn_epoch==1);
    tunnel(APR_TUN_UNIQUE,7);resumed=test_time;fire_timer();
    assert(test_time==resumed+QUIET_NS && a.requests==1 && a.refs==1 && snapshot.batches==1);
    puts("PASS: lost/ambiguous observations block every automatic request; recovery requires a new full quiet period and no false VPN-off");
}
static void test_recovery(void) {
    baseline();struct Object a={1,1,1,1,&cell,0};ready(&a);defer_result=true;
    tunnel(APR_TUN_NONE,0);fire_timer();assert(a.requests==1 && snapshot.awaiting==1 && a.refs==2);
    tunnel(APR_TUN_UNIQUE,8);test_time+=UINT64_C(500000000);change(&wifi);
    apr_retirement_state(a.id,a.handler,nw_connection_state_ready);
    assert(!work_callback && !snapshot.awaiting && snapshot.pending==1);
    fire_timer();assert(a.requests==1 && timer_callback);fire_timer();
    assert(a.requests==2 && snapshot.awaiting==1 && snapshot.batches==2);
    tunnel(APR_TUN_NONE,0);tunnel(APR_TUN_UNIQUE,9);settle();
    assert(a.requests==2 && snapshot.awaiting==1); /* do not duplicate outstanding request */
    apr_retirement_state(a.id,a.handler,nw_connection_state_waiting);assert(!work_callback);
    apr_retirement_state(a.id,a.handler,nw_connection_state_ready);assert(work_callback);
    /* A new event after work is queued must still postpone the actual call. */
    tunnel(APR_TUN_NONE,0);uint64_t last=test_time;fire_work();
    assert(a.requests==2 && timer_callback);fire_timer();
    assert(test_time==last+QUIET_NS && a.requests==3 && snapshot.awaiting==1);
    apr_retirement_state(a.id,a.handler,nw_connection_state_ready);assert(!work_callback && !snapshot.pending);
    apr_retirement_forget(a.id);assert(a.refs==1 && !snapshot.held);defer_result=false;
    puts("PASS: awaiting recovery, later generations, readiness and stale queued work never bypass the shared quiet gate");
}
static void test_opening(void) {
    baseline();struct Object a={1,1,1,1,&cell,0},fresh={1,1,2,2,&wifi,0};
    apr_retirement_start(&a,a.id,a.handler);tunnel(APR_TUN_NONE,0);fire_timer();
    assert(!request_calls && snapshot.vpn_pending==1 && snapshot.quiet_state==APR_QUIET_IDLE);
    apr_retirement_state(a.id,a.handler,nw_connection_state_ready);assert(work_callback);
    tunnel(APR_TUN_UNIQUE,8);uint64_t last=test_time;ready(&fresh);fire_work();
    assert(!request_calls);fire_timer();assert(test_time==last+QUIET_NS && a.requests==1 && !fresh.requests);
    apr_retirement_forget(fresh.id);assert(fresh.refs==1);
    /* Physical handover still protects first readiness on the new network. */
    struct Object physical={1,1,3,3,&wifi,0};apr_retirement_start(&physical,physical.id,physical.handler);
    change(&wifi);apr_retirement_state(physical.id,physical.handler,nw_connection_state_ready);fire_timer();
    assert(!physical.requests && snapshot.batches==1);apr_retirement_forget(physical.id);
    puts("PASS: late in-flight readiness waits for any new quiet deadline; current-generation starts and first physical readiness are protected");
}
static void test_preflight(void) {
    baseline();struct Object a={1,1,1,1,&cell,0};ready(&a);change(&wifi);
    tunnel_choice=APR_TUN_NONE;test_tunnel=(APRTunnel){0}; /* no delivered event/poll */
    fire_timer();uint64_t observed=test_time;assert(!request_calls && timer_when==observed+QUIET_NS);
    tunnel_choice=APR_TUN_UNIQUE;test_tunnel=(APRTunnel){.name="utun8",.index=8,.count=1,.families=APR_TUN_V4};
    fire_timer();observed=test_time;assert(!request_calls && timer_when==observed+QUIET_NS);
    fire_timer();assert(test_time==observed+QUIET_NS && a.requests==1 && snapshot.batches==1);
    assert(snapshot.quiet_events==3);
    puts("PASS: pre-cleanup tunnel snapshot catches missed off/on hints and starts a full new quiet period");
}
static void test_polling(void) {
    baseline();assert(snapshot.vpn_notify==2 && snapshot.vpn_notify_error==9 && !network_notification);
    struct Object a={1,1,1,1,&cell,0};ready(&a);
    tunnel_choice=APR_TUN_NONE;test_tunnel=(APRTunnel){0};fire_vpn();
    assert(timer_callback && !request_calls);
    tunnel_choice=APR_TUN_UNIQUE;test_tunnel=(APRTunnel){.name="utun8",.index=8,.count=1,.families=APR_TUN_V4};
    fire_vpn();uint64_t last=test_time;fire_timer();assert(!request_calls);fire_timer();
    assert(test_time==last+QUIET_NS && a.requests==1 && snapshot.batches==1 && snapshot.quiet_events==2);
    puts("PASS: denied network notifications retain polling and shared debounce");
}
static void test_baseline(void) {
    struct Object a={1,1,1,1,&cell,0};ready(&a);fire_vpn();
    assert(!snapshot.vpn_epoch && !timer_callback && !work_callback);
    tunnel(APR_TUN_UNIQUE,7);assert(snapshot.vpn_epoch==1 && !timer_callback && !a.requests);
    tunnel(APR_TUN_NONE,0);uint64_t last=test_time;fire_timer();
    assert(test_time==last+QUIET_NS && a.requests==1 && !snapshot.epoch);
    puts("PASS: unavailable startup and first VPN baseline are nondestructive; later off observes the same quiet gate before physical baseline");
}
static void test_lifetimes(void) {
    baseline();struct Object many[9];
    for(unsigned i=0;i<9;++i) {many[i]=(struct Object){1,1,10+i,10+i,&cell,0};ready(&many[i]);}
    assert(snapshot.held==8 && snapshot.skipped==1 && many[8].refs==1);
    apr_retirement_start(&many[8],0,1);apr_retirement_start(&many[8],19,0);assert(snapshot.skipped==3);
    apr_retirement_handler(10,20);apr_retirement_state(10,10,nw_connection_state_failed);assert(many[0].refs==2);
    apr_retirement_state(10,20,nw_connection_state_failed);assert(many[0].refs==1);
    apr_retirement_handler(11,0);apr_retirement_forget(12);assert(many[1].refs==1 && many[2].refs==1);
    change(&wifi);apr_retirement_state(13,13,nw_connection_state_cancelled);assert(many[3].refs==1);
    fire_timer();assert(request_calls==4 && snapshot.batches==1 && !snapshot.held);
    for(unsigned i=0;i<9;++i)assert(many[i].refs==1);
    puts("PASS: bounded ownership, handler replacement/clear, stale native callbacks, capacity, owner and natural closures before coalesced cleanup");
}
static void test_failure(const char *scenario) {
    baseline();struct Object a={1,1,1,1,&cell,0};ready(&a);
    if(!strcmp(scenario,"clock-failure")) {clock_fail=true;change(&wifi);assert(snapshot.error==EIO);}
    else {
        if(!strcmp(scenario,"physical-overflow")) {report.epoch=UINT32_MAX;change(&wifi);}
        else if(!strcmp(scenario,"vpn-overflow")) {report.vpn_epoch=UINT32_MAX;tunnel(APR_TUN_NONE,0);}
        else {report.quiet_epoch=UINT32_MAX;change(&wifi);}
        assert(snapshot.error==EOVERFLOW);
    }
    assert(snapshot.status==APR_RET_UNAVAILABLE && !snapshot.held && !a.requests && a.refs==1);
    fire_vpn();assert(!vpn_callback);
    puts("PASS: clock/generation failure releases references without teardown");
}
int main(int argc,char **argv) {
    assert(argc==2);const char *scenario=argv[1];
    bool disabled=!strcmp(scenario,"disabled"),missing=!strcmp(scenario,"missing");
    queue_fail=!strcmp(scenario,"queue-failure");monitor_fail=!strcmp(scenario,"monitor-failure");
    registration_error=!strcmp(scenario,"vpn-notify-failure")?9:0;
    tunnel_choice=!strcmp(scenario,"vpn-baseline")?APR_TUN_UNAVAILABLE:APR_TUN_UNIQUE;
    test_tunnel=(APRTunnel){.name="utun7",.index=7,.families=APR_TUN_V4,.count=1};
    errno=EDOM;apr_retirement_init(!disabled,missing?NULL:request_endpoint);assert(errno==EDOM);
    if(disabled || missing || queue_fail || monitor_fail) {
        assert(!monitor_starts && !snapshot.held && !request_calls && !snapshots && !vpn_callback && !network_notification);
        assert(snapshot.status==(disabled?APR_RET_DISABLED:APR_RET_UNAVAILABLE));
        assert(queues==(unsigned)(queue_fail || monitor_fail) && queue_releases==(unsigned)monitor_fail);
        puts("PASS: disabled/unavailable startup has no monitoring or connection side effects");return 0;
    }
    apr_retirement_init(true,request_endpoint);assert(monitor_starts==1);
    if(!strcmp(scenario,"main"))test_burst();
    else if(!strcmp(scenario,"vpn"))test_vpn();
    else if(!strcmp(scenario,"unknown"))test_unknown();
    else if(!strcmp(scenario,"recovery"))test_recovery();
    else if(!strcmp(scenario,"opening"))test_opening();
    else if(!strcmp(scenario,"preflight"))test_preflight();
    else if(!strcmp(scenario,"vpn-notify-failure"))test_polling();
    else if(!strcmp(scenario,"vpn-baseline"))test_baseline();
    else if(!strcmp(scenario,"lifetimes"))test_lifetimes();
    else test_failure(scenario);
    cleanup();return 0;
}
