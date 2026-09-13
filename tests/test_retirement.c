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

struct TestPath {int tag,refs;nw_path_status_t status;bool wifi,cell;};
struct TestMonitor {int tag,refs;void (^handler)(nw_path_t);};
struct Object {int tag,refs;uint32_t id,handler;nw_path_t path;unsigned requests;};
static struct TestMonitor test_monitor={2,1,NULL};
static struct TestPath cell={3,1,nw_path_status_satisfied,false,true};
static struct TestPath wifi={3,1,nw_path_status_satisfied,true,false};
static struct TestPath mixed={3,1,nw_path_status_satisfied,true,true};
static struct TestPath loop={3,1,nw_path_status_satisfied,false,false};
static APRRetirementStatus snapshot;
static unsigned monitor_starts,queues,queue_releases,request_calls,request_ids[32];
static bool queue_fail,monitor_fail,clock_fail,probe_reentry,defer_result;
static struct Object *spawn_on_request;
static uint64_t test_time=UINT64_C(1000000000),timer_when;
static void (*timer_callback)(void *),(*work_callback)(void *);
static void *timer_context,*work_context;
static void request_endpoint(nw_connection_t);

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
    assert(q==(void *)1 && !timer_callback);timer_when=when;timer_callback=function;timer_context=context;
}
void dispatch_async_f(dispatch_queue_t q,void *context,void (*function)(void *)) {
    assert(q==(void *)1 && !work_callback);work_callback=function;work_context=context;
}
nw_path_status_t nw_path_get_status(nw_path_t p) {assert(p->refs>0);errno=EIO;return p->status;}
bool nw_path_uses_interface_type(nw_path_t p,nw_interface_type_t type) {
    assert(p->refs>0);return type==nw_interface_type_wifi?p->wifi:type==nw_interface_type_cellular?p->cell:false;
}
nw_path_t nw_connection_copy_current_path(nw_connection_t object) {
    struct Object *c=object;assert(c->refs>0);
    if(probe_reentry)apr_retirement_received(c->id); /* Nested sample must coalesce. */
    if(c->path)nw_retain(c->path);return c->path;
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
int main(int argc,char **argv) {
    assert(argc==2);bool disabled=!strcmp(argv[1],"disabled"),missing=!strcmp(argv[1],"missing");
    queue_fail=!strcmp(argv[1],"queue-failure");monitor_fail=!strcmp(argv[1],"monitor-failure");
    errno=EDOM;apr_retirement_init(!disabled,missing?NULL:request_endpoint);assert(errno==EDOM);
    if(disabled || missing || queue_fail || monitor_fail) {
        assert(!monitor_starts && !snapshot.held && !request_calls);
        assert(snapshot.status==(disabled?APR_RET_DISABLED:APR_RET_UNAVAILABLE));
        assert(queues==(unsigned)(queue_fail || monitor_fail));
        assert(queue_releases==(unsigned)monitor_fail);
        puts("PASS: retirement disabled/unavailable initialization has no connection side effects");return 0;
    }
    assert(monitor_starts==1 && snapshot.status==APR_RET_WAITING);
    apr_retirement_init(true,request_endpoint);assert(monitor_starts==1); /* once only */
    struct Object a={1,1,1,1,&cell,0},b={1,1,2,2,&wifi,0},c={1,1,3,3,&cell,0};
    ready(&a);assert(a.refs==2);change(&cell);
    assert(snapshot.epoch==1 && snapshot.network==APR_RET_CELLULAR && !snapshot.pending && !timer_callback);
    change(&cell);assert(!timer_callback && !request_calls);
    change(&wifi);assert(snapshot.epoch==2 && snapshot.pending==1 && timer_callback);
    ready(&b);assert(b.refs==2 && snapshot.pending==1);
    apr_retirement_received(a.id);assert(!work_callback); /* old data cannot protect reuse */
    b.path=&loop;apr_retirement_received(b.id);assert(!work_callback); /* init-like loopback not proof */
    b.path=&wifi;probe_reentry=true;errno=EDOM;apr_retirement_received(b.id);
    assert(errno==EDOM && work_callback);probe_reentry=false;
    apr_retirement_received(b.id); /* work coalesces */
    struct Object replacement={1,1,21,21,&wifi,0};spawn_on_request=&replacement;
    fire_work();assert(a.requests==1 && a.refs==1 && !b.requests && b.refs==2);
    assert(replacement.refs==2 && !replacement.requests);apr_retirement_forget(replacement.id);
    assert(replacement.refs==1);
    assert(snapshot.requests==1 && snapshot.reason==APR_RET_NEW_DATA && !snapshot.pending && request_ids[1]==1);
    fire_timer();assert(request_calls==1 && !timer_callback);
    /* A fresh spare opened on Wi-Fi must not become exempt from the next
       transition merely because its connection path says cellular. */
    ready(&c);change(&cell);assert(snapshot.epoch==3 && snapshot.pending==2);
    struct Object d={1,1,4,4,&cell,0};ready(&d);
    fire_timer();assert(b.requests==1 && c.requests==1 && !d.requests);
    assert(b.refs==1 && c.refs==1 && d.refs==2 && snapshot.reason==APR_RET_DEADLINE);
    assert(snapshot.requests==3 && snapshot.held==1);
    /* Natural cancellation, terminal callbacks, and handler clear release the
       owned reference and prevent later automatic cancellation. */
    apr_retirement_forget(d.id);assert(d.refs==1 && !snapshot.held);
    struct Object e={1,1,5,5,&cell,0};ready(&e);
    apr_retirement_handler(e.id,6);apr_retirement_state(e.id,5,nw_connection_state_cancelled);
    assert(e.refs==2);apr_retirement_state(e.id,6,nw_connection_state_failed);assert(e.refs==1);
    ready(&e);apr_retirement_handler(e.id,0);assert(e.refs==1);
    /* A start before a transition that only reaches readiness afterward is
       protected. An old ready connection remains eligible despite a repeat start. */
    struct Object f={1,1,6,6,&cell,0},g={1,1,7,7,&wifi,0};ready(&f);
    apr_retirement_start(&g,g.id,g.handler);change(&wifi);
    apr_retirement_state(g.id,g.handler,nw_connection_state_ready);
    apr_retirement_start(&f,f.id,f.handler);assert(snapshot.pending==1);
    apr_retirement_received(g.id);assert(work_callback);
    /* A flap invalidates queued early-cleanup evidence. One delayed callback
       survives and reschedules to the latest transition deadline. */
    test_time+=UINT64_C(1000000000);change(&cell);
    struct Object h={1,1,8,8,&cell,0};ready(&h);
    fire_work();assert(!f.requests && !g.requests && !h.requests);
    fire_timer();assert(timer_callback && !f.requests); /* original earlier deadline */
    fire_timer();assert(f.requests==1 && g.requests==1 && !h.requests && h.refs==2);
    /* Unknown/mixed/unsatisfied monitor paths suspend retirement. */
    change(&wifi);change(&mixed);assert(!snapshot.network);
    fire_timer();assert(!h.requests && !timer_callback);
    change(NULL);wifi.status=nw_path_status_unsatisfied;change(&wifi);
    assert(!h.requests && !timer_callback && !snapshot.network);wifi.status=nw_path_status_satisfied;
    change(&wifi);assert(timer_callback);fire_timer();assert(h.requests==1);
    /* No unbounded ownership on capacity/ID/handler failures. */
    struct Object many[9];
    for(unsigned i=0;i<9;++i) {many[i]=(struct Object){1,1,10+i,10+i,&wifi,0};ready(&many[i]);}
    assert(snapshot.held==8 && snapshot.skipped==1 && many[8].refs==1);
    apr_retirement_start(&many[8],0,1);apr_retirement_start(&many[8],19,0);
    assert(snapshot.skipped==3 && many[8].refs==1);
    for(unsigned i=0;i<8;++i) apr_retirement_forget(many[i].id);
    assert(!snapshot.held);
    /* Endpoint fallback can retain the NW object while replacing its TCP
       transport. Keep ownership across the request; do not retry while native
       recovery is outstanding, even if another network change occurs. */
    struct Object fallback={1,1,22,22,&wifi,0};ready(&fallback);defer_result=true;
    change(&cell);fire_timer();
    assert(fallback.requests==1 && fallback.refs==2 && snapshot.held==1);
    assert(snapshot.awaiting==1 && !snapshot.pending && snapshot.status==APR_RET_RECOVERING);
    change(&wifi);assert(!timer_callback && fallback.requests==1 && snapshot.awaiting==1);
    apr_retirement_state(fallback.id,fallback.handler,nw_connection_state_waiting);
    assert(snapshot.awaiting==1);
    apr_retirement_state(fallback.id,fallback.handler,nw_connection_state_ready);
    assert(!snapshot.awaiting && !snapshot.pending && snapshot.status==APR_RET_IDLE);
    change(&cell);fire_timer();assert(fallback.requests==2 && snapshot.awaiting==1);
    apr_retirement_forget(fallback.id);assert(fallback.refs==1 && !snapshot.held && !snapshot.awaiting);
    apr_retirement_state(fallback.id,fallback.handler,nw_connection_state_ready);
    assert(!snapshot.held);defer_result=false;
    change(&wifi);
    /* Clock failure relinquishes owned references without forced teardown. */
    struct Object j={1,1,20,20,&wifi,0};ready(&j);clock_fail=true;change(&cell);
    assert(snapshot.status==APR_RET_UNAVAILABLE && snapshot.error==EIO && j.refs==1 && !j.requests);
    assert(!snapshot.held);
    if(timer_callback)fire_timer();
    if(work_callback)fire_work();
    assert(cell.refs==1 && wifi.refs==1 && loop.refs==1 && mixed.refs==1);
    Block_release(test_monitor.handler);nw_release(&test_monitor);dispatch_release((void *)1);
    assert(test_monitor.refs==0);
    puts("PASS: real monitor Block, endpoint fallback/rearming, bidirectional requests, fresh/spare generations, reentry, lifetimes, bounded scheduling, flaps, native closures, capacity and failure rollback");
}
