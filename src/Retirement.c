/* Retire connections established before an observed Wi-Fi/cellular transition.
   The registry holds eight references at most. An endpoint-request batch
   temporarily owns up to eight more; only one current-path sample runs at once.
   One monitor, one delayed callback and one coalesced work callback are used.
   No app queues or NECP output change. Requests/releases run outside the mutex. */
#include "Retirement.h"
#include "Connections.h"
#include "Diagnostics.h"
#include <dispatch/dispatch.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#define RETIRE_WINDOW_NS UINT64_C(3000000000)
#define RETIRE_LIMIT APR_CONNECTION_COUNT
typedef struct {
    nw_connection_t connection;
    uint32_t id,handler,ready_epoch;
    bool ready,ever_ready,awaiting;
} HeldConnection;
static HeldConnection held[RETIRE_LIMIT];
static pthread_mutex_t retirement_lock=PTHREAD_MUTEX_INITIALIZER;
static dispatch_queue_t retirement_queue;
static nw_path_monitor_t monitor;
static APRRetireFunction request_endpoint_cancellation;
static APRRetirementStatus report;
static bool initialized,active,timer_scheduled,work_scheduled,sample_busy;
static uint32_t last_network,fresh_epoch;
static uint64_t deadline;

static void increment(uint32_t *value) {if(*value!=UINT32_MAX) ++*value;}
static unsigned find_id(uint32_t id) {
    if(id) for(unsigned i=0;i<RETIRE_LIMIT;++i) if(held[i].id==id) return i;
    return RETIRE_LIMIT;
}
/* Caller holds retirement_lock. Transfer the reference for release outside it. */
static nw_connection_t detach_connection(unsigned slot) {
    nw_connection_t connection=held[slot].connection;
    held[slot]=(HeldConnection){0};
    return connection;
}
static bool should_retire(const HeldConnection *entry) {
    return entry->id && entry->ever_ready && !entry->awaiting && entry->ready_epoch && entry->ready_epoch<report.epoch;
}
static void publish(void) {
    report.held=0;
    report.pending=0;
    report.awaiting=0;
    for(unsigned i=0;i<RETIRE_LIMIT;++i) if(held[i].id) {
        ++report.held;
        if(should_retire(&held[i])) ++report.pending;
        if(held[i].awaiting) ++report.awaiting;
    }
    if(active) report.status=!report.epoch?APR_RET_WAITING:!report.network?APR_RET_UNKNOWN:
        report.pending?APR_RET_SETTLING:report.awaiting?APR_RET_RECOVERING:APR_RET_IDLE;
    apr_diag_retirement(&report);
}
static unsigned network_type(nw_path_t path) {
    if(!path || nw_path_get_status(path)!=nw_path_status_satisfied) return 0;
    bool wifi=nw_path_uses_interface_type(path,nw_interface_type_wifi);
    bool cell=nw_path_uses_interface_type(path,nw_interface_type_cellular);
    return wifi==cell?0:wifi?APR_RET_WIFI:APR_RET_CELLULAR;
}
static bool now_ns(uint64_t *value) {
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC,&now)) return false;
    if(now.tv_sec<0 || now.tv_nsec<0 || now.tv_nsec>=1000000000L ||
       (uint64_t)now.tv_sec>(UINT64_MAX-RETIRE_WINDOW_NS-999999999)/UINT64_C(1000000000)) {
        errno=EOVERFLOW;return false;
    }
    *value=(uint64_t)now.tv_sec*UINT64_C(1000000000)+(uint64_t)now.tv_nsec;
    return true;
}
static unsigned stop(int error,nw_connection_t *release) {
    unsigned count=0;active=false;report.status=APR_RET_UNAVAILABLE;
    report.error=(uint32_t)(error?error:EIO);fresh_epoch=0;
    for(unsigned i=0;i<RETIRE_LIMIT;++i) if(held[i].id) {
        release[count++]=detach_connection(i);
    }
    return count;
}
static void timer_fired(void *unused);
static void work_fired(void *unused);
static void schedule_timer(uint64_t delay) {
    if(timer_scheduled) return;
    timer_scheduled=true;
    dispatch_after_f(dispatch_time(DISPATCH_TIME_NOW,(int64_t)delay),retirement_queue,NULL,timer_fired);
}
static void path_changed(nw_path_t path) {
    int saved=errno;unsigned network=network_type(path),count=0;
    nw_connection_t release[RETIRE_LIMIT];
    pthread_mutex_lock(&retirement_lock);
    if(!active) goto done;
    if(!network) {report.network=0;fresh_epoch=0;publish();goto done;}
    bool first=!report.epoch,changed=last_network && last_network!=network;
    bool resumed=!report.network;
    if(changed && report.epoch==UINT32_MAX) {count=stop(EOVERFLOW,release);publish();goto done;}
    report.network=last_network=network;
    if(first) {
        report.epoch=1;
        for(unsigned i=0;i<RETIRE_LIMIT;++i) if(held[i].id && !held[i].ready_epoch) held[i].ready_epoch=1;
    } else if(changed) {++report.epoch;fresh_epoch=0;}
    if(changed || resumed) {
        uint64_t now;
        if(!now_ns(&now)) {count=stop(errno,release);publish();goto done;}
        deadline=now+RETIRE_WINDOW_NS;
    }
    publish();
    if(report.pending) schedule_timer(RETIRE_WINDOW_NS);
done:
    pthread_mutex_unlock(&retirement_lock);
    for(unsigned i=0;i<count;++i) nw_release(release[i]);
    errno=saved;
}
void apr_retirement_init(bool enabled,APRRetireFunction request_endpoint) {
    int saved=errno;
    pthread_mutex_lock(&retirement_lock);
    if(initialized) {pthread_mutex_unlock(&retirement_lock);errno=saved;return;}
    initialized=true;
    if(!enabled || !request_endpoint) {
        report.status=enabled?APR_RET_UNAVAILABLE:APR_RET_DISABLED;
        report.error=enabled?ENOSYS:0;publish();
        pthread_mutex_unlock(&retirement_lock);errno=saved;return;
    }
    retirement_queue=dispatch_queue_create("local.apnsroute.retirement",DISPATCH_QUEUE_SERIAL);
    if(retirement_queue) monitor=nw_path_monitor_create();
    if(!retirement_queue || !monitor) {
        if(retirement_queue) dispatch_release(retirement_queue);
        retirement_queue=NULL;report.status=APR_RET_UNAVAILABLE;report.error=ENOMEM;publish();
        pthread_mutex_unlock(&retirement_lock);errno=saved;return;
    }
    request_endpoint_cancellation=request_endpoint;active=true;publish();
    pthread_mutex_unlock(&retirement_lock);
    /* The dedicated queue belongs to the monitor/retirement work only. apsd's
       connection queues and state/path/viability handlers are left intact. */
    nw_path_monitor_set_queue(monitor,retirement_queue);
    nw_path_monitor_set_update_handler(monitor,^(nw_path_t path) {path_changed(path);});
    nw_path_monitor_start(monitor);
    errno=saved;
}
void apr_retirement_start(nw_connection_t connection,uint32_t id,uint32_t handler) {
    int saved=errno;pthread_mutex_lock(&retirement_lock);
    if(!active) goto done;
    if(!connection || !id || !handler) {increment(&report.skipped);publish();goto done;}
    unsigned slot=find_id(id);
    if(slot<RETIRE_LIMIT) goto done; /* A repeated start cannot refresh its birth. */
    for(slot=0;slot<RETIRE_LIMIT;++slot) if(!held[slot].id) break;
    if(slot==RETIRE_LIMIT) {increment(&report.skipped);publish();goto done;}
    nw_retain(connection); /* Own a reference before the caller can release it. */
    held[slot]=(HeldConnection){
        .connection=connection,
        .id=id,
        .handler=handler,
        .ready_epoch=report.epoch
    };
    publish();
done:
    pthread_mutex_unlock(&retirement_lock);errno=saved;
}
void apr_retirement_forget(uint32_t id) {
    int saved=errno;nw_connection_t release=NULL;
    pthread_mutex_lock(&retirement_lock);unsigned slot=find_id(id);
    if(slot<RETIRE_LIMIT) {release=detach_connection(slot);publish();}
    pthread_mutex_unlock(&retirement_lock);
    if(release) nw_release(release);
    errno=saved;
}
void apr_retirement_handler(uint32_t id,uint32_t handler) {
    if(!handler) {apr_retirement_forget(id);return;}
    int saved=errno;pthread_mutex_lock(&retirement_lock);unsigned slot=find_id(id);
    if(slot<RETIRE_LIMIT) {held[slot].handler=handler;held[slot].ready=false;}
    pthread_mutex_unlock(&retirement_lock);errno=saved;
}
void apr_retirement_state(uint32_t id,uint32_t handler,unsigned state) {
    int saved=errno;nw_connection_t release=NULL;
    pthread_mutex_lock(&retirement_lock);unsigned slot=find_id(id);
    if(slot<RETIRE_LIMIT && handler && held[slot].handler==handler) {
        if(state==nw_connection_state_failed || state==nw_connection_state_cancelled) {
            release=detach_connection(slot);publish();
        } else {
            held[slot].ready=state==nw_connection_state_ready;
            if(held[slot].ready && (!held[slot].ever_ready || held[slot].awaiting)) {
                /* A connection still establishing when the monitor changes is
                   fresh when it first becomes ready on the new generation.
                   Native endpoint recovery rearms the same owned NW object. */
                held[slot].ready_epoch=report.epoch;
                held[slot].ever_ready=true;
                held[slot].awaiting=false;
                publish();
            }
        }
    }
    pthread_mutex_unlock(&retirement_lock);
    if(release) nw_release(release);
    errno=saved;
}
void apr_retirement_received(uint32_t id) {
    int saved=errno;nw_connection_t connection=NULL;uint32_t epoch=0,network=0;
    pthread_mutex_lock(&retirement_lock);unsigned slot=find_id(id);
    if(active && !sample_busy && report.pending && report.network && slot<RETIRE_LIMIT &&
       held[slot].ready && held[slot].ready_epoch==report.epoch) {
        sample_busy=true;
        connection=held[slot].connection;nw_retain(connection);
        epoch=report.epoch;network=report.network;
    }
    pthread_mutex_unlock(&retirement_lock);
    if(connection) {
        nw_path_t path=nw_connection_copy_current_path(connection);
        unsigned observed=network_type(path);
        if(path) nw_release(path);
        pthread_mutex_lock(&retirement_lock);sample_busy=false;slot=find_id(id);
        if(active && epoch==report.epoch && network==report.network && observed==network &&
           slot<RETIRE_LIMIT && held[slot].connection==connection && held[slot].ready && held[slot].ready_epoch==epoch) {
            fresh_epoch=epoch;
            if(!work_scheduled) {work_scheduled=true;dispatch_async_f(retirement_queue,NULL,work_fired);}
        }
        pthread_mutex_unlock(&retirement_lock);nw_release(connection);
    }
    errno=saved;
}
static void drain(bool timer) {
    int saved=errno;unsigned count=0,release_count=0;
    nw_connection_t connections[RETIRE_LIMIT],release[RETIRE_LIMIT];uint32_t ids[RETIRE_LIMIT];
    pthread_mutex_lock(&retirement_lock);
    if(timer) timer_scheduled=false;else work_scheduled=false;
    if(!active || !report.network || !report.pending) goto done;
    uint64_t now;
    if(!now_ns(&now)) {release_count=stop(errno,release);publish();goto done;}
    bool fresh=fresh_epoch==report.epoch;
    if(!fresh && now<deadline) {schedule_timer(deadline-now);goto done;}
    for(unsigned i=0;i<RETIRE_LIMIT;++i) if(should_retire(&held[i])) {
        connections[count]=held[i].connection;ids[count++]=held[i].id;
        /* Endpoint fallback may keep this NW object. Retain the registry entry
           for later handovers; take an independent reference for this call.
           No second request is made while native recovery is outstanding. */
        nw_retain(held[i].connection);
        held[i].ready_epoch=report.epoch;
        held[i].ready=false;
        held[i].awaiting=true;
    }
    for(unsigned i=0;i<count;++i) {increment(&report.requests);report.last_id=ids[i];}
    if(count) report.reason=fresh?APR_RET_NEW_DATA:APR_RET_DEADLINE;
    publish();
done:
    pthread_mutex_unlock(&retirement_lock);
    for(unsigned i=0;i<count;++i) {
        apr_connection_retire_requested(ids[i]);
        request_endpoint_cancellation(connections[i]);
        nw_release(connections[i]);
    }
    for(unsigned i=0;i<release_count;++i) nw_release(release[i]);
    errno=saved;
}
static void timer_fired(void *unused) {(void)unused;drain(true);}
static void work_fired(void *unused) {(void)unused;drain(false);}
