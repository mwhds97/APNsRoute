/* Coalesce physical-network and VPN transitions behind one quiet-period gate.
   Eight registry references and up to eight temporary batch references are
   owned. One path monitor, one quiet timer, one VPN check timer and one
   coalesced work callback share a serial queue. Native callbacks/queues and
   NECP output stay intact; endpoint requests/releases run outside the mutex. */
#include "Retirement.h"
#include "Connections.h"
#include "Diagnostics.h"
#include "TunnelSelector.h"
#include <dispatch/dispatch.h>
#include <errno.h>
#include <pthread.h>
#include <notify.h>
#include <string.h>
#include <time.h>

#define QUIET_NS (APR_QUIET_PERIOD_MS * UINT64_C(1000000))
#define VPN_CHECK_NS UINT64_C(1000000000)
#define RETIRE_LIMIT APR_CONNECTION_COUNT
typedef struct {
    nw_connection_t connection;
    uint32_t id,handler,ready_epoch,vpn_epoch;
    bool ever_ready,awaiting;
} HeldConnection;
static HeldConnection held[RETIRE_LIMIT];
static pthread_mutex_t retirement_lock=PTHREAD_MUTEX_INITIALIZER;
static dispatch_queue_t retirement_queue;
static nw_path_monitor_t monitor;
static APRRetireFunction request_endpoint_cancellation;
static APRRetirementStatus report;
static bool initialized,active,timer_scheduled,work_scheduled;
static uint32_t last_network,last_vpn;
static uint64_t deadline;
static APRTunnel last_tunnel;
static int vpn_notify_token;
static void timer_fired(void *unused);
static void work_fired(void *unused);
static void vpn_check(void *unused);
static void vpn_tick(void *unused);

static void increment(uint32_t *value) {if(*value!=UINT32_MAX) ++*value;}
static unsigned find_id(uint32_t id) {
    if(id) for(unsigned i=0;i<RETIRE_LIMIT;++i) if(held[i].id==id) return i;
    return RETIRE_LIMIT;
}
/* Caller holds retirement_lock. Transfer ownership for release outside it. */
static nw_connection_t detach_connection(unsigned slot) {
    nw_connection_t connection=held[slot].connection;
    held[slot]=(HeldConnection){0};
    return connection;
}
static bool older_physical(const HeldConnection *entry) {
    return entry->id && entry->ever_ready && entry->ready_epoch && entry->ready_epoch<report.epoch;
}
static bool older_vpn(const HeldConnection *entry) {
    return entry->id && entry->vpn_epoch && entry->vpn_epoch<report.vpn_epoch;
}
static bool eligible(const HeldConnection *entry) {
    return entry->ever_ready && !entry->awaiting && (older_physical(entry) || older_vpn(entry));
}
static bool vpn_known(void) {return report.vpn_state==APR_VPN_ON || report.vpn_state==APR_VPN_OFF;}
static bool observations_known(void) {
    /* VPN may establish its baseline before the first physical-path callback.
       Once a physical baseline exists, losing it suspends all automatic work. */
    return vpn_known() && (!report.epoch || report.network);
}
static void publish(void) {
    report.held=report.pending=report.awaiting=report.vpn_pending=0;
    for(unsigned i=0;i<RETIRE_LIMIT;++i) if(held[i].id) {
        ++report.held;
        if(eligible(&held[i])) ++report.pending;
        if(older_vpn(&held[i])) ++report.vpn_pending;
        if(held[i].awaiting) ++report.awaiting;
    }
    if(active) {
        if(report.quiet_state!=APR_QUIET_IDLE && !observations_known()) report.quiet_state=APR_QUIET_BLOCKED;
        report.status=report.quiet_state==APR_QUIET_BLOCKED?APR_RET_UNKNOWN:
            report.quiet_state==APR_QUIET_WAITING || report.pending?APR_RET_SETTLING:
            report.awaiting?APR_RET_RECOVERING:!report.epoch && !report.vpn_epoch?APR_RET_WAITING:APR_RET_IDLE;
    }
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
       (uint64_t)now.tv_sec>(UINT64_MAX-QUIET_NS-999999999)/UINT64_C(1000000000)) {
        errno=EOVERFLOW;return false;
    }
    *value=(uint64_t)now.tv_sec*UINT64_C(1000000000)+(uint64_t)now.tv_nsec;
    return true;
}
static unsigned stop(int error,nw_connection_t *release) {
    unsigned count=0;active=false;report.status=APR_RET_UNAVAILABLE;
    report.error=(uint32_t)(error?error:EIO);
    report.quiet_state=APR_QUIET_IDLE;report.quiet_remaining_ms=0;
    for(unsigned i=0;i<RETIRE_LIMIT;++i) if(held[i].id) release[count++]=detach_connection(i);
    return count;
}
/* Caller holds retirement_lock. An earlier timer is allowed to wake and check
   the latest deadline; it never carries a captured generation or object list. */
static void schedule_timer(uint64_t delay) {
    if(timer_scheduled) return;
    timer_scheduled=true;
    dispatch_after_f(dispatch_time(DISPATCH_TIME_NOW,(int64_t)delay),retirement_queue,NULL,timer_fired);
}
static void schedule_work(void) {
    if(!work_scheduled) {work_scheduled=true;dispatch_async_f(retirement_queue,NULL,work_fired);}
}
static bool note_activity(uint32_t causes) {
    uint64_t now;
    if(!now_ns(&now)) return false;
    if(report.quiet_state==APR_QUIET_IDLE) {
        if(report.quiet_epoch==UINT32_MAX) {errno=EOVERFLOW;return false;}
        ++report.quiet_epoch;report.quiet_events=report.quiet_causes=0;
    }
    increment(&report.quiet_events);report.quiet_causes|=causes;
    deadline=now+QUIET_NS;
    report.quiet_state=APR_QUIET_WAITING;report.quiet_remaining_ms=APR_QUIET_PERIOD_MS;
    schedule_timer(QUIET_NS);
    return true;
}
static void quiet_remaining(uint64_t now) {
    report.quiet_remaining_ms=now>=deadline?0:(uint32_t)((deadline-now+999999)/UINT64_C(1000000));
}
static void path_changed(nw_path_t path) {
    int saved=errno;unsigned network=network_type(path),count=0;
    nw_connection_t release[RETIRE_LIMIT];
    pthread_mutex_lock(&retirement_lock);
    if(!active) goto done;
    bool first=!report.epoch,changed=network && last_network && last_network!=network;
    bool lost=!network && report.network,resumed=network && !report.network && !first;
    if(changed && report.epoch==UINT32_MAX) {count=stop(EOVERFLOW,release);publish();goto done;}
    report.network=network;
    if(network) {
        last_network=network;
        if(first) {
            report.epoch=1;
            for(unsigned i=0;i<RETIRE_LIMIT;++i) if(held[i].id && !held[i].ready_epoch) held[i].ready_epoch=1;
        } else if(changed) ++report.epoch;
    }
    /* Unknown/resumed observations also extend an in-progress switch. A cold
       first baseline alone is not a switch and does not retire anything. */
    if(changed || lost || resumed || (network && first && report.quiet_state!=APR_QUIET_IDLE)) {
        uint32_t causes=(changed?APR_QUIET_PHYSICAL:0) | (lost || resumed || first?APR_QUIET_UNCERTAIN:0);
        if(!note_activity(causes)) count=stop(errno,release);
    }
    publish();
done:
    pthread_mutex_unlock(&retirement_lock);
    for(unsigned i=0;i<count;++i) nw_release(release[i]);
    vpn_check(NULL);errno=saved;
}
/* Notification delivery is a hint. Validate the same unique, addressed up
   utun used for routing. Failed/ambiguous snapshots are never VPN-off. */
static void vpn_check(void *unused) {
    (void)unused;int saved=errno,error=0;APRTunnel tunnel;
    pthread_mutex_lock(&retirement_lock);bool enabled=active;pthread_mutex_unlock(&retirement_lock);
    if(!enabled) {errno=saved;return;}
    enum apr_tunnel_choice choice=apr_tunnel_select(0,&tunnel,&error);
    uint32_t state=choice==APR_TUN_UNIQUE?APR_VPN_ON:choice==APR_TUN_NONE?APR_VPN_OFF:
        choice==APR_TUN_AMBIGUOUS?APR_VPN_AMBIGUOUS:APR_VPN_UNAVAILABLE;
    nw_connection_t release[RETIRE_LIMIT];unsigned count=0;
    pthread_mutex_lock(&retirement_lock);
    if(!active) goto done;
    bool was_known=vpn_known();uint32_t previous=report.vpn_state,causes=0;
    report.vpn_state=state;report.vpn_index=state==APR_VPN_ON?tunnel.index:0;
    report.vpn_error=(uint32_t)error;
    if(vpn_known()) {
        bool changed=last_vpn && (last_vpn!=state || (state==APR_VPN_ON &&
            (last_tunnel.index!=tunnel.index || strcmp(last_tunnel.name,tunnel.name))));
        if(changed && report.vpn_epoch==UINT32_MAX) {count=stop(EOVERFLOW,release);publish();goto done;}
        if(!report.vpn_epoch) {
            report.vpn_epoch=1;
            for(unsigned i=0;i<RETIRE_LIMIT;++i) if(held[i].id) held[i].vpn_epoch=1;
            if(report.quiet_state!=APR_QUIET_IDLE) causes|=APR_QUIET_UNCERTAIN;
        } else {
            if(!was_known) causes|=APR_QUIET_UNCERTAIN;
            if(changed) {
                ++report.vpn_epoch;
                report.vpn_reason=state==APR_VPN_OFF?APR_RET_VPN_OFF:
                    last_vpn==APR_VPN_OFF?APR_RET_VPN_ON:APR_RET_VPN_REPLACED;
                causes|=state==APR_VPN_OFF?APR_QUIET_VPN_OFF:
                    last_vpn==APR_VPN_OFF?APR_QUIET_VPN_ON:APR_QUIET_VPN_REPLACED;
            }
        }
        last_vpn=state;last_tunnel=tunnel;
    } else if(report.vpn_epoch && previous!=state) causes|=APR_QUIET_UNCERTAIN;
    if(causes && !note_activity(causes)) {count=stop(errno,release);publish();goto done;}
    if(report.quiet_state!=APR_QUIET_IDLE) {
        uint64_t now;
        if(!now_ns(&now)) {count=stop(errno,release);publish();goto done;}
        quiet_remaining(now);
    } else if(observations_known()) {
        for(unsigned i=0;i<RETIRE_LIMIT;++i) if(eligible(&held[i])) {schedule_work();break;}
    }
    publish();
done:
    pthread_mutex_unlock(&retirement_lock);
    for(unsigned i=0;i<count;++i) nw_release(release[i]);
    errno=saved;
}
static void vpn_tick(void *unused) {
    int saved=errno;vpn_check(unused);
    pthread_mutex_lock(&retirement_lock);
    if(active) dispatch_after_f(dispatch_time(DISPATCH_TIME_NOW,VPN_CHECK_NS),retirement_queue,NULL,vpn_tick);
    pthread_mutex_unlock(&retirement_lock);errno=saved;
}
void apr_retirement_init(bool enabled,APRRetireFunction request_endpoint) {
    int saved=errno;pthread_mutex_lock(&retirement_lock);
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
    uint32_t notify_status=notify_register_dispatch("com.apple.system.config.network_change",
        &vpn_notify_token,retirement_queue,^(int token) {(void)token;vpn_check(NULL);});
    pthread_mutex_lock(&retirement_lock);
    report.vpn_notify=notify_status==NOTIFY_STATUS_OK?1:2;
    report.vpn_notify_error=notify_status;publish();
    pthread_mutex_unlock(&retirement_lock);
    dispatch_async_f(retirement_queue,NULL,vpn_tick);
    nw_path_monitor_set_queue(monitor,retirement_queue);
    nw_path_monitor_set_update_handler(monitor,^(nw_path_t path) {path_changed(path);});
    nw_path_monitor_start(monitor);errno=saved;
}
void apr_retirement_start(nw_connection_t connection,uint32_t id,uint32_t handler) {
    int saved=errno;pthread_mutex_lock(&retirement_lock);
    if(!active) goto done;
    if(!connection || !id || !handler) {increment(&report.skipped);publish();goto done;}
    unsigned slot=find_id(id);
    if(slot<RETIRE_LIMIT) goto done;
    for(slot=0;slot<RETIRE_LIMIT;++slot) if(!held[slot].id) break;
    if(slot==RETIRE_LIMIT) {increment(&report.skipped);publish();goto done;}
    nw_retain(connection);
    held[slot]=(HeldConnection){.connection=connection,.id=id,.handler=handler,
        .ready_epoch=report.epoch,.vpn_epoch=report.vpn_epoch};
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
    if(slot<RETIRE_LIMIT) held[slot].handler=handler;
    pthread_mutex_unlock(&retirement_lock);errno=saved;
}
void apr_retirement_state(uint32_t id,uint32_t handler,unsigned state) {
    int saved=errno;nw_connection_t release=NULL;
    pthread_mutex_lock(&retirement_lock);unsigned slot=find_id(id);
    if(slot<RETIRE_LIMIT && handler && held[slot].handler==handler) {
        if(state==nw_connection_state_failed || state==nw_connection_state_cancelled) release=detach_connection(slot);
        else if(state==nw_connection_state_ready && (!held[slot].ever_ready || held[slot].awaiting)) {
            held[slot].ready_epoch=report.epoch;held[slot].ever_ready=true;held[slot].awaiting=false;
            /* A later VPN generation survives native recovery. Readiness can
               queue work, but cannot reset or bypass the shared quiet gate. */
            if(eligible(&held[slot]) && report.quiet_state==APR_QUIET_IDLE) schedule_work();
        }
        publish();
    }
    pthread_mutex_unlock(&retirement_lock);
    if(release) nw_release(release);
    errno=saved;
}
static void drain(bool timer) {
    int saved=errno;unsigned count=0,release_count=0;
    nw_connection_t connections[RETIRE_LIMIT],release[RETIRE_LIMIT];uint32_t ids[RETIRE_LIMIT];
    /* Recheck the tunnel immediately before deciding whether the last event
       really stayed quiet. This can extend the deadline for a missed hint. */
    vpn_check(NULL);
    pthread_mutex_lock(&retirement_lock);
    if(timer) timer_scheduled=false;else work_scheduled=false;
    if(!active || (report.quiet_state==APR_QUIET_IDLE && !report.pending)) goto done;
    uint64_t now;
    if(!now_ns(&now)) {release_count=stop(errno,release);publish();goto done;}
    quiet_remaining(now);
    if(!observations_known()) {report.quiet_state=APR_QUIET_BLOCKED;publish();goto done;}
    if(now<deadline) {
        report.quiet_state=APR_QUIET_WAITING;schedule_timer(deadline-now);publish();goto done;
    }
    report.quiet_state=APR_QUIET_IDLE;
    for(unsigned i=0;i<RETIRE_LIMIT;++i) if(eligible(&held[i])) {
        connections[count]=held[i].connection;ids[count++]=held[i].id;
        nw_retain(held[i].connection);
        if(older_vpn(&held[i])) {increment(&report.vpn_requests);report.reason=report.vpn_reason;}
        else report.reason=APR_RET_QUIET;
        held[i].ready_epoch=report.epoch;held[i].vpn_epoch=report.vpn_epoch;held[i].awaiting=true;
    }
    if(count) increment(&report.batches);
    for(unsigned i=0;i<count;++i) {increment(&report.requests);report.last_id=ids[i];}
    publish();
done:
    pthread_mutex_unlock(&retirement_lock);
    for(unsigned i=0;i<count;++i) {
        apr_connection_retire_requested(ids[i]);request_endpoint_cancellation(connections[i]);nw_release(connections[i]);
    }
    for(unsigned i=0;i<release_count;++i) nw_release(release[i]);
    errno=saved;
}
static void timer_fired(void *unused) {(void)unused;drain(true);}
static void work_fired(void *unused) {(void)unused;drain(false);}
