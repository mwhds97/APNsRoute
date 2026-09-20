/* Public iOS 12/13 APIs. Observers preserve apsd's callbacks and queues.
   Retirement owns bounded references separately and requests current-endpoint
   cancellation only after a monitored network transition. */
#include "NWObserver.h"
#include "NWHooks.h"
#include "Diagnostics.h"
#include "ConnectionStatus.h"
#include "Connections.h"
#include "Retirement.h"
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

extern bool apr_can_modify(void);
void (*apr_original_nw_start)(nw_connection_t);
void (*apr_original_nw_state_handler)(nw_connection_t,nw_connection_state_changed_handler_t);
void (*apr_original_nw_send)(nw_connection_t,dispatch_data_t,nw_content_context_t,bool,nw_connection_send_completion_t);
void (*apr_original_nw_receive)(nw_connection_t,uint32_t,uint32_t,nw_connection_receive_completion_t);
void (*apr_original_nw_receive_message)(nw_connection_t,nw_connection_receive_completion_t);
void (*apr_original_nw_cancel)(nw_connection_t);
void (*apr_original_nw_force_cancel)(nw_connection_t);
static nw_path_unsatisfied_reason_t (*path_reason)(nw_path_t);
static void (*cancel_endpoint)(nw_connection_t);
/* Endpoint/force cancellation may synchronously call a public cancel API.
   Such a nested call must pass through without an upgrade or recursion. */
static _Thread_local bool native_cancel_dispatch;
static void dispatch_force_cancel(nw_connection_t connection) {
    bool previous=native_cancel_dispatch;
    native_cancel_dispatch=true;
    apr_original_nw_force_cancel(connection);
    native_cancel_dispatch=previous;
}
void apr_nw_retire(nw_connection_t connection) {
    /* Request native endpoint fallback/failure on this CFNetwork-owned object.
       Terminal cancellation remains the owner's decision; there is no full
       cancellation fallback or synthetic callback here. */
    if(!cancel_endpoint) return;
    bool previous=native_cancel_dispatch;
    native_cancel_dispatch=true;
    cancel_endpoint(connection);
    native_cancel_dispatch=previous;
}
bool apr_nw_retirement_available(void) {return cancel_endpoint!=NULL;}
void apr_nw_observer_init(void) {
    int saved=errno;
    /* Public iOS 14.2 API, resolved dynamically so rootful 14.0/14.1 can still
       load. Its exact enum/path signature comes from the 14.5 SDK path.h. */
    path_reason=dlsym(RTLD_DEFAULT,"nw_path_get_unsatisfied_reason");
    /* Public iOS 12 API. Optional lookup keeps an unavailable runtime native. */
    cancel_endpoint=dlsym(RTLD_DEFAULT,"nw_connection_cancel_current_endpoint");
    errno=saved;
}

static bool matched_connection(nw_connection_t connection) {
    if(!connection) return false;
    nw_endpoint_t endpoint=nw_connection_copy_endpoint(connection);
    bool target=apr_nw_target(endpoint);
    if(endpoint) nw_release(endpoint);
    return target;
}

static uint32_t connection_id(nw_connection_t connection) {
    /* Called synchronously with a caller-owned connection. A saved key is never
       treated as a usable object reference; callbacks capture only its ID. */
    uint32_t id=apr_connection_find((uintptr_t)connection);
    if(id) return id;
    nw_endpoint_t endpoint=nw_connection_copy_endpoint(connection);
    if(endpoint) {
        id=apr_connection_observe((uintptr_t)connection,apr_nw_role(endpoint),false);
        nw_release(endpoint);
    }
    return id;
}

static unsigned sample_path(nw_connection_t connection,bool force) {
    unsigned detail=APR_PATH_SEEN | (force?APR_PATH_FORCE:0);
    /* The caller owns a valid connection during this synchronous hook. Read
       before forwarding cancel; no connection reference escapes the call. */
    nw_path_t path=nw_connection_copy_current_path(connection);
    if(path) {
        detail|=APR_PATH_PRESENT | ((unsigned)nw_path_get_status(path)&255U);
        if(path_reason)detail|=APR_PATH_REASON_API | (((unsigned)path_reason(path)&255U)<<8);
        if(nw_path_uses_interface_type(path,nw_interface_type_wifi))detail|=APR_PATH_WIFI;
        if(nw_path_uses_interface_type(path,nw_interface_type_cellular))detail|=APR_PATH_CELL;
        if(nw_path_uses_interface_type(path,nw_interface_type_loopback))detail|=APR_PATH_LOOP;
        if(nw_path_is_expensive(path))detail|=APR_PATH_EXPENSIVE;
        if(nw_path_is_constrained(path))detail|=APR_PATH_CONSTRAINED;
        nw_release(path);
    }
    return detail;
}
static unsigned before_cancel(nw_connection_t connection,bool force) {
    unsigned detail=sample_path(connection,force);
    apr_diag_event(detail&APR_PATH_PRESENT?APR_NW_CANCEL_PATH:APR_NW_CANCEL_PATH_MISSING);
    apr_diag_nw_cancel_path(detail);
    return detail;
}
void apr_nw_cancel(nw_connection_t connection) {
    if(native_cancel_dispatch) {apr_original_nw_cancel(connection);return;}
    int saved=errno;
    bool immediate=false;
    if(matched_connection(connection)) {
        apr_retirement_forget(connection_id(connection));
        unsigned action=APR_CANCEL_NATIVE;
        if(apr_can_modify()) {
            immediate=apr_original_nw_force_cancel!=NULL;
            action=immediate?APR_CANCEL_IMMEDIATE:APR_CANCEL_UNAVAILABLE;
        }
        unsigned detail=before_cancel(connection,immediate);
        apr_connection_cancel(connection_id(connection),false,detail);
        apr_diag_nw_cancel(action);
    }
    errno=saved;
    /* Normal cancel may negotiate FIN/TLS closure over a path that has just
       changed. Force-cancel asks the stack to abort that already-retired
       connection, rather than letting the close negotiation linger. Both
       APIs asynchronously deliver the normal cancellation callbacks. Call
       exactly one trampoline; do not cancel a new/replacement connection. */
    if(immediate) dispatch_force_cancel(connection);
    else apr_original_nw_cancel(connection);
}
void apr_nw_force_cancel(nw_connection_t connection) {
    if(native_cancel_dispatch) {apr_original_nw_force_cancel(connection);return;}
    int saved=errno;
    if(matched_connection(connection)) {
        apr_retirement_forget(connection_id(connection));
        unsigned detail=before_cancel(connection,true);
        apr_connection_cancel(connection_id(connection),true,detail);
        apr_diag_nw_cancel(APR_CANCEL_APP_FORCE);
    }
    errno=saved;
    dispatch_force_cancel(connection);
}

void apr_nw_start(nw_connection_t connection) {
    int saved=errno;
    if(matched_connection(connection)) {
        apr_diag_event(APR_NW_START);
        apr_diag_nw_start(APR_START_SEEN);
        uint32_t id=connection_id(connection);
        apr_retirement_start(connection,id,apr_connection_handler_id(id));
    }
    errno=saved;
    apr_original_nw_start(connection);
}

void apr_nw_state_handler(nw_connection_t connection,nw_connection_state_changed_handler_t handler) {
    int saved=errno;
    if(!matched_connection(connection)) {
        errno=saved;apr_original_nw_state_handler(connection,handler);return;
    }
    uint32_t id=connection_id(connection);
    if(!handler) {
        /* NULL must actually remove the handler. Do not install our own one. */
        apr_diag_event(APR_NW_STATE_CLEAR);
        apr_connection_handler(id,0);
        apr_retirement_handler(id,0);
        errno=saved;apr_original_nw_state_handler(connection,NULL);return;
    }
    /* The callback captures a generation and the caller block, never the
       connection. Older handlers cannot replace the latest diagnostic state. */
    uint32_t generation=apr_diag_nw_handler();
    apr_connection_handler(id,generation);
    apr_retirement_handler(id,generation);
    if(!generation) {
        errno=saved;apr_original_nw_state_handler(connection,handler);return;
    }
    apr_diag_event(APR_NW_STATE_HANDLER);
    errno=saved;
    apr_original_nw_state_handler(connection,^(nw_connection_state_t state,nw_error_t error) {
        int incoming=errno;
        unsigned domain=error ? (unsigned)nw_error_get_error_domain(error) : 0;
        int code=error ? nw_error_get_error_code(error) : 0;
        apr_diag_nw_state(generation,(unsigned)state,domain,code);
        apr_connection_state(id,generation,(unsigned)state,domain,code);
        switch(state) {
            case nw_connection_state_ready: apr_diag_event(APR_NW_STATE_READY);break;
            case nw_connection_state_waiting: apr_diag_event(APR_NW_STATE_WAITING);break;
            case nw_connection_state_failed: apr_diag_event(APR_NW_STATE_FAILED);break;
            case nw_connection_state_cancelled: apr_diag_event(APR_NW_STATE_CANCELLED);break;
            default: break;
        }
        errno=incoming;
        handler(state,error);
        int outgoing=errno;
        apr_retirement_state(id,generation,(unsigned)state);
        errno=outgoing;
        /* Capture only the original block and scalar IDs. The system
           copies the wrapper and therefore its nested block. No connection
           capture, retained object, or added callback queue. */
    });
}

static pthread_mutex_t report_lock=PTHREAD_MUTEX_INITIALIZER;
static bool report_busy,report_previous;
static uint64_t report_last;
static bool begin_report(void) {
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC,&now) || now.tv_sec<0) return false;
    uint64_t seconds=(uint64_t)now.tv_sec;
    pthread_mutex_lock(&report_lock);
    bool take=!report_busy && (!report_previous || (seconds>=report_last && seconds-report_last>=5));
    if(take) {report_busy=true;report_previous=true;report_last=seconds;}
    pthread_mutex_unlock(&report_lock);
    return take;
}
void apr_nw_send(nw_connection_t connection,dispatch_data_t content,nw_content_context_t context,
                 bool complete,nw_connection_send_completion_t completion) {
    int saved=errno;
    if(matched_connection(connection)) {
        apr_diag_event(APR_NW_SEND);
        apr_connection_send(connection_id(connection));
        if(begin_report()) {
            apr_diag_event(APR_NW_REPORT_REQUESTED);
            apr_diag_nw_report(APR_REPORT_REQUESTED);
            /* Request while the caller owns a valid connection. The public API
               manages the asynchronous access; our callback captures nothing.
               A pre-ready report is NULL. A later send may retry after 5 s.
               This global last report is NOT correlated with the last handler. */
            nw_connection_access_establishment_report(connection,
                dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),
                ^(nw_establishment_report_t report) {
                    int incoming=errno;
                    unsigned detail=APR_REPORT_REQUESTED|APR_REPORT_RETURNED;
                    if(report) {
                        detail|=APR_REPORT_AVAILABLE;
                        if(nw_establishment_report_get_proxy_configured(report)) detail|=APR_REPORT_CONFIGURED;
                        if(nw_establishment_report_get_used_proxy(report)) detail|=APR_REPORT_USED;
                        apr_diag_event(APR_NW_REPORT_AVAILABLE);
                    } else apr_diag_event(APR_NW_REPORT_UNAVAILABLE);
                    apr_diag_nw_report(detail);
                    pthread_mutex_lock(&report_lock);report_busy=false;pthread_mutex_unlock(&report_lock);
                    errno=incoming;
                });
        }
    }
    errno=saved;
    apr_original_nw_send(connection,content,context,complete,completion);
}

/* Observe the caller's receives without requesting any additional I/O. Block
   arguments, queue, completion count and errno are preserved. Content is never
   inspected: dispatch_data_get_size supplies an aggregate byte count only. */
static void received(uint32_t id,dispatch_data_t content,bool complete,nw_error_t error) {
    size_t bytes=content?dispatch_data_get_size(content):0;
    unsigned domain=error?(unsigned)nw_error_get_error_domain(error):0;
    int code=error?nw_error_get_error_code(error):0;
    apr_connection_received(id,bytes,complete,domain,code);
}
void apr_nw_receive(nw_connection_t connection,uint32_t minimum,uint32_t maximum,
                    nw_connection_receive_completion_t completion) {
    int saved=errno;uint32_t id=0;
    if(matched_connection(connection)) {
        id=connection_id(connection);apr_connection_read(id,sample_path(connection,false));
    }
    errno=saved;
    if(!id || !completion) {apr_original_nw_receive(connection,minimum,maximum,completion);return;}
    apr_original_nw_receive(connection,minimum,maximum,
        ^(dispatch_data_t content,nw_content_context_t context,bool complete,nw_error_t error) {
            int incoming=errno;received(id,content,complete,error);errno=incoming;
            completion(content,context,complete,error);
        });
}
void apr_nw_receive_message(nw_connection_t connection,nw_connection_receive_completion_t completion) {
    int saved=errno;uint32_t id=0;
    if(matched_connection(connection)) {
        id=connection_id(connection);apr_connection_read(id,sample_path(connection,false));
    }
    errno=saved;
    if(!id || !completion) {apr_original_nw_receive_message(connection,completion);return;}
    apr_original_nw_receive_message(connection,
        ^(dispatch_data_t content,nw_content_context_t context,bool complete,nw_error_t error) {
            int incoming=errno;received(id,content,complete,error);errno=incoming;
            completion(content,context,complete,error);
        });
}
