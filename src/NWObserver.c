/* Public iOS 12/13 API observations. Never retains a connection, changes its
   queue, starts/cancels it, inspects content, or substitutes a send completion. */
#include "NWObserver.h"
#include "NWHooks.h"
#include "Diagnostics.h"
#include "ConnectionStatus.h"
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

void (*apr_original_nw_start)(nw_connection_t);
void (*apr_original_nw_state_handler)(nw_connection_t,nw_connection_state_changed_handler_t);
void (*apr_original_nw_send)(nw_connection_t,dispatch_data_t,nw_content_context_t,bool,nw_connection_send_completion_t);
void (*apr_original_nw_cancel)(nw_connection_t);
void (*apr_original_nw_force_cancel)(nw_connection_t);
static nw_path_unsatisfied_reason_t (*path_reason)(nw_path_t);
void apr_nw_observer_init(void) {
    int saved=errno;
    /* Public iOS 14.2 API, resolved dynamically so rootful 14.0/14.1 can still
       load. Its exact enum/path signature comes from the 14.5 SDK path.h. */
    path_reason=dlsym(RTLD_DEFAULT,"nw_path_get_unsatisfied_reason");
    errno=saved;
}

static bool matched_connection(nw_connection_t connection) {
    if(!connection) return false;
    nw_endpoint_t endpoint=nw_connection_copy_endpoint(connection);
    bool target=apr_nw_target(endpoint);
    if(endpoint) nw_release(endpoint);
    return target;
}

static void before_cancel(nw_connection_t connection,bool force) {
    if(!matched_connection(connection))return;
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
        nw_release(path);apr_diag_event(APR_NW_CANCEL_PATH);
    } else apr_diag_event(APR_NW_CANCEL_PATH_MISSING);
    apr_diag_nw_cancel_path(detail);
}
void apr_nw_cancel(nw_connection_t connection) {
    int saved=errno;before_cancel(connection,false);errno=saved;apr_original_nw_cancel(connection);
}
void apr_nw_force_cancel(nw_connection_t connection) {
    int saved=errno;before_cancel(connection,true);errno=saved;apr_original_nw_force_cancel(connection);
}

void apr_nw_start(nw_connection_t connection) {
    int saved=errno;
    if(matched_connection(connection)) {
        apr_diag_event(APR_NW_START);
        apr_diag_nw_start(APR_START_SEEN);
    }
    errno=saved;
    apr_original_nw_start(connection);
}

void apr_nw_state_handler(nw_connection_t connection,nw_connection_state_changed_handler_t handler) {
    int saved=errno;
    if(!matched_connection(connection)) {
        errno=saved;apr_original_nw_state_handler(connection,handler);return;
    }
    if(!handler) {
        /* NULL must actually remove the handler. Do not install our own one. */
        apr_diag_event(APR_NW_STATE_CLEAR);
        errno=saved;apr_original_nw_state_handler(connection,NULL);return;
    }
    /* The callback captures a generation and the caller block, never the
       connection. Older handlers cannot replace the latest diagnostic state. */
    uint32_t generation=apr_diag_nw_handler();
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
        switch(state) {
            case nw_connection_state_ready: apr_diag_event(APR_NW_STATE_READY);break;
            case nw_connection_state_waiting: apr_diag_event(APR_NW_STATE_WAITING);break;
            case nw_connection_state_failed: apr_diag_event(APR_NW_STATE_FAILED);break;
            case nw_connection_state_cancelled: apr_diag_event(APR_NW_STATE_CANCELLED);break;
            default: break;
        }
        errno=incoming;
        handler(state,error);
        /* Capture only the original block and a scalar generation. The system
           copies the wrapper and therefore its nested block. No connection
           capture, retain cycle, pointer table, or added callback queue. */
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
