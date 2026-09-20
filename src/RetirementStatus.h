#ifndef APNSROUTE_RETIREMENT_STATUS_H
#define APNSROUTE_RETIREMENT_STATUS_H
#include <stdint.h>

/* One duration for the runtime deadline and the doctor's displayed minimum. */
#define APR_QUIET_PERIOD_MS UINT32_C(2000)

enum apr_retirement_status { APR_RET_NOT_INITIALIZED, APR_RET_DISABLED,
    APR_RET_WAITING, APR_RET_UNKNOWN, APR_RET_IDLE, APR_RET_SETTLING, APR_RET_UNAVAILABLE,
    APR_RET_RECOVERING };
enum apr_retirement_reason { APR_RET_NONE, APR_RET_QUIET,
    APR_RET_VPN_ON, APR_RET_VPN_OFF, APR_RET_VPN_REPLACED };
enum apr_quiet_state { APR_QUIET_IDLE, APR_QUIET_WAITING, APR_QUIET_BLOCKED };
enum apr_quiet_cause { APR_QUIET_PHYSICAL=1, APR_QUIET_VPN_ON=2,
    APR_QUIET_VPN_OFF=4, APR_QUIET_VPN_REPLACED=8, APR_QUIET_UNCERTAIN=16 };
enum apr_vpn_state { APR_VPN_UNKNOWN, APR_VPN_OFF, APR_VPN_ON,
    APR_VPN_AMBIGUOUS, APR_VPN_UNAVAILABLE };
enum { APR_RET_WIFI=3, APR_RET_CELLULAR=5 };
typedef struct {
    uint32_t status,network,epoch,held,pending,requests,last_id,reason,error,skipped,awaiting;
    uint32_t vpn_state,vpn_index,vpn_epoch,vpn_pending,vpn_requests,vpn_reason;
    uint32_t vpn_notify,vpn_notify_error,vpn_error;
    uint32_t quiet_state,quiet_epoch,quiet_events,quiet_causes,quiet_remaining_ms,batches;
} APRRetirementStatus;
#define APR_RETIREMENT_FIELDS(X) \
    X(RET_STATUS,"ret-status") \
    X(RET_NETWORK,"ret-network") \
    X(RET_EPOCH,"ret-epoch") \
    X(RET_HELD,"ret-held") \
    X(RET_PENDING,"ret-pending") \
    X(RET_REQUESTS,"ret-requests") \
    X(RET_LAST_ID,"ret-last-id") \
    X(RET_REASON,"ret-reason") \
    X(RET_ERROR,"ret-error") \
    X(RET_SKIPPED,"ret-skipped") \
    X(RET_AWAITING,"ret-awaiting") \
    X(VPN_STATE,"vpn-state") \
    X(VPN_INDEX,"vpn-index") \
    X(VPN_EPOCH,"vpn-epoch") \
    X(VPN_PENDING,"vpn-pending") \
    X(VPN_REQUESTS,"vpn-requests") \
    X(VPN_REASON,"vpn-reason") \
    X(VPN_NOTIFY,"vpn-notify") \
    X(VPN_NOTIFY_ERROR,"vpn-notify-error") \
    X(VPN_ERROR,"vpn-error") \
    X(QUIET_STATE,"quiet-state") \
    X(QUIET_EPOCH,"quiet-epoch") \
    X(QUIET_EVENTS,"quiet-events") \
    X(QUIET_CAUSES,"quiet-causes") \
    X(QUIET_REMAINING_MS,"quiet-remaining-ms") \
    X(RET_BATCHES,"ret-batches")
#endif
