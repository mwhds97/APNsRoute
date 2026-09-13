#ifndef APNSROUTE_RETIREMENT_STATUS_H
#define APNSROUTE_RETIREMENT_STATUS_H
#include <stdint.h>
enum apr_retirement_status { APR_RET_NOT_INITIALIZED, APR_RET_DISABLED,
    APR_RET_WAITING, APR_RET_UNKNOWN, APR_RET_IDLE, APR_RET_SETTLING, APR_RET_UNAVAILABLE,
    APR_RET_RECOVERING };
enum apr_retirement_reason { APR_RET_NONE, APR_RET_NEW_DATA, APR_RET_DEADLINE };
enum { APR_RET_WIFI=3, APR_RET_CELLULAR=5 };
typedef struct {
    uint32_t status,network,epoch,held,pending,requests,last_id,reason,error,skipped,awaiting;
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
    X(RET_AWAITING,"ret-awaiting")
#endif
