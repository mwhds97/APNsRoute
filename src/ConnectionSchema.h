#ifndef APNSROUTE_CONNECTION_SCHEMA_H
#define APNSROUTE_CONNECTION_SCHEMA_H
#include <stdint.h>
#define APR_CONNECTION_COUNT 8
#define APR_CONNECTION_FIELDS(X,P,N) \
    X(P##_ID,N "id") \
    X(P##_HANDLER,N "handler") \
    X(P##_ROLE,N "role") \
    X(P##_STATE,N "state") \
    X(P##_ERROR_INFO,N "error-info") \
    X(P##_ERROR_CODE,N "error-code") \
    X(P##_SENDS,N "sends") \
    X(P##_READS,N "reads") \
    X(P##_RECEIVED,N "received") \
    X(P##_BYTES,N "bytes") \
    X(P##_COMPLETES,N "completes") \
    X(P##_CANCELS,N "cancels") \
    X(P##_RETIRE_REQUESTS,N "retire-requests") \
    X(P##_PATH,N "path")
#define APR_RECORD_ENUM(field,name) field,
enum { APR_CONNECTION_FIELDS(APR_RECORD_ENUM,APR_R,"") APR_CONNECTION_FIELD_COUNT };
#undef APR_RECORD_ENUM
#define APR_CONNECTION_DIAGNOSTIC_FIELDS(X) \
    APR_CONNECTION_FIELDS(X,CONN_0,"conn-0-") \
    APR_CONNECTION_FIELDS(X,CONN_1,"conn-1-") \
    APR_CONNECTION_FIELDS(X,CONN_2,"conn-2-") \
    APR_CONNECTION_FIELDS(X,CONN_3,"conn-3-") \
    APR_CONNECTION_FIELDS(X,CONN_4,"conn-4-") \
    APR_CONNECTION_FIELDS(X,CONN_5,"conn-5-") \
    APR_CONNECTION_FIELDS(X,CONN_6,"conn-6-") \
    APR_CONNECTION_FIELDS(X,CONN_7,"conn-7-")
enum apr_connection_role { APR_ROLE_UNKNOWN,APR_ROLE_INIT,APR_ROLE_COURIER,
    APR_ROLE_HOST,APR_ROLE_ADDRESS };
enum { APR_ROW_HANDLER_CLEARED=1U<<8, APR_ROW_HISTORY_SHIFT=16 };
enum { APR_ERROR_STATE=1, APR_ERROR_RECEIVE=2 };
#endif
