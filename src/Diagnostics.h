#ifndef APNSROUTE_DIAGNOSTICS_H
#define APNSROUTE_DIAGNOSTICS_H
#include <stdbool.h>
#include <stdint.h>
#include "ConstraintStatus.h"
#include "DiagnosticFields.h"
#include "Version.h"

/* Protocol 22: endpoint retirement requests and awaiting-native-result state. */
#define APR_DIAG_PROTOCOL "22"
#define APR_DIAG_MAGIC (UINT64_C(0x41505246) << 32)
#define APR_DIAG_PREFIX "local.apnsroute.v" APR_DIAG_PROTOCOL
#define APR_DIAG_UNBIND (UINT64_C(1) << 16)
enum apr_stage { APR_ENTERED = 1, APR_WRONG_OS, APR_CONFIG_ERROR, APR_DISABLED,
    APR_INVALID_MODE, APR_READY, APR_NO_HOOK_ENGINE, APR_NATIVE_READY };
enum apr_event {
    APR_NW_MATCHED,
    APR_NECP_CALL,
    APR_NECP_MATCHED,
    APR_NECP_CELLULAR,
    APR_NECP_CHANGED,
    APR_NECP_FAILED,
    APR_NECP_INVALID,
    APR_NW_ANY,
    APR_NECP_PARSED,
    APR_NECP_IPPROTO8,
    APR_NECP_LEGACY_ADDRESS,
    APR_NECP_NO_CELLULAR,
    APR_NECP_TUNNEL_PROHIBITED,
    APR_NECP_RESULT,
    APR_NECP_RESULT_UTUN,
    APR_NECP_RESULT_CELLULAR,
    APR_NECP_RESULT_NEXUS,
    APR_NECP_RESULT_TUNNEL_POLICY,
    APR_NECP_RESULT_INVALID,
    APR_NECP_TRACK_FULL,
    APR_NECP_RESULT_NO_INTERFACE,
    APR_NECP_RESULT_LOOPBACK,
    APR_NECP_PRIMARY_UTUN,
    APR_NECP_PRIMARY_CELLULAR,
    APR_NECP_PRIMARY_LOOPBACK,
    APR_NECP_SCOPED_POLICY,
    APR_NECP_PASS_POLICY,
    APR_NW_START,
    APR_NW_STATE_HANDLER,
    APR_NW_STATE_CLEAR,
    APR_NW_SEND,
    APR_NW_CREATE_FAILED,
    APR_NW_REPORT_REQUESTED,
    APR_NW_REPORT_AVAILABLE,
    APR_NW_REPORT_UNAVAILABLE,
    APR_NW_STATE_READY,
    APR_NW_STATE_WAITING,
    APR_NW_STATE_FAILED,
    APR_NW_STATE_CANCELLED,
    APR_NW_CANCEL_PATH,
    APR_NW_CANCEL_PATH_MISSING,
    APR_EVENT_COUNT
};
enum apr_necp_reject { APR_REJECT_BUFFER=1, APR_REJECT_TLV, APR_REJECT_TEXT,
    APR_REJECT_ENDPOINT, APR_REJECT_PROTOCOL, APR_REJECT_FLAGS, APR_REJECT_CONFLICT };
enum apr_hook_bit {
    APR_H_NW = 1U << 0, APR_H_NECP = 1U << 1,
    APR_H_NW_START = 1U << 2, APR_H_NW_STATE = 1U << 3,
    APR_H_NW_SEND = 1U << 4, APR_H_NW_CANCEL = 1U << 5,
    APR_H_NW_FORCE = 1U << 6, APR_H_NW_RECEIVE = 1U << 7,
    APR_H_NW_RECEIVE_MESSAGE = 1U << 8
};
#define APR_HOOK_MASK 511U
void apr_diag_init(uint64_t incarnation);
void apr_diag_stage(enum apr_stage stage, int config_error, bool unbind);
void apr_diag_hook(unsigned mask);
void apr_diag_event(enum apr_event event);
void apr_diag_engine(unsigned source, unsigned result);
void apr_diag_necp_reject(enum apr_necp_reject reason, unsigned type, uint32_t length);
void apr_diag_nw_created(bool created,int error);
void apr_diag_nw_start(unsigned detail);
uint32_t apr_diag_nw_handler(void);
void apr_diag_nw_state(uint32_t generation,unsigned state,unsigned domain,int error);
void apr_diag_nw_report(unsigned detail);
void apr_diag_nw_cancel_path(unsigned detail);
void apr_diag_nw_cancel(unsigned action);
void apr_diag_connection(unsigned slot,const uint32_t value[APR_CONNECTION_FIELD_COUNT]);
void apr_diag_connection_overflow(void);
void apr_diag_retirement(const APRRetirementStatus *status);
uint32_t apr_diag_binding(uint32_t status,uint32_t index,int error,const APRConstraints *constraints);
void apr_diag_binding_result(uint32_t generation,uint32_t flags,uint32_t policy,uint32_t index);
#endif
