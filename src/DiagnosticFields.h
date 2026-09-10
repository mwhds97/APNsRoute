#ifndef APNSROUTE_DIAGNOSTIC_FIELDS_H
#define APNSROUTE_DIAGNOSTIC_FIELDS_H
#include <stddef.h>
/* Versioned fixed fields shared by apsd, doctor and the snapshot reader.
   Names and positions are defined once; removed experiments have no slots. */
#define APR_DIAGNOSTIC_HEAD_FIELDS(X) \
    X(STATUS, "status") \
    X(EVENTS, "events") \
    X(ENGINE, "engine") \
    X(VERSION, "version") \
    X(EVENTS2, "events2") \
    X(NECP_REJECT, "necp-reject")

#define APR_TRANSPORT_FIELDS(X) \
    X(SEQ, "transport-seq") \
    X(NW_CREATED, "nw-created") \
    X(NW_CREATE_ERRNO, "nw-create-errno") \
    X(NW_START, "nw-start") \
    X(NW_STATE, "nw-state") \
    X(NW_STATE_ERROR, "nw-state-error") \
    X(NW_REPORT, "nw-report") \
    X(NW_HANDLER_ID, "nw-handler-id") \
    X(NW_CANCEL_PATH, "nw-cancel-path") \
    X(NECP_BINDING_ID, "necp-binding-id") \
    X(NECP_BINDING_INDEX, "necp-binding-index") \
    X(NECP_BINDING_STATUS, "necp-binding-status") \
    X(NECP_BINDING_ERRNO, "necp-binding-errno") \
    X(NECP_BINDING_RESULT, "necp-binding-result") \
    X(NECP_BINDING_POLICY, "necp-binding-policy") \
    X(NECP_BINDING_RESULT_INDEX, "necp-binding-result-index") \
    X(NECP_CONSTRAINTS_SEEN, "necp-constraints-seen") \
    X(NECP_CONSTRAINTS_RESTRICTED, "necp-constraints-restricted") \
    X(NECP_CONSTRAINTS_INERT, "necp-constraints-inert") \
    X(NECP_CONSTRAINTS_UNSUPPORTED, "necp-constraints-unsupported") \
    X(NECP_CONSTRAINTS_FIRST, "necp-constraints-first") \
    X(NECP_CONSTRAINTS_BLOCKED, "necp-constraints-blocked") \
    X(NECP_AGENT_INFO, "necp-agent-info") \
    X(NECP_AGENT_EDIT, "necp-agent-edit") \
    X(NECP_INTERFACE_CHECK, "necp-interface-check") \
    X(NECP_INTERFACE_CHECK_INDEX, "necp-interface-check-index") \
    X(NECP_AGENT_NAME_0, "necp-agent-name-0") \
    X(NECP_AGENT_NAME_1, "necp-agent-name-1") \
    X(NECP_AGENT_NAME_2, "necp-agent-name-2") \
    X(NECP_AGENT_NAME_3, "necp-agent-name-3") \
    X(NECP_AGENT_NAME_4, "necp-agent-name-4") \
    X(NECP_AGENT_NAME_5, "necp-agent-name-5") \
    X(NECP_AGENT_NAME_6, "necp-agent-name-6") \
    X(NECP_AGENT_NAME_7, "necp-agent-name-7") \
    X(NECP_AGENT_NAME_8, "necp-agent-name-8") \
    X(NECP_AGENT_NAME_9, "necp-agent-name-9") \
    X(NECP_AGENT_NAME_10, "necp-agent-name-10") \
    X(NECP_AGENT_NAME_11, "necp-agent-name-11") \
    X(NECP_AGENT_NAME_12, "necp-agent-name-12") \
    X(NECP_AGENT_NAME_13, "necp-agent-name-13") \
    X(NECP_AGENT_NAME_14, "necp-agent-name-14") \
    X(NECP_AGENT_NAME_15, "necp-agent-name-15") \
    X(NECP_PROHIBITED_TYPES_0, "necp-prohibited-types-0") \
    X(NECP_PROHIBITED_TYPES_1, "necp-prohibited-types-1") \
    X(NECP_PROHIBITED_TYPES_2, "necp-prohibited-types-2") \
    X(NECP_PROHIBITED_TYPES_3, "necp-prohibited-types-3") \
    X(NECP_PROHIBITED_TYPES_4, "necp-prohibited-types-4") \
    X(NECP_PROHIBITED_TYPES_5, "necp-prohibited-types-5") \
    X(NECP_PROHIBITED_TYPES_6, "necp-prohibited-types-6") \
    X(NECP_PROHIBITED_TYPES_7, "necp-prohibited-types-7")

#define APR_HEAD_ENUM(field, name) APR_D_##field,
enum { APR_DIAGNOSTIC_HEAD_FIELDS(APR_HEAD_ENUM) APR_TRANSPORT_FIRST_SLOT };
#undef APR_HEAD_ENUM
#define APR_TRANSPORT_ENUM(field, name) APR_T_##field,
enum { APR_TRANSPORT_FIELDS(APR_TRANSPORT_ENUM) APR_TRANSPORT_SLOTS };
#undef APR_TRANSPORT_ENUM
#define APR_DIAG_SLOTS (APR_TRANSPORT_FIRST_SLOT + APR_TRANSPORT_SLOTS)
_Static_assert(APR_T_NECP_AGENT_NAME_15 - APR_T_NECP_AGENT_NAME_0 == 15, "agent word layout");
_Static_assert(APR_T_NECP_PROHIBITED_TYPES_7 - APR_T_NECP_PROHIBITED_TYPES_0 == 7, "prohibition word layout");
static inline const char *apr_diag_field_name(unsigned slot) {
#define APR_FIELD_NAME(field, name) name,
    static const char *names[] = {
        APR_DIAGNOSTIC_HEAD_FIELDS(APR_FIELD_NAME)
        APR_TRANSPORT_FIELDS(APR_FIELD_NAME)
    };
#undef APR_FIELD_NAME
    _Static_assert(sizeof(names) / sizeof(*names) == APR_DIAG_SLOTS, "field name count");
    return slot < APR_DIAG_SLOTS ? names[slot] : NULL;
}
static inline const char *apr_transport_field_name(unsigned slot) {
    return slot < APR_TRANSPORT_SLOTS ? apr_diag_field_name(APR_TRANSPORT_FIRST_SLOT + slot) : NULL;
}
#endif
