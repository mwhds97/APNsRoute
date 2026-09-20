#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <notify.h>
#include "../src/Diagnostics.h"
#include "../src/ConnectionStatus.h"
#include "../src/TransportSnapshot.h"
#include "../src/HookEngine.h"

static uint64_t values[APR_DIAG_SLOTS];
static bool registered[APR_DIAG_SLOTS], denied;
static unsigned writes, reads;
static int fail_slot = -1, change_at = -1;
uint32_t notify_register_check(const char *name, int *token) {
    if (denied) return 9;
    const char *suffix = strrchr(name, '.');
    assert(suffix);
    for (unsigned i = 0; i < APR_DIAG_SLOTS; ++i) {
        if (!strcmp(suffix + 1, apr_diag_field_name(i))) {
            assert(!registered[i]); registered[i] = true; *token = (int)i; return 0;
        }
    }
    assert(false); return 9;
}
uint32_t notify_set_state(int token, uint64_t value) {
    assert(token >= 0 && token < APR_DIAG_SLOTS);
    if (token == fail_slot) return 9;
    values[token] = value; ++writes; errno = EIO; return 0;
}
static bool snapshot_read(void *context, const char *name, uint64_t *value) {
    (void)context;
    if ((int)reads++ == change_at) apr_diag_nw_created(false, ETIMEDOUT);
    for (unsigned i = 0; i < APR_TRANSPORT_SLOTS; ++i) {
        if (!strcmp(name, apr_transport_field_name(i))) {
            *value = values[APR_TRANSPORT_FIRST_SLOT + i]; return true;
        }
    }
    return false;
}
static void check_constraints(const uint32_t *snapshot, const APRConstraints *c) {
    assert(snapshot[APR_T_NECP_CONSTRAINTS_SEEN] == c->seen);
    assert(snapshot[APR_T_NECP_CLIENT_FLAGS] == c->request_flags);
    assert(snapshot[APR_T_NECP_CONSTRAINTS_RESTRICTED] == c->restricted);
    assert(snapshot[APR_T_NECP_CONSTRAINTS_INERT] == c->inert);
    assert(snapshot[APR_T_NECP_CONSTRAINTS_UNSUPPORTED] == c->unsupported);
    assert(snapshot[APR_T_NECP_CONSTRAINTS_FIRST] == c->first);
    assert(snapshot[APR_T_NECP_CONSTRAINTS_BLOCKED] == c->blocked);
    assert(snapshot[APR_T_NECP_AGENT_INFO] == c->agent_info);
    assert(snapshot[APR_T_NECP_AGENT_EDIT] == c->edit);
    assert(snapshot[APR_T_NECP_INTERFACE_CHECK] == c->check);
    assert(snapshot[APR_T_NECP_INTERFACE_CHECK_INDEX] == c->check_index);
    assert(!memcmp(snapshot + APR_T_NECP_AGENT_NAME_0, c->agent, 64));
    assert(!memcmp(snapshot + APR_T_NECP_PROHIBITED_TYPES_0, c->prohibited_types, 32));
}
int main(int argc, char **argv) {
    denied = argc > 1 && !strcmp(argv[1], "denied");
    /* Stable external field names are checked independently of their indexes. */
    assert(!strcmp(apr_diag_field_name(APR_D_VERSION), "version"));
    assert(!strcmp(apr_transport_field_name(APR_T_NECP_BINDING_ID), "necp-binding-id"));
    assert(!strcmp(apr_transport_field_name(APR_T_NECP_BINDING_RESULT_INDEX), "necp-binding-result-index"));
    assert(!strcmp(apr_transport_field_name(APR_T_NECP_AGENT_NAME_15), "necp-agent-name-15"));
    assert(!strcmp(apr_transport_field_name(APR_T_NECP_PROHIBITED_TYPES_7), "necp-prohibited-types-7"));
    assert(!apr_diag_field_name(APR_DIAG_SLOTS) && !apr_transport_field_name(APR_TRANSPORT_SLOTS));
    for (unsigned i = 0; i < APR_DIAG_SLOTS; ++i)
        for (unsigned j = 0; j < i; ++j) assert(strcmp(apr_diag_field_name(i), apr_diag_field_name(j)));
    errno = EDOM; apr_diag_init(123456);
    apr_diag_stage(APR_READY, 0, true);
    apr_diag_hook(APR_H_NW | APR_H_NECP | APR_H_NW_SEND | APR_H_NW_FORCE);
    apr_diag_engine(APR_HOOK_GLOBAL, APR_LOOKUP_FOUND);
    for (unsigned event = 0; event < APR_EVENT_COUNT; ++event) apr_diag_event((enum apr_event)event);
    apr_diag_necp_reject(APR_REJECT_ENDPOINT, 201, 16);
    apr_diag_necp_reject(APR_REJECT_TLV, 1, 2); /* First example stays paired. */
    apr_diag_nw_created(true, 0); apr_diag_nw_start(APR_START_SEEN);
    uint32_t current = apr_diag_nw_handler();
    apr_diag_nw_state(current, 1, 3, -9807); apr_diag_nw_state(current, 5, 0, 0);
    apr_diag_nw_report(APR_REPORT_REQUESTED | APR_REPORT_RETURNED | APR_REPORT_AVAILABLE | APR_REPORT_USED);
    apr_diag_nw_cancel_path(APR_PATH_SEEN | APR_PATH_CELL);
    apr_diag_nw_cancel(APR_CANCEL_NATIVE);
    apr_diag_nw_cancel(APR_CANCEL_IMMEDIATE);
    apr_diag_nw_cancel(APR_CANCEL_UNAVAILABLE);
    apr_diag_nw_cancel(APR_CANCEL_APP_FORCE);
    apr_diag_nw_cancel(APR_CANCEL_NONE); /* Invalid actions must not count. */
    apr_diag_nw_cancel(99);
    uint32_t row[APR_CONNECTION_FIELD_COUNT]={[APR_R_ID]=9,[APR_R_ROLE]=APR_ROLE_COURIER,
        [APR_R_HANDLER]=5,[APR_R_BYTES]=123};
    apr_diag_connection(0,row);apr_diag_connection_overflow();
    apr_diag_connection(99,row);apr_diag_connection(0,NULL);
    APRRetirementStatus retirement={.status=APR_RET_SETTLING,.network=APR_RET_WIFI,.epoch=3,
        .held=4,.pending=2,.requests=7,.last_id=9,.reason=APR_RET_QUIET,.skipped=1,.awaiting=1,
        .vpn_state=APR_VPN_ON,.vpn_index=8,.vpn_epoch=4,.vpn_pending=2,.vpn_requests=5,
        .vpn_reason=APR_RET_VPN_REPLACED,.vpn_notify=2,.vpn_notify_error=9,.vpn_error=EACCES,.quiet_state=APR_QUIET_WAITING,.quiet_epoch=5,.quiet_events=3,
        .quiet_causes=APR_QUIET_PHYSICAL|APR_QUIET_VPN_ON|APR_QUIET_VPN_OFF,.quiet_remaining_ms=1200,.batches=2};
    apr_diag_retirement(&retirement);apr_diag_retirement(NULL);
    if (!denied) {
        uint32_t snapshot[APR_TRANSPORT_SLOTS];
        assert(apr_transport_snapshot(snapshot_read, NULL, snapshot));
        assert(snapshot[APR_T_RET_STATUS]==APR_RET_SETTLING && snapshot[APR_T_RET_NETWORK]==APR_RET_WIFI);
        assert(snapshot[APR_T_RET_EPOCH]==3 && snapshot[APR_T_RET_HELD]==4 && snapshot[APR_T_RET_PENDING]==2);
        assert(snapshot[APR_T_RET_REQUESTS]==7 && snapshot[APR_T_RET_LAST_ID]==9);
        assert(snapshot[APR_T_RET_AWAITING]==1);
        assert(snapshot[APR_T_QUIET_STATE]==APR_QUIET_WAITING && snapshot[APR_T_QUIET_EPOCH]==5);
        assert(snapshot[APR_T_QUIET_EVENTS]==3 && snapshot[APR_T_QUIET_CAUSES]==7);
        assert(snapshot[APR_T_QUIET_REMAINING_MS]==1200 && snapshot[APR_T_RET_BATCHES]==2);
        assert(snapshot[APR_T_VPN_STATE]==APR_VPN_ON && snapshot[APR_T_VPN_INDEX]==8);
        assert(snapshot[APR_T_VPN_EPOCH]==4 && snapshot[APR_T_VPN_PENDING]==2 && snapshot[APR_T_VPN_REQUESTS]==5);
        assert(snapshot[APR_T_VPN_REASON]==APR_RET_VPN_REPLACED && snapshot[APR_T_VPN_NOTIFY]==2);
        assert(snapshot[APR_T_VPN_NOTIFY_ERROR]==9 && snapshot[APR_T_VPN_ERROR]==EACCES);
        assert(snapshot[APR_T_RET_REASON]==APR_RET_QUIET && !snapshot[APR_T_RET_ERROR] && snapshot[APR_T_RET_SKIPPED]==1);
        fail_slot=APR_TRANSPORT_FIRST_SLOT+APR_T_RET_REASON;
        retirement.reason=APR_RET_VPN_OFF;retirement.requests=8;apr_diag_retirement(&retirement);
        assert(!apr_transport_snapshot(snapshot_read,NULL,snapshot));
        fail_slot=-1;apr_diag_retirement(&retirement);
        assert(apr_transport_snapshot(snapshot_read,NULL,snapshot));
        assert(snapshot[APR_T_RET_REASON]==APR_RET_VPN_OFF && snapshot[APR_T_RET_REQUESTS]==8);
        assert(snapshot[APR_T_NW_CREATED] == (APR_CREATE_SEEN | APR_CREATE_OK));
        assert(snapshot[APR_T_NW_START] == APR_START_SEEN);
        assert(snapshot[APR_T_NW_CANCEL_NORMAL] == 3);
        assert(snapshot[APR_T_NW_CANCEL_IMMEDIATE] == 1);
        assert(snapshot[APR_T_NW_CANCEL_APP_FORCE] == 1);
        assert(snapshot[APR_T_NW_CANCEL_ACTION] == APR_CANCEL_APP_FORCE);
        assert((snapshot[APR_T_NW_STATE] & 255) == 5);
        assert(((snapshot[APR_T_NW_STATE] >> 8) & 255) == 3);
        assert(!(snapshot[APR_T_NW_STATE] & APR_STATE_CURRENT_ERROR));
        assert((int32_t)snapshot[APR_T_NW_STATE_ERROR] == -9807);
        assert(snapshot[APR_T_NW_HANDLER_ID] == current);
        assert(((snapshot[APR_T_NW_STATE] >> APR_STATE_HISTORY_SHIFT) & 63) == ((1U << 1) | (1U << 5)));
        assert(snapshot[APR_T_NW_CANCEL_PATH] == (APR_PATH_SEEN | APR_PATH_CELL));
        reads = 0; change_at = 4;
        assert(apr_transport_snapshot(snapshot_read, NULL, snapshot));
        assert(reads > APR_TRANSPORT_SLOTS && (int32_t)snapshot[APR_T_NW_CREATE_ERRNO] == ETIMEDOUT);
        assert(!(snapshot[APR_T_NW_CREATED] & APR_CREATE_OK)); change_at = -1;
        fail_slot = APR_TRANSPORT_FIRST_SLOT+APR_T_NW_STATE_ERROR; apr_diag_nw_state(current, 4, 2, -65554);
        assert(!apr_transport_snapshot(snapshot_read, NULL, snapshot));
        fail_slot = -1; apr_diag_nw_start(APR_START_SEEN);
        assert(apr_transport_snapshot(snapshot_read, NULL, snapshot));
        assert((int32_t)snapshot[APR_T_NW_STATE_ERROR] == -65554);
        uint32_t newer = apr_diag_nw_handler(); assert(newer > current);
        apr_diag_nw_state(current, 3, 0, 0);
        assert(apr_transport_snapshot(snapshot_read, NULL, snapshot));
        assert(!((snapshot[APR_T_NW_STATE] >> APR_STATE_HISTORY_SHIFT) & 63));
        apr_diag_nw_state(newer, 3, 0, 0); apr_diag_nw_state(newer, 5, 0, 0);
        assert(apr_transport_snapshot(snapshot_read, NULL, snapshot));
        assert(((snapshot[APR_T_NW_STATE] >> APR_STATE_HISTORY_SHIFT) & 63) == ((1U << 3) | (1U << 5)));
        APRConstraints metadata = {.seen = APR_C_PARENT};
        APRConstraints c = {.request_flags=0x1000, .seen = APR_C_REQUIRE_TYPE | APR_C_REQUIRE_AGENT | APR_C_PARENT,
            .restricted = APR_C_REQUIRE_TYPE, .inert = APR_C_REQUIRE_TYPE,
            .unsupported = APR_C_REQUIRE_AGENT, .first = 111U | (1U << 8) | (5U << 24),
            .blocked = APR_C_REQUIRE_TYPE | APR_C_REQUIRE_AGENT, .agent_info = 1 | APR_AGENT_NAMES | APR_AGENT_OTHER,
            .edit = 1 | APR_EDIT_SUBMITTED | APR_EDIT_ACCEPTED, .check = 1 | (2U << 8), .check_index = 5};
        memcpy(c.agent, "Cellular", 9); memcpy(c.agent + 32, "Internet", 9);
        c.agent[30] = 'X'; c.agent[62] = 'Y';
        for (unsigned i = 0; i < 8; ++i) c.prohibited_types[i] = UINT32_C(0x80000000) | (1U << i);
        uint32_t first = apr_diag_binding(2, 12, 0, &metadata), second = apr_diag_binding(7, 0, 0, &c);
        assert(second > first); apr_diag_binding_result(first, 5, 12, 12);
        assert(apr_transport_snapshot(snapshot_read, NULL, snapshot));
        assert(snapshot[APR_T_NECP_BINDING_ID] == second && !snapshot[APR_T_NECP_BINDING_RESULT]);
        check_constraints(snapshot, &c);
        apr_diag_binding_result(second, 29, 12, 13);
        assert(apr_transport_snapshot(snapshot_read, NULL, snapshot));
        assert(snapshot[APR_T_NECP_BINDING_RESULT] == 29 && snapshot[APR_T_NECP_BINDING_POLICY] == 12 && snapshot[APR_T_NECP_BINDING_RESULT_INDEX] == 13);
        fail_slot = APR_TRANSPORT_FIRST_SLOT+APR_T_NECP_BINDING_RESULT_INDEX; apr_diag_binding_result(second, 13, 12, 14);
        assert(!apr_transport_snapshot(snapshot_read, NULL, snapshot));
        fail_slot = -1; apr_diag_nw_created(true, 0);
        assert(apr_transport_snapshot(snapshot_read, NULL, snapshot) && snapshot[APR_T_NECP_BINDING_RESULT_INDEX] == 14);
        uint32_t third = apr_diag_binding(1, 0, 0, NULL); assert(third > second);
        apr_diag_binding_result(second, 29, 12, 13);
        assert(apr_transport_snapshot(snapshot_read, NULL, snapshot));
        assert(snapshot[APR_T_NECP_BINDING_ID] == third && !snapshot[APR_T_NECP_BINDING_RESULT] && !snapshot[APR_T_NECP_BINDING_RESULT_INDEX]);
        for (unsigned i = APR_T_NECP_CONSTRAINTS_SEEN; i < APR_TRANSPORT_SLOTS; ++i) assert(!snapshot[i]);
        fail_slot = APR_DIAG_SLOTS - 1;
        uint32_t fourth = apr_diag_binding(7, 0, 0, &c); assert(fourth > third);
        assert(!apr_transport_snapshot(snapshot_read, NULL, snapshot));
        fail_slot = -1; apr_diag_binding_result(fourth, 13, 12, 5);
        assert(apr_transport_snapshot(snapshot_read, NULL, snapshot));
        assert(snapshot[APR_T_NECP_BINDING_ID] == fourth && snapshot[APR_T_NECP_BINDING_RESULT_INDEX] == 5);
        check_constraints(snapshot, &c);
        assert(!memcmp(snapshot+APR_T_CONN_0_ID,row,sizeof(row)));
        assert(snapshot[APR_T_CONNECTION_OVERFLOW]==1);
        unsigned before_writes=writes;
        row[APR_R_BYTES]=999;apr_diag_connection(0,row);
        assert(writes-before_writes==3); /* sequence plus exactly one changed field */
        fail_slot=APR_TRANSPORT_FIRST_SLOT+APR_T_CONN_0_RECEIVED;
        row[APR_R_RECEIVED]=2;row[APR_R_BYTES]=1000;apr_diag_connection(0,row);
        assert(!apr_transport_snapshot(snapshot_read,NULL,snapshot));
        fail_slot=-1;apr_diag_nw_start(APR_START_SEEN);
        assert(apr_transport_snapshot(snapshot_read,NULL,snapshot));
        assert(!memcmp(snapshot+APR_T_CONN_0_ID,row,sizeof(row)));
        fail_slot=APR_TRANSPORT_FIRST_SLOT+APR_T_SEQ;
        row[APR_R_BYTES]=1001;apr_diag_connection(0,row);
        /* Failed opening sequence cannot expose a half-written transaction. */
        assert(apr_transport_snapshot(snapshot_read,NULL,snapshot));
        assert(snapshot[APR_T_CONN_0_BYTES]==1000);
        fail_slot=-1;apr_diag_nw_start(APR_START_SEEN);
        assert(apr_transport_snapshot(snapshot_read,NULL,snapshot));
        assert(snapshot[APR_T_CONN_0_BYTES]==1001);
        values[APR_TRANSPORT_FIRST_SLOT + APR_T_NW_REPORT] = 0;
        assert(!apr_transport_snapshot(snapshot_read, NULL, snapshot));
        for (unsigned i = 0; i < APR_DIAG_SLOTS; ++i) assert(registered[i]);
        assert((values[APR_D_STATUS] & 255) == APR_READY && (values[APR_D_STATUS] & APR_DIAG_UNBIND));
        assert(((values[APR_D_STATUS] >> 17) & APR_HOOK_MASK) == (APR_H_NW | APR_H_NECP | APR_H_NW_SEND | APR_H_NW_FORCE));
        assert((uint32_t)values[APR_D_VERSION] == APR_BUILD_ID);
        for (unsigned event = 0; event < APR_EVENT_COUNT; ++event) {
            unsigned slot = event < 32 ? APR_D_EVENTS : APR_D_EVENTS2;
            assert((values[slot] & UINT64_C(0xffffffff00000000)) == APR_DIAG_MAGIC);
            assert((uint32_t)values[slot] & (UINT32_C(1) << (event % 32)));
        }
        assert((uint32_t)values[APR_D_NECP_REJECT] == (APR_REJECT_ENDPOINT | (201U << 8) | (16U << 16)));
    } else assert(!writes);
    assert(errno == EDOM);
    puts(denied ? "PASS: denied doctor channel leaves runtime unaffected" :
        "PASS: shared diagnostic schema, all event banks, atomic request/result/name/type snapshots, stale rejection and partial-write recovery");
}
