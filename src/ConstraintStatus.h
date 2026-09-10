#ifndef APNSROUTE_CONSTRAINT_STATUS_H
#define APNSROUTE_CONSTRAINT_STATUS_H
#include <stdint.h>
/* Fixed classification of the original ADD input, paired with its generation.
   No agent UUIDs, resolver tags, destinations or payloads retained. One readable
   agent domain/type pair is exposed as system metadata, each at most 31 chars.
   Bits map to TLV types 9,100,101,102,103,111,112,113,150 respectively. */
enum apr_constraint_bit {
    APR_C_BOUND=1, APR_C_PROHIBIT_INTERFACE=2, APR_C_PROHIBIT_TYPE=4,
    APR_C_PROHIBIT_AGENT=8, APR_C_PROHIBIT_AGENT_TYPE=16, APR_C_REQUIRE_TYPE=32,
    APR_C_REQUIRE_AGENT=64, APR_C_REQUIRE_AGENT_TYPE=128, APR_C_PARENT=256
};
typedef struct {
    uint32_t seen, restricted, inert, unsupported, first;
    uint32_t blocked,agent_info,edit,check,check_index;
    uint8_t agent[64];
    /* All unique one-byte PROHIBIT_IF_TYPE values, including inactive zero.
       Union is conservative beyond Darwin's four slots / zero terminator. */
    uint32_t prohibited_types[8];
} APRConstraints;
enum { APR_AGENT_NAMES=1U<<8, APR_AGENT_MULTIPLE=1U<<9, APR_AGENT_BAD_NAME=1U<<10,
    APR_AGENT_EXISTING_PREFERENCE=1U<<11, APR_AGENT_TOO_MANY=1U<<12,
    APR_AGENT_OTHER=1U<<13,
    APR_EDIT_SUBMITTED=1U<<8, APR_EDIT_ACCEPTED=1U<<9 };
/* agent_info: nonempty type-113 field count (saturates at 255) and flags above.
   edit: converted type-113 count plus submitted/accepted flags. Conversion is
   113 REQUIRE_AGENT_TYPE -> 123 PREFER_AGENT_TYPE; all 64 value bytes remain.
   check/check_index: read-only selected-tunnel/delegate exclusion check. */
/* first: first original nonzero/unsupported TLV type in bits 0..7, length in 8..23,
   interface-type scalar in 24..31 ONLY for types 101/111. Zero means none.
   This field no longer identifies the first blocker: some restrictions can
   now be satisfied or converted. The blocked mask identifies remaining guards.
   Restricted/unsupported bits never clear, even when a later TLV is inert.
   A valid PARENT_ID is metadata: seen, but neither restricted nor inert. */
#endif
