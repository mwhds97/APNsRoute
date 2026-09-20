#ifndef APNSROUTE_RETIREMENT_H
#define APNSROUTE_RETIREMENT_H
#include <Network/Network.h>
#include <stdint.h>
#include <stdbool.h>
#include "RetirementStatus.h"
typedef void (*APRRetireFunction)(nw_connection_t);
void apr_retirement_init(bool enabled,APRRetireFunction request_endpoint);
/* Called only for rule-matched, caller-owned connections that apsd starts. */
void apr_retirement_start(nw_connection_t connection,uint32_t id,uint32_t handler);
void apr_retirement_handler(uint32_t id,uint32_t handler);
void apr_retirement_state(uint32_t id,uint32_t handler,unsigned state);
void apr_retirement_forget(uint32_t id);
#endif
