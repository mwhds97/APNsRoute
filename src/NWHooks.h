#ifndef APNSROUTE_NW_HOOKS_H
#define APNSROUTE_NW_HOOKS_H
#include <Network/Network.h>
bool apr_nw_target(nw_endpoint_t endpoint);
extern nw_connection_t (*apr_original_nw_create)(nw_endpoint_t,nw_parameters_t);
nw_connection_t apr_nw_create(nw_endpoint_t,nw_parameters_t);
#endif
