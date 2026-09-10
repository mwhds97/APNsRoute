#ifndef APNSROUTE_INTERFACE_CHECK_H
#define APNSROUTE_INTERFACE_CHECK_H
#include <stdint.h>
#include "TunnelSelector.h"
enum apr_interface_check { APR_IF_NOT_CHECKED, APR_IF_ALLOWED, APR_IF_EXCLUDED,
    APR_IF_QUERY_FAILED, APR_IF_CHANGED, APR_IF_UNSUPPORTED, APR_IF_CYCLE, APR_IF_LIMIT };
/* detail = status | queried interface count << 8 | observed type mask << 16.
   index identifies the last queried interface, including a failing delegate. */
typedef struct { uint32_t detail,index; } APRInterfaceEvidence;
/* All original one-byte exclusions remain in the submitted request. Zero is
   inactive in Darwin; other values apply to the tunnel and every delegate. */
enum apr_interface_check apr_check_interface_exclusions(int fd,const APRTunnel *tunnel,
    const uint32_t prohibited_types[8],
    APRInterfaceEvidence *evidence,int *error);
#endif
