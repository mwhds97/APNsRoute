#ifndef APNSROUTE_TUNNEL_SELECTOR_H
#define APNSROUTE_TUNNEL_SELECTOR_H
#include <stdint.h>
enum { APR_TUN_V4=1, APR_TUN_V6=2 };
enum apr_tunnel_choice { APR_TUN_UNAVAILABLE, APR_TUN_UNIQUE, APR_TUN_NONE,
    APR_TUN_AMBIGUOUS, APR_TUN_FAMILY, APR_TUN_CHANGED };
typedef struct { char name[16]; uint32_t index; unsigned families,count; } APRTunnel;
enum apr_tunnel_choice apr_tunnel_select(unsigned family,APRTunnel *out,int *error);
#endif
