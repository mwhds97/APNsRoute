#ifndef APNSROUTE_NECP_HOOKS_H
#define APNSROUTE_NECP_HOOKS_H
#include <stddef.h>
#include <stdint.h>
extern int (*apr_original_necp)(int,uint32_t,uint8_t *,size_t,uint8_t *,size_t);
int apr_necp(int fd,uint32_t action,uint8_t *client,size_t client_length,uint8_t *buffer,size_t size);
#endif
