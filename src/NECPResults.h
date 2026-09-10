#ifndef APNSROUTE_NECP_RESULTS_H
#define APNSROUTE_NECP_RESULTS_H
#include <stddef.h>
#include <stdint.h>
void apr_necp_record_binding(int fd,const uint8_t id[16],uint32_t generation,uint32_t requested_index);
void apr_necp_result_action(int fd,uint32_t action,const uint8_t id[16],
    const uint8_t *buffer,size_t capacity,int result);
#endif
