#ifndef APNSROUTE_CONNECTIONS_H
#define APNSROUTE_CONNECTIONS_H
#include "ConnectionSchema.h"
#include <stdbool.h>
#include <stddef.h>
/* Borrowed pointer VALUES are identity keys only. The table never dereferences,
   retains, releases, cancels, starts or otherwise acts on a connection. */
uint32_t apr_connection_observe(uintptr_t key,unsigned role,bool new_object);
uint32_t apr_connection_find(uintptr_t key);
uint32_t apr_connection_handler_id(uint32_t id);
void apr_connection_handler(uint32_t id,uint32_t handler);
void apr_connection_state(uint32_t id,uint32_t handler,unsigned state,unsigned domain,int error);
void apr_connection_send(uint32_t id);
void apr_connection_read(uint32_t id,unsigned path);
void apr_connection_received(uint32_t id,size_t bytes,bool complete,unsigned domain,int error);
void apr_connection_cancel(uint32_t id,bool force,unsigned path);
void apr_connection_retire_requested(uint32_t id);
#endif
