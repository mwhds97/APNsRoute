#ifndef APNSROUTE_NW_OBSERVER_H
#define APNSROUTE_NW_OBSERVER_H
#include <Network/Network.h>
extern void (*apr_original_nw_start)(nw_connection_t);
void apr_nw_start(nw_connection_t);
void apr_nw_observer_init(void);
extern void (*apr_original_nw_cancel)(nw_connection_t);
extern void (*apr_original_nw_force_cancel)(nw_connection_t);
void apr_nw_cancel(nw_connection_t);
void apr_nw_force_cancel(nw_connection_t);
void apr_nw_retire(nw_connection_t);
bool apr_nw_retirement_available(void);
#ifdef __BLOCKS__
extern void (*apr_original_nw_state_handler)(nw_connection_t,nw_connection_state_changed_handler_t);
extern void (*apr_original_nw_send)(nw_connection_t,dispatch_data_t,nw_content_context_t,bool,nw_connection_send_completion_t);
extern void (*apr_original_nw_receive)(nw_connection_t,uint32_t,uint32_t,nw_connection_receive_completion_t);
extern void (*apr_original_nw_receive_message)(nw_connection_t,nw_connection_receive_completion_t);
void apr_nw_state_handler(nw_connection_t,nw_connection_state_changed_handler_t);
void apr_nw_send(nw_connection_t,dispatch_data_t,nw_content_context_t,bool,nw_connection_send_completion_t);
void apr_nw_receive(nw_connection_t,uint32_t,uint32_t,nw_connection_receive_completion_t);
void apr_nw_receive_message(nw_connection_t,nw_connection_receive_completion_t);
#endif
#endif
