#ifndef TEST_NETWORK_H
#define TEST_NETWORK_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
typedef struct Parameters *nw_parameters_t;
typedef struct Endpoint *nw_endpoint_t;
typedef void *nw_connection_t;
typedef enum {nw_endpoint_type_invalid,nw_endpoint_type_address,nw_endpoint_type_host} nw_endpoint_type_t;
typedef enum {nw_interface_type_other,nw_interface_type_wifi,nw_interface_type_cellular,nw_interface_type_wired,nw_interface_type_loopback} nw_interface_type_t;
nw_endpoint_type_t nw_endpoint_get_type(nw_endpoint_t);
const char *nw_endpoint_get_hostname(nw_endpoint_t);
uint16_t nw_endpoint_get_port(nw_endpoint_t);
const struct sockaddr *nw_endpoint_get_address(nw_endpoint_t);
void nw_retain(void *);
void nw_release(void *);
#ifdef __BLOCKS__
#include <dispatch/dispatch.h>
typedef struct TestPath *nw_path_t;
typedef struct TestMonitor *nw_path_monitor_t;
nw_path_monitor_t nw_path_monitor_create(void);
void nw_path_monitor_set_queue(nw_path_monitor_t,dispatch_queue_t);
void nw_path_monitor_set_update_handler(nw_path_monitor_t,void (^)(nw_path_t));
void nw_path_monitor_start(nw_path_monitor_t);
typedef enum {nw_path_status_invalid,nw_path_status_satisfied,nw_path_status_unsatisfied,nw_path_status_satisfiable} nw_path_status_t;
typedef enum {nw_path_unsatisfied_reason_not_available,nw_path_unsatisfied_reason_cellular_denied,nw_path_unsatisfied_reason_wifi_denied,nw_path_unsatisfied_reason_local_network_denied} nw_path_unsatisfied_reason_t;
nw_path_t nw_connection_copy_current_path(nw_connection_t);
nw_path_status_t nw_path_get_status(nw_path_t);
bool nw_path_uses_interface_type(nw_path_t,nw_interface_type_t);
bool nw_path_is_expensive(nw_path_t);
bool nw_path_is_constrained(nw_path_t);
typedef void *nw_content_context_t;
typedef struct TestError *nw_error_t;
typedef struct TestReport *nw_establishment_report_t;
typedef enum {nw_connection_state_invalid,nw_connection_state_waiting,nw_connection_state_preparing,
    nw_connection_state_ready,nw_connection_state_failed,nw_connection_state_cancelled} nw_connection_state_t;
typedef enum {nw_error_domain_invalid,nw_error_domain_posix,nw_error_domain_dns,nw_error_domain_tls} nw_error_domain_t;
typedef void (^nw_connection_state_changed_handler_t)(nw_connection_state_t,nw_error_t);
typedef void (^nw_connection_send_completion_t)(nw_error_t);
typedef void (^nw_connection_receive_completion_t)(dispatch_data_t,nw_content_context_t,bool,nw_error_t);
typedef void (^nw_establishment_report_access_block_t)(nw_establishment_report_t);
nw_endpoint_t nw_connection_copy_endpoint(nw_connection_t);
nw_error_domain_t nw_error_get_error_domain(nw_error_t);
int nw_error_get_error_code(nw_error_t);
void nw_connection_access_establishment_report(nw_connection_t,dispatch_queue_t,nw_establishment_report_access_block_t);
bool nw_establishment_report_get_proxy_configured(nw_establishment_report_t);
bool nw_establishment_report_get_used_proxy(nw_establishment_report_t);
#endif
#endif
