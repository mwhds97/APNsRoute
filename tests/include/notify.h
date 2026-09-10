#ifndef APNSROUTE_TEST_NOTIFY_H
#define APNSROUTE_TEST_NOTIFY_H
#include <stdint.h>
#define NOTIFY_STATUS_OK 0
uint32_t notify_register_check(const char *name, int *token);
uint32_t notify_set_state(int token, uint64_t state);
#endif
