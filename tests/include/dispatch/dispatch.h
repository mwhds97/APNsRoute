#ifndef APR_TEST_DISPATCH_H
#define APR_TEST_DISPATCH_H
#include <stddef.h>
#include <stdint.h>
typedef void *dispatch_data_t;
size_t dispatch_data_get_size(dispatch_data_t);
typedef void *dispatch_queue_t;
#define DISPATCH_QUEUE_PRIORITY_DEFAULT 0
#define DISPATCH_QUEUE_SERIAL ((void *)0)
#define DISPATCH_TIME_NOW 0
typedef uint64_t dispatch_time_t;
dispatch_queue_t dispatch_queue_create(const char *,void *);
void dispatch_release(void *);
dispatch_time_t dispatch_time(dispatch_time_t,int64_t);
void dispatch_after_f(dispatch_time_t,dispatch_queue_t,void *,void (*)(void *));
void dispatch_async_f(dispatch_queue_t,void *,void (*)(void *));
dispatch_queue_t dispatch_get_global_queue(long,unsigned long);
#endif
