#ifndef APR_TEST_DISPATCH_H
#define APR_TEST_DISPATCH_H
typedef void *dispatch_data_t;
typedef void *dispatch_queue_t;
#define DISPATCH_QUEUE_PRIORITY_DEFAULT 0
dispatch_queue_t dispatch_get_global_queue(long,unsigned long);
#endif
