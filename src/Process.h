#ifndef APNSROUTE_PROCESS_H
#define APNSROUTE_PROCESS_H
#include <stdint.h>
#include <sys/sysctl.h>
static inline uint64_t apr_incarnation(const struct kinfo_proc *p) {
    return (uint64_t)p->kp_proc.p_starttime.tv_sec * UINT64_C(1000000) +
        (uint64_t)p->kp_proc.p_starttime.tv_usec;
}
#endif
