#ifndef TEST_SYSCTL_H
#define TEST_SYSCTL_H
#include <stddef.h>
#include <sys/time.h>
#include <sys/types.h>
enum {CTL_KERN=1,KERN_PROC=2,KERN_PROC_PID=3,KERN_PROC_ALL=4};
struct kinfo_proc {struct {struct timeval p_starttime;char p_comm[32];pid_t p_pid;} kp_proc;};
int sysctl(const int *,unsigned,void *,size_t *,const void *,size_t);
int sysctlbyname(const char *,void *,size_t *,const void *,size_t);
#endif
