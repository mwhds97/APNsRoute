/* Run the actual constructor once per process. Hook functions are opaque
   addresses here; their forwarding/mutation contracts have separate tests. */
#define _DEFAULT_SOURCE 1
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include "../src/Diagnostics.h"
#include "../src/HookEngine.h"

#define APNSROUTE_NECP_HOOKS_H
#define APNSROUTE_NW_HOOKS_H
#define APNSROUTE_NW_OBSERVER_H
/* Only the constructor sees these stand-ins, never the real hook code. */
static void apr_necp(void) {} static void *apr_original_necp;
static void apr_nw_create(void) {} static void *apr_original_nw_create;
static void apr_nw_start(void) {} static void *apr_original_nw_start;
static void apr_nw_state_handler(void) {} static void *apr_original_nw_state_handler;
static void apr_nw_send(void) {} static void *apr_original_nw_send;
static void apr_nw_cancel(void) {} static void *apr_original_nw_cancel;
static void apr_nw_force_cancel(void) {} static void *apr_original_nw_force_cancel;

static bool begin,engine_missing,config_missing,bad_os;
static const char *saved_mode;
static unsigned stage,hooks,lookups,installs,observer_init;
static bool loaded_enabled;
static const char *names[]={"nw_connection_create","necp_client_action",
    "nw_connection_start","nw_connection_set_state_changed_handler","nw_connection_send",
    "nw_connection_cancel","nw_connection_force_cancel"};
static const char *fake_getprogname(void) {return begin?"apsd":"host-test";}
int sysctl(const int *mib,unsigned count,void *out,size_t *length,const void *input,size_t in_length) {
    assert(count==4 && mib[2]==KERN_PROC_PID && !input && !in_length && *length==sizeof(struct kinfo_proc));
    struct kinfo_proc *p=out;memset(p,0,sizeof(*p));p->kp_proc.p_starttime.tv_sec=1;return 0;
}
int sysctlbyname(const char *name,void *out,size_t *length,const void *input,size_t in_length) {
    assert(!strcmp(name,"kern.osrelease") && !input && !in_length && *length>=8);
    strcpy(out,bad_os?"21.0.0":"20.6.0");return 0;
}
static FILE *fake_fopen(const char *path,const char *mode) {
    assert(!strcmp(path,"/Library/Application Support/APNsRoute/mode") && !strcmp(mode,"r"));
    if(config_missing) {errno=ENOENT;return NULL;}
    FILE *f=tmpfile();assert(f);fputs(saved_mode,f);rewind(f);return f;
}
static void engine(void *target,void *replacement,void **original) {
    assert(target && replacement && original);*original=target;++installs;
}
APRHookFunction apr_find_hook_engine(void) {return engine_missing?NULL:engine;}
static void *fake_dlsym(void *handle,const char *name) {
    (void)handle;for(unsigned i=0;i<7;++i)if(!strcmp(name,names[i])) {lookups|=1U<<i;return (void *)(uintptr_t)(i+1);}
    abort();
}
void apr_diag_init(uint64_t incarnation) {assert(incarnation==1000000);}
void apr_diag_stage(enum apr_stage value,int error,bool enabled) {stage=value;loaded_enabled=enabled;if(value==APR_CONFIG_ERROR)assert(error==ENOENT);}
void apr_diag_hook(unsigned mask) {hooks|=mask;}
void apr_diag_event(enum apr_event event) {(void)event;}
void apr_nw_observer_init(void) {++observer_init;}
#define getprogname fake_getprogname
#define fopen fake_fopen
#define dlsym fake_dlsym
#include "../src/Tweak.c"

int main(int argc,char **argv) {
    assert(argc==2);saved_mode=argv[1];
    engine_missing=!strcmp(saved_mode,"missing-engine");config_missing=!strcmp(saved_mode,"missing-config");bad_os=!strcmp(saved_mode,"wrong-os");
    if(engine_missing || bad_os)saved_mode="disabled\n";
    begin=true;apr_init();
    if(config_missing || bad_os || engine_missing || !strcmp(saved_mode,"invalid")) {
        assert(!installs && !hooks && !observer_init);
        assert(!apr_can_modify());
        assert(stage==(config_missing?APR_CONFIG_ERROR:bad_os?APR_WRONG_OS:engine_missing?APR_NO_HOOK_ENGINE:APR_INVALID_MODE));
    } else if(!strcmp(saved_mode,"unbind")) {
        assert(stage==APR_READY && loaded_enabled && hooks==APR_HOOK_MASK && lookups==APR_HOOK_MASK && installs==7);
        assert(observer_init==1);
        assert(apr_can_modify());
    } else {
        assert(stage==APR_NATIVE_READY && !loaded_enabled && hooks==APR_HOOK_MASK && lookups==APR_HOOK_MASK && installs==7);
        assert(observer_init==1);
        assert(!apr_can_modify());
    }
    printf("PASS: actual constructor mode %s, requested observers and mutation guard\n",argv[1]);
}
