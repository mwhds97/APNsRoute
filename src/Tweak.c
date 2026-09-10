#include <string.h>
#include "HookEngine.h"
#include "Diagnostics.h"
#include "NECPHooks.h"
#include "Process.h"
#include "NWHooks.h"
#include "NWObserver.h"
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>

static bool apr_enabled;

bool apr_can_modify(void) {
    return apr_enabled; /* NECP performs its own fresh tunnel selection. */
}

static void install_hook(APRHookFunction engine,const char *name,void *replacement,void **original,unsigned bit) {
    void *target=dlsym(RTLD_DEFAULT,name);
    if (target) engine(target,replacement,original);
    if (*original) apr_diag_hook(bit);
}
__attribute__((constructor)) static void apr_init(void) {
    const char *process=getprogname();
    if (!process || strcmp(process,"apsd")) return;
    struct kinfo_proc info={0}; size_t info_size=sizeof(info);
    int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_PID,getpid()};
    uint64_t incarnation=0;
    if (!sysctl(mib,4,&info,&info_size,NULL,0) && info_size==sizeof(info))
        incarnation=apr_incarnation(&info);
    apr_diag_init(incarnation);
    char release[64]={0}; size_t size=sizeof(release);
    if (sysctlbyname("kern.osrelease",release,&size,NULL,0) || strncmp(release,"20.",3)) {
        apr_diag_stage(APR_WRONG_OS,0,false); return;
    }
    char mode[32]={0};
    FILE *file=fopen("/Library/Application Support/APNsRoute/mode","r");
    if (!file) { apr_diag_stage(APR_CONFIG_ERROR,errno,false); return; }
    if (!fgets(mode,sizeof(mode),file)) {
        int error=ferror(file) ? (errno?errno:EIO) : EINVAL;
        fclose(file); apr_diag_stage(APR_CONFIG_ERROR,error,false); return;
    }
    fclose(file); mode[strcspn(mode,"\r\n")]=0;
    if (!strcmp(mode,"unbind")) apr_enabled=true;
    else if (strcmp(mode,"disabled") && strcmp(mode,"observe")) {
        apr_diag_stage(APR_INVALID_MODE,0,false); return;
    }
    /* Both modes install seven hooks. Only matched NECP ADD input may be
       changed in enabled mode.
       The legacy saved value "observe" maps to this same disabled control. */
    APRHookFunction engine=apr_find_hook_engine();
    if (!engine) { apr_diag_stage(APR_NO_HOOK_ENGINE,0,apr_enabled); return; }
    apr_nw_observer_init();
    install_hook(engine,"nw_connection_create",(void *)apr_nw_create,(void **)&apr_original_nw_create,APR_H_NW);
    install_hook(engine,"necp_client_action",(void *)apr_necp,(void **)&apr_original_necp,APR_H_NECP);
    install_hook(engine,"nw_connection_start",(void *)apr_nw_start,(void **)&apr_original_nw_start,APR_H_NW_START);
    install_hook(engine,"nw_connection_set_state_changed_handler",(void *)apr_nw_state_handler,(void **)&apr_original_nw_state_handler,APR_H_NW_STATE);
    install_hook(engine,"nw_connection_send",(void *)apr_nw_send,(void **)&apr_original_nw_send,APR_H_NW_SEND);
    install_hook(engine,"nw_connection_cancel",(void *)apr_nw_cancel,(void **)&apr_original_nw_cancel,APR_H_NW_CANCEL);
    install_hook(engine,"nw_connection_force_cancel",(void *)apr_nw_force_cancel,(void **)&apr_original_nw_force_cancel,APR_H_NW_FORCE);
    apr_diag_stage(apr_enabled ? APR_READY : APR_NATIVE_READY,0,apr_enabled);
}
