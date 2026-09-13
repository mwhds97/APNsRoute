/* Standalone arm64 tool. No injection, task ports, route changes or entitlements.
   Inspect only apsd PIDs and this package's non-secret notification states. */
#include "Diagnostics.h"
#include "HookEngine.h"
#include "Process.h"
#include "LiveSockets.h"
#include "BindingStatus.h"
#include "InterfaceCheck.h"
#include <net/if.h>
#include "TransportSnapshot.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <notify.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

static uint32_t read_state(pid_t pid, uint64_t incarnation, const char *suffix, uint64_t *value) {
    char name[128];
    snprintf(name, sizeof(name), APR_DIAG_PREFIX ".%ld.%llu.%s", (long)pid, (unsigned long long)incarnation, suffix);
    int token = -1;
    uint32_t result = notify_register_check(name, &token);
    if (result != NOTIFY_STATUS_OK) return result;
    result = notify_get_state(token, value);
    notify_cancel(token);
    return result;
}

static int check_channel(void) {
    char name[128];
    snprintf(name, sizeof(name), "local.apnsroute.diag.%ld", (long)getpid());
    int writer = -1, reader = -1;
    uint64_t value = 0;
    uint32_t result = notify_register_check(name, &writer);
    if (!result) result = notify_set_state(writer, APR_DIAG_MAGIC | 123);
    if (!result) result = notify_register_check(name, &reader);
    if (!result) result = notify_get_state(reader, &value);
    if (reader >= 0) notify_cancel(reader);
    if (writer >= 0) notify_cancel(writer);
    if (result || value != (APR_DIAG_MAGIC | 123)) {
        printf("Diagnostic channel: unavailable (notify status=%u)\n", result);
        return 1;
    }
    puts("Diagnostic channel: works in this terminal process; apsd access still needs its own signal");
    return 0;
}

static const char *stage_name(unsigned stage) {
    switch (stage) {
        case APR_ENTERED: return "constructor entered; setup has not completed";
        case APR_WRONG_OS: return "OS check failed; hooks disabled";
        case APR_CONFIG_ERROR: return "configuration read failed; hooks disabled";
        case APR_DISABLED: return "disabled; no hooks";
        case APR_INVALID_MODE: return "invalid mode; no hooks";
        case APR_READY: return "hook setup completed (see individual trampolines below)";
        case APR_NO_HOOK_ENGINE: return "hook engine unavailable; no hooks installed";
        case APR_NATIVE_READY: return "native-routing observers installed (see individual trampolines below)";
        default: return "unknown protocol state";
    }
}

struct transport_context {pid_t pid;uint64_t incarnation;};
static bool transport_read(void *context,const char *name,uint64_t *value) {
    struct transport_context *c=context;
    return read_state(c->pid,c->incarnation,name,value)==NOTIFY_STATUS_OK;
}
static void report_cancel_path(unsigned detail) {
    if(!(detail&APR_PATH_SEEN)) {puts("  Path before cancellation: not observed through cancel hooks");return;}
    if(!(detail&APR_PATH_PRESENT)) {puts("  Path before cancellation: API returned no path");return;}
    static const char *status[]={"invalid","satisfied","unsatisfied","satisfiable"};
    static const char *reasons[]={"no reason supplied","cellular access denied","Wi-Fi access denied","local network access denied"};
    unsigned state=detail&255,reason=(detail>>8)&255;
    printf("  Path before %scancel: %s\n",detail&APR_PATH_FORCE?"force-":"",state<4?status[state]:"unknown");
    printf("    Unsatisfied reason: %s\n",!(detail&APR_PATH_REASON_API)?"API unavailable":reason<4?reasons[reason]:"unknown reason");
    printf("    Uses interfaces: Wi-Fi=%s cellular=%s loopback=%s; expensive=%s constrained=%s\n",
        detail&APR_PATH_WIFI?"yes":"no",detail&APR_PATH_CELL?"yes":"no",detail&APR_PATH_LOOP?"yes":"no",
        detail&APR_PATH_EXPENSIVE?"yes":"no",detail&APR_PATH_CONSTRAINED?"yes":"no");
}
static const char *interface_type_name(unsigned type) {
    static const char *names[]={"unknown", "loopback", "wired", "Wi-Fi infrastructure",
        "Wi-Fi AWDL", "cellular", "internal coprocessor", "Companion Link"};
    return type<sizeof(names)/sizeof(*names)?names[type]:"unrecognized";
}
static void report_constraints(const uint32_t *v) {
    static const char *names[]={"BOUND_INTERFACE (9)","PROHIBIT_INTERFACE (100)",
        "PROHIBIT_IF_TYPE (101)","PROHIBIT_AGENT (102)","PROHIBIT_AGENT_TYPE (103)",
        "REQUIRE_IF_TYPE (111)","REQUIRE_AGENT (112)","REQUIRE_AGENT_TYPE (113)","PARENT_ID (150)"};
    if(!v[APR_T_NECP_CONSTRAINTS_SEEN]) {puts("  Original input: no interface/agent constraint or PARENT_ID field");return;}
    puts("  Original fields for this request:");
    for(unsigned i=0;i<sizeof(names)/sizeof(*names);++i) {
        uint32_t bit=1U<<i;
        if(!(v[APR_T_NECP_CONSTRAINTS_SEEN]&bit))continue;
        printf("    %s: %s%s%s\n",names[i],
            v[APR_T_NECP_CONSTRAINTS_UNSUPPORTED]&bit?"unsupported layout; binding blocked":
            (v[APR_T_NECP_CONSTRAINTS_RESTRICTED]&bit) && (v[APR_T_NECP_CONSTRAINTS_BLOCKED]&bit)?"nonzero restriction; guard blocker":
            (v[APR_T_NECP_CONSTRAINTS_RESTRICTED]&bit) && bit==APR_C_PROHIBIT_TYPE?"exclusions retained; tunnel/delegates must pass complete type check":
            (v[APR_T_NECP_CONSTRAINTS_RESTRICTED]&bit) && bit==APR_C_REQUIRE_AGENT_TYPE?"Cellular / Internet eligible for REQUIRE -> PREFER on bound copy":
            bit==APR_C_PARENT?"resolver metadata/empty; does not block binding":"empty/zero; does not block binding",
            (v[APR_T_NECP_CONSTRAINTS_UNSUPPORTED]&bit) && (v[APR_T_NECP_CONSTRAINTS_RESTRICTED]&bit)?"; also nonzero occurrence":"",
            (v[APR_T_NECP_CONSTRAINTS_INERT]&bit) && ((v[APR_T_NECP_CONSTRAINTS_RESTRICTED]|v[APR_T_NECP_CONSTRAINTS_UNSUPPORTED])&bit)?"; also empty/zero occurrence":"");
    }
    if(v[APR_T_NECP_CONSTRAINTS_SEEN]&APR_C_PROHIBIT_TYPE) {
        puts("  Original prohibited interface types (all unique one-byte values):");
        bool any=false;
        for(unsigned type=0;type<256;++type)if(v[APR_T_NECP_PROHIBITED_TYPES_0+type/32] & (UINT32_C(1)<<(type%32))) {
            printf("    %u (%s)\n",type,type?interface_type_name(type):"inactive zero");any=true;
        }
        if(!any)puts("    No supported one-byte values observed");
    }
    if(v[APR_T_NECP_CONSTRAINTS_FIRST]) {
        unsigned type=v[APR_T_NECP_CONSTRAINTS_FIRST]&255;
        printf("  First original nonzero/unsupported field: type=%u length=%u",type,(v[APR_T_NECP_CONSTRAINTS_FIRST]>>8)&65535);
        if(type==101 || type==111)printf(" interface-type=%u",v[APR_T_NECP_CONSTRAINTS_FIRST]>>24);
        putchar('\n');
    }
    if(v[APR_T_NECP_AGENT_INFO]&255) {
        printf("  Required-agent-type fields: %u\n",v[APR_T_NECP_AGENT_INFO]&255);
        if(v[APR_T_NECP_AGENT_INFO]&APR_AGENT_NAMES) {
            char names[64];for(unsigned i=0;i<16;++i)memcpy(names+i*4,&v[APR_T_NECP_AGENT_NAME_0+i],4);
            names[31]=names[63]=0;
            for(unsigned i=0;i<64;++i)if(names[i] && ((unsigned char)names[i]<32 || (unsigned char)names[i]>126))names[i]='?';
            printf("    First readable domain: %s\n",names[0]?names:"(wildcard)");
            printf("    First readable type: %s\n",names[32]?names+32:"(wildcard)");
            if(v[APR_T_NECP_AGENT_INFO]&APR_AGENT_MULTIPLE)puts("    Additional different agent types present; only first shown");
        }
        if(v[APR_T_NECP_AGENT_INFO]&APR_AGENT_BAD_NAME)puts("    Noncanonical/unreadable agent name; conversion blocked");
        if(v[APR_T_NECP_AGENT_INFO]&APR_AGENT_OTHER)puts("    A non-Cellular / Internet requirement is preserved; conversion blocked");
        if(v[APR_T_NECP_AGENT_INFO]&APR_AGENT_TOO_MANY)puts("    More than four required-agent-type fields; conversion blocked");
        if(v[APR_T_NECP_AGENT_INFO]&APR_AGENT_EXISTING_PREFERENCE)puts("    Existing preferred-agent-type list preserved; conversion blocked");
    }
    if(v[APR_T_NECP_AGENT_EDIT]&APR_EDIT_SUBMITTED)printf("  Agent REQUIRE -> PREFER fields supplied: %u; ADD accepted: %s\n",
        v[APR_T_NECP_AGENT_EDIT]&255,v[APR_T_NECP_AGENT_EDIT]&APR_EDIT_ACCEPTED?"yes":"no");
    else puts("  Agent/tunnel input changes supplied: no");
    static const char *checks[]={"not performed","passed: no prohibited tunnel/delegate type observed",
        "blocked: prohibited interface/delegate type","unavailable: kernel query failed",
        "blocked: interface missing/changed","blocked: unknown functional type",
        "blocked: delegate cycle","blocked: delegate depth limit"};
    unsigned check=v[APR_T_NECP_INTERFACE_CHECK]&255;
    if(check) {
        printf("  Interface exclusion check: %s; interfaces examined=%u; last index=%" PRIu32 "\n",
            check<sizeof(checks)/sizeof(*checks)?checks[check]:"unknown",(v[APR_T_NECP_INTERFACE_CHECK]>>8)&255,v[APR_T_NECP_INTERFACE_CHECK_INDEX]);
        printf("    Observed functional types:");
        unsigned mask=v[APR_T_NECP_INTERFACE_CHECK]>>16;
        for(unsigned type=0;type<8;++type)if(mask&(1U<<type))printf(" %u (%s);",type,interface_type_name(type));
        puts(mask?"":" none read");
    }
}
static void report_binding(const uint32_t *v) {
    static const char *names[]={"not attempted","disabled; native input forwarded",
        "tunnel-binding ADD accepted (routing still needs result below)",
        "skipped: no up utun with a usable IP address", "skipped: multiple usable utun interfaces",
        "skipped: tunnel lacks the matched IP family", "skipped: interface enumeration unavailable",
        "skipped: original constraint/unsupported field preserved (details below)", "skipped: explicit/unsupported local endpoint preserved",
        "skipped: allocation failed", "tunnel-binding ADD rejected by kernel",
        "skipped: interface changed during selection", "skipped: input size limit",
        "skipped: multipath/custom/cost/constrained or unknown flags preserved",
        "skipped: tunnel/delegate interface exclusion check did not pass"};
    _Static_assert(sizeof(names)/sizeof(*names)==APR_BIND_INTERFACE_CHECK+1,"binding status schema");
    if(!v[APR_T_NECP_BINDING_ID]) {puts("Matched tunnel-binding request: no recognized ADD observed");return;}
    unsigned status=v[APR_T_NECP_BINDING_STATUS]&255;
    printf("Latest matched NECP request #%" PRIu32 ": %s\n",v[APR_T_NECP_BINDING_ID],
        status<sizeof(names)/sizeof(*names)?names[status]:"unknown status");
    printf("  Original client flags: 0x%08" PRIx32 " (guards unchanged)\n",v[APR_T_NECP_CLIENT_FLAGS]);
    report_constraints(v);
    if(v[APR_T_NECP_BINDING_INDEX]) {
        char name[IF_NAMESIZE]={0};const char *current=if_indextoname(v[APR_T_NECP_BINDING_INDEX],name);
        printf("  Candidate/requested interface index: %" PRIu32 " (current name: %s)\n",v[APR_T_NECP_BINDING_INDEX],current?current:"unavailable");
        printf("  Candidate addresses: IPv4=%s IPv6=%s; owner not verified\n",
            (v[APR_T_NECP_BINDING_STATUS]>>16)&1?"yes":"no",(v[APR_T_NECP_BINDING_STATUS]>>16)&2?"yes":"no");
    }
    if(v[APR_T_NECP_BINDING_ERRNO])printf("  Request/selection errno: %" PRId32 " (%s)\n",(int32_t)v[APR_T_NECP_BINDING_ERRNO],strerror((int32_t)v[APR_T_NECP_BINDING_ERRNO]));
    if(!(v[APR_T_NECP_BINDING_RESULT]&APR_BIND_RESULT_READ)) {puts("  Result for this client/registered flow: not observed");return;}
    if(v[APR_T_NECP_BINDING_RESULT]&APR_BIND_RESULT_INVALID) {puts("  Result for this client/registered flow: unsupported/malformed");return;}
    if(v[APR_T_NECP_BINDING_RESULT]&APR_BIND_RESULT_INTERFACE) {
        char name[IF_NAMESIZE]={0};const char *current=if_indextoname(v[APR_T_NECP_BINDING_RESULT_INDEX],name);
        printf("  Returned top-level interface index: %" PRIu32 " (current name: %s)\n",v[APR_T_NECP_BINDING_RESULT_INDEX],current?current:"unavailable");
    } else puts("  Returned top-level interface index: absent (may be a flow-only update)");
    if(v[APR_T_NECP_BINDING_RESULT]&APR_BIND_RESULT_POLICY)printf("  Returned routing policy: %" PRIu32 "\n",v[APR_T_NECP_BINDING_POLICY]);
    else puts("  Returned routing policy: absent");
    if(status==APR_BIND_ACCEPTED && (v[APR_T_NECP_BINDING_RESULT]&APR_BIND_RESULT_INTERFACE))
        printf("  Kernel result matches requested tunnel index: %s\n",v[APR_T_NECP_BINDING_RESULT]&APR_BIND_RESULT_MATCH?"yes":"no");
    puts("  This pair identifies one NECP client/its flows; it is not paired with the NW handler below.");
    puts("  An accepted request or matching interface does not confirm Surge capture or push delivery.");
}
static void report_retirement(const uint32_t *v) {
    static const char *states[]={"not initialized", "disabled; native lifetime",
        "waiting for first Wi-Fi/cellular path", "suspended; physical path unknown or unsatisfied",
        "watching; no older established connections", "handover window; older connections pending",
        "unavailable; native lifetime", "endpoint request awaiting native readiness or closure"};
    static const char *reasons[]={"none", "fresh matched connection received data on current network",
        "three-second handover window elapsed"};
    unsigned status=v[APR_T_RET_STATUS],reason=v[APR_T_RET_REASON],network=v[APR_T_RET_NETWORK];
    printf("Handover retirement: %s\n",status<sizeof(states)/sizeof(*states)?states[status]:"unknown status");
    printf("  Monitor network: %s; generation=%" PRIu32 "\n",
        network==APR_RET_WIFI?"Wi-Fi":network==APR_RET_CELLULAR?"cellular":"unknown",v[APR_T_RET_EPOCH]);
    printf("  Held connections=%" PRIu32 "/8; older established connections pending=%" PRIu32 "\n",
        v[APR_T_RET_HELD],v[APR_T_RET_PENDING]);
    printf("  Endpoint retirement requests=%" PRIu32 "; last connection=#%" PRIu32 "\n",
        v[APR_T_RET_REQUESTS],v[APR_T_RET_LAST_ID]);
    printf("  Awaiting native readiness/closure=%" PRIu32 "\n",v[APR_T_RET_AWAITING]);
    printf("  Last retirement reason: %s\n",reason<sizeof(reasons)/sizeof(*reasons)?reasons[reason]:"unknown");
    printf("  Tracking attempts skipped (capacity/ID/handler unavailable): %" PRIu32 "\n",v[APR_T_RET_SKIPPED]);
    if(v[APR_T_RET_ERROR])printf("  Retirement error: %" PRId32 " (%s)\n",
        (int32_t)v[APR_T_RET_ERROR],strerror((int32_t)v[APR_T_RET_ERROR]));
    puts("  Requests cancel the current endpoint; counts do not confirm transport closure or push delivery.");
    puts("  No handover restart of apsd. Native endpoint fallback/failure handles recovery; new init traffic is possible.");
}
static void report_connections(const uint32_t *v) {
    static const char *roles[]={"unknown","init hint","courier hint","matched host","matched address"};
    static const char *states[]={"invalid","waiting","preparing","ready","failed","cancelled"};
    static const char *paths[]={"invalid","satisfied","unsatisfied","satisfiable"};
    puts("NW connection observations (up to 8; IDs are local to this apsd process):");
    bool any=false;
    for(unsigned slot=0;slot<APR_CONNECTION_COUNT;++slot) {
        const uint32_t *r=v+APR_T_CONN_0_ID+slot*APR_CONNECTION_FIELD_COUNT;
        if(!r[APR_R_ID]) continue;
        any=true;unsigned state=r[APR_R_STATE]&255U,role=r[APR_R_ROLE];
        unsigned history=r[APR_R_STATE]>>APR_ROW_HISTORY_SHIFT;
        const char *name=r[APR_R_STATE]&APR_ROW_HANDLER_CLEARED?"handler cleared":
            !history?"no state callback":state<6?states[state]:"unknown state";
        printf("  Connection #%" PRIu32 " (%s), handler #%" PRIu32 ": %s\n",
            r[APR_R_ID],role<5?roles[role]:"unknown",r[APR_R_HANDLER],name);
        printf("    Send calls=%" PRIu32 "; receive calls=%" PRIu32 "; receive callbacks=%" PRIu32 "\n",
            r[APR_R_SENDS],r[APR_R_READS],r[APR_R_RECEIVED]);
        printf("    Received bytes=%" PRIu32 "; complete callbacks=%" PRIu32 "; cancels: normal=%u force=%u\n",
            r[APR_R_BYTES],r[APR_R_COMPLETES],r[APR_R_CANCELS]&65535U,r[APR_R_CANCELS]>>16);
        printf("    Endpoint retirement requests=%" PRIu32 "\n",r[APR_R_RETIRE_REQUESTS]);
        printf("    Handler states seen: ready=%s waiting=%s failed=%s cancelled=%s\n",
            history&(1U<<3)?"yes":"no",history&(1U<<1)?"yes":"no",
            history&(1U<<4)?"yes":"no",history&(1U<<5)?"yes":"no");
        unsigned domain=r[APR_R_ERROR_INFO]&255U,source=r[APR_R_ERROR_INFO]>>8;
        if(domain) printf("    Last error: %s (%u), code=%" PRId32 "; from %s callback\n",
            domain==1?"POSIX":domain==2?"DNS":domain==3?"TLS":"unknown",domain,(int32_t)r[APR_R_ERROR_CODE],
            source==APR_ERROR_RECEIVE?"receive":"state");
        else puts("    Last error: none observed");
        unsigned path=r[APR_R_PATH];
        if(!(path&APR_PATH_SEEN)) puts("    Path at last receive/cancel call: not sampled");
        else if(!(path&APR_PATH_PRESENT)) puts("    Path at last receive/cancel call: unavailable");
        else printf("    Path at last receive/cancel call: %s; Wi-Fi=%s cellular=%s loopback=%s\n",
            (path&255U)<4?paths[path&255U]:"unknown",path&APR_PATH_WIFI?"yes":"no",
            path&APR_PATH_CELL?"yes":"no",path&APR_PATH_LOOP?"yes":"no");
    }
    if(!any) puts("  No matched connection recorded");
    printf("  Record attempts skipped (capacity/ID exhaustion): %" PRIu32 "\n",v[APR_T_CONNECTION_OVERFLOW]);
    puts("  Rows contain last observations, not a live-connection list or Surge row mapping.");
    puts("  A connection ID identifies an NW object, which can survive endpoint replacement.");
    puts("  Counters saturate. Complete callbacks need not mean TCP EOF; bytes do not prove push delivery.");
    puts("  Empty slots are used first; terminal/cleared slots may be reused. These diagnostic rows own no references.");
    puts("  Enabled handover retirement separately holds at most eight connection references, reported above.");
    puts("  Hostname hints label diagnostics only; all 13 routing rules remain active.");
}
static void report_transport(pid_t pid,uint64_t incarnation,bool enabled) {
    struct transport_context context={pid,incarnation};uint32_t v[APR_TRANSPORT_SLOTS]={0};
    if(!apr_transport_snapshot(transport_read,&context,v)) {
        puts("Matched transport snapshot: unavailable or changing; rerun doctor");return;
    }
    report_retirement(v);
    report_connections(v);
    report_binding(v);
    puts("NW transport samples (independent of the NECP request above):");
    if(v[APR_T_NW_CREATED]&APR_CREATE_SEEN) {
        printf("  Last create: %s\n",v[APR_T_NW_CREATED]&APR_CREATE_OK?"returned a connection":"returned NULL");
        if(!(v[APR_T_NW_CREATED]&APR_CREATE_OK)) printf("    errno snapshot: %" PRId32 " (API may not set errno)\n",(int32_t)v[APR_T_NW_CREATE_ERRNO]);
    } else puts("  Last create: not observed");
    printf("  Last start: %s\n",v[APR_T_NW_START]&APR_START_SEEN?"called":"not observed");
    if(v[APR_T_NW_STATE]&APR_STATE_REGISTERED) {
        static const char *names[]={"invalid","waiting","preparing","ready","failed","cancelled"};
        unsigned state=v[APR_T_NW_STATE]&255,domain=(v[APR_T_NW_STATE]>>8)&255;
        printf("  Latest matched handler #%" PRIu32 ": %s\n",v[APR_T_NW_HANDLER_ID],v[APR_T_NW_STATE]&APR_STATE_CALLBACK?
            (state<sizeof(names)/sizeof(*names)?names[state]:"unknown state"):"registered; no callback observed");
        if(domain) printf("    Last error: %s (%u), code=%" PRId32 "%s\n",
            domain==1?"POSIX":domain==2?"DNS":domain==3?"TLS":"unknown domain",domain,(int32_t)v[APR_T_NW_STATE_ERROR],
            v[APR_T_NW_STATE]&APR_STATE_CURRENT_ERROR?"":" (earlier callback for this handler)");
        else puts("    Last error: none observed for this handler");
        if(domain==1 && (int32_t)v[APR_T_NW_STATE_ERROR]>0) printf("    POSIX meaning: %s\n",strerror((int32_t)v[APR_T_NW_STATE_ERROR]));
        unsigned history=(v[APR_T_NW_STATE]>>APR_STATE_HISTORY_SHIFT)&63U;
        printf("    States seen for this handler: ready=%s waiting=%s failed=%s cancelled=%s\n",
            history&(1U<<3)?"yes":"no",history&(1U<<1)?"yes":"no",history&(1U<<4)?"yes":"no",history&(1U<<5)?"yes":"no");
        if(!enabled && (history&(1U<<3)))
            puts("    A matched connection reached ready with native routing. Check notification arrival and Surge capture separately.");
        else if(!enabled && (history&(1U<<4)))
            puts("    A matched connection failed with APNsRoute routing changes disabled.");
        else if(enabled && (history&(1U<<4)) && !(history&(1U<<3)))
            puts("    This handler failed before readiness; compare with the disabled native control.");
    } else puts("  Matched state: no non-NULL handler intercepted; state unknown");
    if(!(v[APR_T_NW_REPORT]&APR_REPORT_REQUESTED)) puts("  Establishment report: no eligible send-triggered request yet");
    else if(!(v[APR_T_NW_REPORT]&APR_REPORT_RETURNED)) puts("  Establishment report: callback pending");
    else if(!(v[APR_T_NW_REPORT]&APR_REPORT_AVAILABLE)) puts("  Establishment report: unavailable when requested (connection may not have been ready)");
    else {
        printf("  Establishment report: proxy configured=%s; proxy used=%s\n",
            v[APR_T_NW_REPORT]&APR_REPORT_CONFIGURED?"yes":"no",v[APR_T_NW_REPORT]&APR_REPORT_USED?"yes":"no");
    }
    report_cancel_path(v[APR_T_NW_CANCEL_PATH]);
    printf("  Matched cancellation calls since apsd start: normal=%" PRIu32 "; apsd force=%" PRIu32 "\n",
        v[APR_T_NW_CANCEL_NORMAL],v[APR_T_NW_CANCEL_APP_FORCE]);
    printf("  Normal cancels upgraded to immediate teardown: %" PRIu32 "\n",v[APR_T_NW_CANCEL_IMMEDIATE]);
    static const char *actions[]={"none observed", "native cancellation (tweak disabled)",
        "immediate teardown requested by APNsRoute", "native cancellation (force-cancel trampoline unavailable)",
        "apsd requested force-cancel; forwarded unchanged"};
    unsigned action=v[APR_T_NW_CANCEL_ACTION];
    printf("  Last matched cancellation dispatch: %s\n",action<sizeof(actions)/sizeof(*actions)?actions[action]:"unknown");
    puts("  Counts are API calls across matching connections, not unique connections or confirmed Surge closures.");
    puts("  State belongs to the latest registered handler, which may later be replaced/cleared.");
    puts("  Establishment reports are send-triggered, at most once per 5 s; no report timer or extra APNs traffic.");

}
static int report_pid(pid_t pid) {
    struct kinfo_proc process;
    size_t size = sizeof(process);
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    memset(&process, 0, sizeof(process));
    if (sysctl(mib, 4, &process, &size, NULL, 0) != 0 || size != sizeof(process)) {
        printf("PID %ld: cannot confirm running process; rerun doctor after relaunch\n", (long)pid);
        return 1;
    }
    if (strcmp(process.kp_proc.p_comm, "apsd")) {
        printf("PID %ld: not apsd; skipped\n", (long)pid);
        return 1;
    }
    printf("apsd PID: %ld\n", (long)pid);
    uint64_t incarnation=apr_incarnation(&process);
    uint64_t status=0,events=0,engine=0,version=0;
    uint32_t result=read_state(pid,incarnation,"status",&status);
    if(result || (status & UINT64_C(0xffffffff00000000))!=APR_DIAG_MAGIC) {
        printf("APNsRoute startup signal: unavailable (notify status=%u)\n",result);
        puts("Loading is unconfirmed: old mapped version, injection/ABI failure, or diagnostics unavailable.");
        puts("After an upgrade, run apnsroutectl restart, wait for relaunch, then rerun doctor.");
        apr_live_sockets(pid); return 1;
    }
    puts("Startup signal: present for this PID and process start time (protocol v" APR_DIAG_PROTOCOL ")");
    if(!read_state(pid,incarnation,"version",&version) &&
        (version & UINT64_C(0xffffffff00000000))==APR_DIAG_MAGIC) {
        if((uint32_t)version==APR_BUILD_ID) puts("Loaded package: " APR_VERSION);
        else printf("Loaded build ID: 0x%08x (different from this doctor)\n",(uint32_t)version);
    } else puts("Loaded version: unavailable");
    printf("Stage: %s\n",stage_name(status & 255));
    bool enabled=(status & APR_DIAG_UNBIND)!=0;
    printf("Loaded setting: %s\n",enabled ? "enabled (NECP tunnel binding; matched endpoint retirement)" : "disabled (native routing and lifetime)");
    if((status&255)==APR_NATIVE_READY)
        puts("Native control: nine observers requested; original input/results and cancellation forwarded.");
    report_transport(pid,incarnation,enabled);

    unsigned config_error=(status>>8)&255;
    if(config_error) printf("Configuration errno: %u (%s)\n",config_error,strerror(config_error));
    if(!read_state(pid,incarnation,"engine",&engine) &&
        (engine & UINT64_C(0xffffffff00000000))==APR_DIAG_MAGIC) {
        puts("MSHookFunction lookup:");
        for(unsigned i=0;i<APR_HOOK_SOURCE_COUNT;++i) {
            unsigned v=(engine>>(4*i))&15;
            printf("  %s: %s\n",apr_hook_source_name(i),v==APR_LOOKUP_FOUND ? "resolved" :
                v==APR_LOOKUP_OPEN_FAILED ? "dlopen failed" : v==APR_LOOKUP_SYMBOL_MISSING ? "symbol unavailable" : "not tried");
        }
    }
    unsigned hooks=(status>>17)&APR_HOOK_MASK;
    const char *hook_names[]={"nw_connection_create", "necp_client_action",
        "nw_connection_start", "nw_connection_set_state_changed_handler", "nw_connection_send",
        "nw_connection_cancel", "nw_connection_force_cancel",
        "nw_connection_receive", "nw_connection_receive_message"};
    puts("Hook trampolines:");
    for(unsigned i=0;i<sizeof(hook_names)/sizeof(*hook_names);++i)
        printf("  %s: %s\n",hook_names[i],hooks&(1U<<i)?"present":"absent");
    if(!read_state(pid,incarnation,"events",&events) &&
        (events & UINT64_C(0xffffffff00000000))==APR_DIAG_MAGIC) {
        static const char *labels[APR_EVENT_COUNT]={
            [APR_NW_MATCHED]="NW domain/IP rule matched",
            [APR_NECP_CALL]="NECP client creation intercepted",
            [APR_NECP_MATCHED]="NECP domain/IP rule matched",
            [APR_NECP_CHANGED]="NECP matched tunnel-binding ADD accepted by kernel",
            [APR_NECP_FAILED]="NECP matched tunnel-binding ADD rejected by kernel",
            [APR_NECP_INVALID]="NECP input unsupported or malformed; passed unchanged",
            [APR_NECP_TRACK_FULL]="NECP result tracking full (routing unaffected)",
            [APR_NECP_RESULT]="NECP result read for a tracked matched client/flow",
            [APR_NECP_PRIMARY_UTUN]="matched top-level NECP interface index names utun",
            [APR_NECP_PRIMARY_CELLULAR]="matched top-level NECP interface index names pdp_ip",
            [APR_NECP_SCOPED_POLICY]="matched top-level NECP policy is interface-scoped/direct",
            [APR_NECP_RESULT_NEXUS]="matched NECP result includes Nexus instance",
        };
        uint32_t banks[2]={(uint32_t)events,0};bool have[2]={true,false};
        const char *suffixes[]={"events","events2"};
        for(unsigned b=1;b<2;++b) {
            uint64_t value=0;
            have[b]=!read_state(pid,incarnation,suffixes[b],&value) &&
                (value & UINT64_C(0xffffffff00000000))==APR_DIAG_MAGIC;
            banks[b]=(uint32_t)value;
        }
        puts("Events seen since this apsd start (fixed flags; not a connection history):");
        const unsigned active[]={APR_NW_MATCHED,APR_NECP_CALL,APR_NECP_MATCHED,
            APR_NECP_CHANGED,APR_NECP_FAILED,APR_NECP_INVALID,APR_NECP_TRACK_FULL,
            APR_NECP_RESULT,APR_NECP_PRIMARY_UTUN,APR_NECP_PRIMARY_CELLULAR,APR_NECP_SCOPED_POLICY,
            APR_NECP_RESULT_NEXUS};
        for(unsigned k=0;k<sizeof(active)/sizeof(*active);++k) {unsigned i=active[k];
            printf("  %s: %s\n",labels[i],!have[i/32] ? "unavailable" :
                banks[i/32]&(UINT32_C(1)<<(i%32)) ? "yes" : "no");}
        puts("Flags are independent. Accepted changes do not establish delivery or Surge capture.");
    } else puts("Event state unavailable");
    puts("No proxy injection, active probes, log files or unified logging in this build.");
    uint64_t rejection=0;
    if(!read_state(pid,incarnation,"necp-reject",&rejection) &&
        (rejection & UINT64_C(0xffffffff00000000))==APR_DIAG_MAGIC && (uint32_t)rejection) {
        const char *reasons[]={"none","buffer size/pointer","TLV bounds","text encoding",
            "endpoint layout/family","protocol width","flags width","conflicting fields"};
        unsigned reason=rejection&255,type=(rejection>>8)&255,length=(rejection>>16)&65535;
        printf("First rejected NECP input: reason=%s type=%u length=%u%s\n",
            reason<sizeof(reasons)/sizeof(*reasons) ? reasons[reason] : "unknown",type,length,
            length==65535 ? " (length saturated)" : "");
        puts("  May belong to another client; no input bytes or hostnames were retained.");
    }
    apr_live_sockets(pid);

    return 0;
}

int main(int argc, char **argv) {
    puts("APNsRoute doctor " APR_VERSION " (read-only; no log files)");
    if (argc > 2) { fprintf(stderr, "Usage: apnsroute-diag [apsd-PID]\n"); return 2; }
    (void)check_channel();
    if (argc == 2) {
        char *end = NULL;
        errno = 0;
        long value = strtol(argv[1], &end, 10);
        if (errno || !argv[1][0] || *end || value <= 0 || value > INT_MAX) return 2;
        return report_pid((pid_t)value);
    }
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    struct kinfo_proc *list = NULL;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        free(list);
        list = NULL;
        if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0) break;
        if (size > 16 * 1024 * 1024) { errno = EOVERFLOW; break; }
        size += 32 * sizeof(*list);
        list = malloc(size);
        if (!list) break;
        if (sysctl(mib, 4, list, &size, NULL, 0) == 0) {
            int found = 0, failure = 0;
            for (size_t i = 0; i < size / sizeof(*list); ++i) {
                if (strcmp(list[i].kp_proc.p_comm, "apsd")) continue;
                ++found;
                failure |= report_pid(list[i].kp_proc.p_pid);
            }
            free(list);
            if (!found) puts("No apsd process found; rerun after launchd relaunches it");
            return found ? failure : 1;
        }
        if (errno != ENOMEM) break;
    }
    int error = errno;
    free(list);
    printf("Cannot enumerate apsd: errno=%d (%s). Run as root.\n", error, strerror(error));
    puts("If enumeration is restricted, try /usr/libexec/apnsroute-diag <known apsd PID>.");
    return 1;
}
