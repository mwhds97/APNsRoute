/* Fixed-size doctor state; no files, unified logs, payloads or timers. */
#include "Diagnostics.h"
#include "HookEngine.h"
#include "ConnectionStatus.h"
#include <errno.h>
#include <notify.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int tokens[APR_DIAG_SLOTS];
static uint64_t states[APR_DIAG_SLOTS];
static bool transport_dirty[APR_TRANSPORT_SLOTS];
static bool publish(unsigned slot) {
    return tokens[slot]>=0 && notify_set_state(tokens[slot],states[slot])==NOTIFY_STATUS_OK;
}
void apr_diag_init(uint64_t incarnation) {
    int saved = errno;
    for(unsigned i=0;i<APR_DIAG_SLOTS;++i)states[i]=APR_DIAG_MAGIC;
    states[APR_D_STATUS]|=APR_ENTERED;states[APR_D_VERSION]|=APR_BUILD_ID;
    for (unsigned i=0; i<APR_DIAG_SLOTS; ++i) {
        char name[128];
        snprintf(name,sizeof(name),APR_DIAG_PREFIX ".%ld.%llu.%s",
            (long)getpid(),(unsigned long long)incarnation,apr_diag_field_name(i));
        tokens[i]=-1;
        if (notify_register_check(name,&tokens[i]) != NOTIFY_STATUS_OK) tokens[i]=-1;
        bool ok=publish(i);
        if(i>APR_TRANSPORT_FIRST_SLOT) transport_dirty[i-APR_TRANSPORT_FIRST_SLOT]=!ok;
    }
    errno=saved;
}
void apr_diag_stage(enum apr_stage stage, int config_error, bool unbind) {
    int saved=errno; pthread_mutex_lock(&lock);
    states[APR_D_STATUS] &= ~(UINT64_C(0xffff) | APR_DIAG_UNBIND);
    states[APR_D_STATUS] |= (uint64_t)stage | ((uint64_t)(config_error & 255)<<8);
    if (unbind) states[APR_D_STATUS] |= APR_DIAG_UNBIND;
    publish(APR_D_STATUS); pthread_mutex_unlock(&lock); errno=saved;
}
void apr_diag_hook(unsigned mask) {
    int saved=errno; pthread_mutex_lock(&lock);
    states[APR_D_STATUS] |= (uint64_t)(mask & APR_HOOK_MASK)<<17;
    publish(APR_D_STATUS); pthread_mutex_unlock(&lock); errno=saved;
}
void apr_diag_event(enum apr_event event) {
    int saved=errno;
    if ((unsigned)event >= APR_EVENT_COUNT) return;
    pthread_mutex_lock(&lock);
    _Static_assert(APR_EVENT_COUNT<=64,"doctor event capacity exceeded");
    unsigned slot=(unsigned)event<32 ? APR_D_EVENTS : APR_D_EVENTS2;
    uint64_t bit=UINT64_C(1)<<((unsigned)event%32);
    if (!(states[slot] & bit)) { states[slot] |= bit; publish(slot); }
    pthread_mutex_unlock(&lock); errno=saved;
}
void apr_diag_engine(unsigned source, unsigned result) {
    int saved=errno;
    if (source>=APR_HOOK_SOURCE_COUNT || result>APR_LOOKUP_FOUND) return;
    pthread_mutex_lock(&lock);
    unsigned shift=4*source;
    states[APR_D_ENGINE]=(states[APR_D_ENGINE] & ~(UINT64_C(15)<<shift)) | ((uint64_t)result<<shift);
    publish(APR_D_ENGINE); pthread_mutex_unlock(&lock); errno=saved;
}
void apr_diag_necp_reject(enum apr_necp_reject reason, unsigned type, uint32_t length) {
    int saved=errno; pthread_mutex_lock(&lock);
    /* One bounded structural example; no input bytes, hosts or UUIDs. */
    if (!(uint32_t)states[APR_D_NECP_REJECT]) {
        if(length>65535) length=65535;
        states[APR_D_NECP_REJECT]=APR_DIAG_MAGIC | (unsigned)reason | ((uint64_t)(type&255)<<8) |
            ((uint64_t)length<<16);
        publish(APR_D_NECP_REJECT);
    }
    pthread_mutex_unlock(&lock); errno=saved;
}

/* Seqlock publication for a coherent bounded transport snapshot. Readers must
   see the same even sequence before/after all transport fields. Failure of any
   notification state invalidates the snapshot; it never affects connections. */
static uint32_t transport_sequence,handler_generation;
static bool transport_publication_ok;
static void transport_begin(void) {
    states[APR_TRANSPORT_FIRST_SLOT + APR_T_SEQ]=APR_DIAG_MAGIC | ++transport_sequence;transport_publication_ok=publish(APR_TRANSPORT_FIRST_SLOT + APR_T_SEQ);
}
static void transport_set(unsigned slot,uint32_t value) {
    uint64_t next=APR_DIAG_MAGIC | value;
    if(states[APR_TRANSPORT_FIRST_SLOT + slot]!=next) {
        states[APR_TRANSPORT_FIRST_SLOT + slot]=next;transport_dirty[slot]=true;
    }
}
static void transport_end(void) {
    /* Publish changed fields and retry every failed field. Receive callbacks
       need only update their own row, not every slot. The same even sequence
       still certifies the whole snapshot; incomplete writes stay uncertified. */
    if(transport_publication_ok) {
        for(unsigned slot=1;slot<APR_TRANSPORT_SLOTS;++slot) if(transport_dirty[slot]) {
            if(publish(APR_TRANSPORT_FIRST_SLOT+slot)) transport_dirty[slot]=false;
            else transport_publication_ok=false;
        }
    }
    states[APR_TRANSPORT_FIRST_SLOT + APR_T_SEQ]=APR_DIAG_MAGIC | ++transport_sequence;
    if(transport_publication_ok) (void)publish(APR_TRANSPORT_FIRST_SLOT + APR_T_SEQ);
}
void apr_diag_nw_created(bool created,int error) {
    int saved=errno;pthread_mutex_lock(&lock);transport_begin();
    transport_set(APR_T_NW_CREATED,APR_CREATE_SEEN | (created?APR_CREATE_OK:0));
    transport_set(APR_T_NW_CREATE_ERRNO,(uint32_t)error);
    transport_end();pthread_mutex_unlock(&lock);errno=saved;
}
void apr_diag_nw_start(unsigned detail) {
    int saved=errno;pthread_mutex_lock(&lock);transport_begin();
    transport_set(APR_T_NW_START,detail);transport_end();pthread_mutex_unlock(&lock);errno=saved;
}
uint32_t apr_diag_nw_handler(void) {
    int saved=errno;pthread_mutex_lock(&lock);
    uint32_t generation=0;
    if(handler_generation!=UINT32_MAX) {
        generation=++handler_generation;
        transport_begin();transport_set(APR_T_NW_STATE,APR_STATE_REGISTERED);
        transport_set(APR_T_NW_STATE_ERROR,0);transport_set(APR_T_NW_HANDLER_ID,generation);transport_end();
    }
    pthread_mutex_unlock(&lock);errno=saved;return generation;
}
void apr_diag_nw_state(uint32_t generation,unsigned state,unsigned domain,int error) {
    int saved=errno;pthread_mutex_lock(&lock);
    /* Delayed callbacks from replaced/older handlers cannot overwrite the
       most recently registered handler's state or signed error code. */
    if(generation && generation==handler_generation) {
        uint32_t detail=APR_STATE_REGISTERED | APR_STATE_CALLBACK | (state&255U);
        detail|=(uint32_t)states[APR_TRANSPORT_FIRST_SLOT + APR_T_NW_STATE] & (63U<<APR_STATE_HISTORY_SHIFT);
        if(state<=5) detail|=1U<<(APR_STATE_HISTORY_SHIFT+state);
        if(domain) detail|=((domain&255U)<<8) | APR_STATE_CURRENT_ERROR;
        else detail|=(uint32_t)states[APR_TRANSPORT_FIRST_SLOT + APR_T_NW_STATE]&0xff00U; /* preserve last error */
        transport_begin();transport_set(APR_T_NW_STATE,detail);
        if(domain) transport_set(APR_T_NW_STATE_ERROR,(uint32_t)error);
        transport_end();
    }
    pthread_mutex_unlock(&lock);errno=saved;
}
void apr_diag_nw_report(unsigned detail) {
    int saved=errno;pthread_mutex_lock(&lock);transport_begin();
    transport_set(APR_T_NW_REPORT,detail);transport_end();pthread_mutex_unlock(&lock);errno=saved;
}
void apr_diag_nw_cancel_path(unsigned detail) {
    int saved=errno;pthread_mutex_lock(&lock);transport_begin();
    transport_set(APR_T_NW_CANCEL_PATH,detail);transport_end();pthread_mutex_unlock(&lock);errno=saved;
}
static void transport_increment(unsigned slot) {
    uint32_t value=(uint32_t)states[APR_TRANSPORT_FIRST_SLOT+slot];
    transport_set(slot,value==UINT32_MAX?value:value+1);
}
void apr_diag_connection(unsigned slot,const uint32_t value[APR_CONNECTION_FIELD_COUNT]) {
    if(slot>=APR_CONNECTION_COUNT || !value) return;
    int saved=errno;pthread_mutex_lock(&lock);transport_begin();
    unsigned base=APR_T_CONN_0_ID+slot*APR_CONNECTION_FIELD_COUNT;
    for(unsigned i=0;i<APR_CONNECTION_FIELD_COUNT;++i) transport_set(base+i,value[i]);
    transport_end();pthread_mutex_unlock(&lock);errno=saved;
}
void apr_diag_connection_overflow(void) {
    int saved=errno;pthread_mutex_lock(&lock);transport_begin();
    transport_increment(APR_T_CONNECTION_OVERFLOW);
    transport_end();pthread_mutex_unlock(&lock);errno=saved;
}
void apr_diag_retirement(const APRRetirementStatus *status) {
    if(!status) return;
    int saved=errno;pthread_mutex_lock(&lock);transport_begin();
    transport_set(APR_T_RET_STATUS,status->status);
    transport_set(APR_T_RET_NETWORK,status->network);
    transport_set(APR_T_RET_EPOCH,status->epoch);
    transport_set(APR_T_RET_HELD,status->held);
    transport_set(APR_T_RET_PENDING,status->pending);
    transport_set(APR_T_RET_REQUESTS,status->requests);
    transport_set(APR_T_RET_LAST_ID,status->last_id);
    transport_set(APR_T_RET_REASON,status->reason);
    transport_set(APR_T_RET_ERROR,status->error);
    transport_set(APR_T_RET_SKIPPED,status->skipped);
    transport_set(APR_T_RET_AWAITING,status->awaiting);
    transport_end();pthread_mutex_unlock(&lock);errno=saved;
}
void apr_diag_nw_cancel(unsigned action) {
    if(action<APR_CANCEL_NATIVE || action>APR_CANCEL_APP_FORCE) return;
    int saved=errno;pthread_mutex_lock(&lock);transport_begin();
    transport_increment(action==APR_CANCEL_APP_FORCE?APR_T_NW_CANCEL_APP_FORCE:APR_T_NW_CANCEL_NORMAL);
    if(action==APR_CANCEL_IMMEDIATE) transport_increment(APR_T_NW_CANCEL_IMMEDIATE);
    transport_set(APR_T_NW_CANCEL_ACTION,action);
    transport_end();pthread_mutex_unlock(&lock);errno=saved;
}
/* Latest matched ADD and later results for exactly that client/its registered
   flows. Generation identifiers prevent older clients overwriting this pair. */
static uint32_t binding_generation;
uint32_t apr_diag_binding(uint32_t status,uint32_t index,int error,const APRConstraints *constraints) {
    int saved=errno;pthread_mutex_lock(&lock);uint32_t generation=0;
    if(binding_generation!=UINT32_MAX) {
        generation=++binding_generation;transport_begin();
        transport_set(APR_T_NECP_BINDING_ID,generation);transport_set(APR_T_NECP_BINDING_INDEX,index);transport_set(APR_T_NECP_BINDING_STATUS,status);
        transport_set(APR_T_NECP_BINDING_ERRNO,(uint32_t)error);transport_set(APR_T_NECP_BINDING_RESULT,0);transport_set(APR_T_NECP_BINDING_POLICY,0);transport_set(APR_T_NECP_BINDING_RESULT_INDEX,0);
        transport_set(APR_T_NECP_CONSTRAINTS_SEEN,constraints?constraints->seen:0);
        transport_set(APR_T_NECP_CLIENT_FLAGS,constraints?constraints->request_flags:0);
        transport_set(APR_T_NECP_CONSTRAINTS_RESTRICTED,constraints?constraints->restricted:0);
        transport_set(APR_T_NECP_CONSTRAINTS_INERT,constraints?constraints->inert:0);
        transport_set(APR_T_NECP_CONSTRAINTS_UNSUPPORTED,constraints?constraints->unsupported:0);
        transport_set(APR_T_NECP_CONSTRAINTS_FIRST,constraints?constraints->first:0);
        transport_set(APR_T_NECP_CONSTRAINTS_BLOCKED,constraints?constraints->blocked:0);
        transport_set(APR_T_NECP_AGENT_INFO,constraints?constraints->agent_info:0);
        transport_set(APR_T_NECP_AGENT_EDIT,constraints?constraints->edit:0);
        transport_set(APR_T_NECP_INTERFACE_CHECK,constraints?constraints->check:0);
        transport_set(APR_T_NECP_INTERFACE_CHECK_INDEX,constraints?constraints->check_index:0);
        for(unsigned i=0;i<16;++i) {
            uint32_t word=0;if(constraints)memcpy(&word,constraints->agent+i*4,4);
            transport_set(APR_T_NECP_AGENT_NAME_0+i,word);
        }
        for(unsigned i=0;i<8;++i)
            transport_set(APR_T_NECP_PROHIBITED_TYPES_0+i,constraints?constraints->prohibited_types[i]:0);
        transport_end();
    }
    pthread_mutex_unlock(&lock);errno=saved;return generation;
}
void apr_diag_binding_result(uint32_t generation,uint32_t flags,uint32_t policy,uint32_t index) {
    int saved=errno;pthread_mutex_lock(&lock);
    if(generation && generation==binding_generation) {
        transport_begin();transport_set(APR_T_NECP_BINDING_RESULT,flags);transport_set(APR_T_NECP_BINDING_POLICY,policy);transport_set(APR_T_NECP_BINDING_RESULT_INDEX,index);transport_end();
    }
    pthread_mutex_unlock(&lock);errno=saved;
}
