/* Bounded latest observations, not a live-object owner or a packet/event log. */
#include "Connections.h"
#include "Diagnostics.h"
#include <errno.h>
#include <pthread.h>
#include <string.h>
typedef struct {uintptr_t key;uint32_t value[APR_CONNECTION_FIELD_COUNT];bool reusable;} Row;
static Row rows[APR_CONNECTION_COUNT];
static pthread_mutex_t row_lock=PTHREAD_MUTEX_INITIALIZER;
static uint32_t next_id;
static unsigned slot_for_id(uint32_t id) {
    if(id) for(unsigned i=0;i<APR_CONNECTION_COUNT;++i)
        if(rows[i].value[APR_R_ID]==id) return i;
    return APR_CONNECTION_COUNT;
}
static void publish(unsigned slot) {apr_diag_connection(slot,rows[slot].value);}
static void increment(uint32_t *v,size_t amount) {
    *v=amount>UINT32_MAX-*v?UINT32_MAX:*v+(uint32_t)amount;
}
uint32_t apr_connection_handler_id(uint32_t id) {
    int saved=errno;uint32_t handler=0;pthread_mutex_lock(&row_lock);
    unsigned slot=slot_for_id(id);
    if(slot<APR_CONNECTION_COUNT) handler=rows[slot].value[APR_R_HANDLER];
    pthread_mutex_unlock(&row_lock);errno=saved;return handler;
}
uint32_t apr_connection_find(uintptr_t key) {
    int saved=errno;uint32_t id=0;pthread_mutex_lock(&row_lock);
    if(key) for(unsigned i=0;i<APR_CONNECTION_COUNT;++i)
        if(rows[i].key==key) {id=rows[i].value[APR_R_ID];break;}
    pthread_mutex_unlock(&row_lock);errno=saved;return id;
}
uint32_t apr_connection_observe(uintptr_t key,unsigned role,bool new_object) {
    int saved=errno;uint32_t id=0;bool full=false;
    if(!key || !role) return 0;
    pthread_mutex_lock(&row_lock);
    unsigned slot=APR_CONNECTION_COUNT;
    for(unsigned i=0;i<APR_CONNECTION_COUNT;++i) {
        if(rows[i].key==key) {
            if(!new_object) {id=rows[i].value[APR_R_ID];goto done;}
            slot=i;break;
        }
        if(slot==APR_CONNECTION_COUNT && !rows[i].value[APR_R_ID]) slot=i;
    }
    /* Preserve recent terminal observations while any empty slot remains. */
    if(slot==APR_CONNECTION_COUNT) for(unsigned i=0;i<APR_CONNECTION_COUNT;++i)
        if(rows[i].reusable && (slot==APR_CONNECTION_COUNT ||
            rows[i].value[APR_R_ID]<rows[slot].value[APR_R_ID])) slot=i;
    if(slot==APR_CONNECTION_COUNT || next_id==UINT32_MAX) {full=true;goto done;}
    rows[slot]=(Row){.key=key};id=++next_id;
    rows[slot].value[APR_R_ID]=id;rows[slot].value[APR_R_ROLE]=role;publish(slot);
done:
    pthread_mutex_unlock(&row_lock);
    if(full) apr_diag_connection_overflow();
    errno=saved;return id;
}
#define BEGIN_ROW(id) int saved=errno;pthread_mutex_lock(&row_lock); \
    unsigned slot=slot_for_id(id); \
    if(slot<APR_CONNECTION_COUNT) {Row *r=&rows[slot];uint32_t *v=r->value;
#define END_ROW publish(slot);} pthread_mutex_unlock(&row_lock);errno=saved;
void apr_connection_handler(uint32_t id,uint32_t handler) {
    BEGIN_ROW(id)
    v[APR_R_HANDLER]=handler;v[APR_R_STATE]=handler?0:APR_ROW_HANDLER_CLEARED;
    r->reusable=!handler;
    END_ROW
}
void apr_connection_state(uint32_t id,uint32_t handler,unsigned state,unsigned domain,int error) {
    int saved=errno;pthread_mutex_lock(&row_lock);unsigned slot=slot_for_id(id);
    if(slot<APR_CONNECTION_COUNT && handler && rows[slot].value[APR_R_HANDLER]==handler) {
        Row *r=&rows[slot];uint32_t *v=r->value;
        v[APR_R_STATE]=(v[APR_R_STATE]&~255U)|(state&255U);
        if(state<=5) v[APR_R_STATE]|=1U<<(APR_ROW_HISTORY_SHIFT+state);
        if(domain) {v[APR_R_ERROR_INFO]=(APR_ERROR_STATE<<8)|(domain&255U);v[APR_R_ERROR_CODE]=(uint32_t)error;}
        r->reusable=state==4 || state==5;publish(slot);
    }
    pthread_mutex_unlock(&row_lock);errno=saved;
}
void apr_connection_send(uint32_t id) {
    BEGIN_ROW(id)
    (void)r;increment(&v[APR_R_SENDS],1);
    END_ROW
}
void apr_connection_retire_requested(uint32_t id) {
    BEGIN_ROW(id)
    (void)r;increment(&v[APR_R_RETIRE_REQUESTS],1);
    END_ROW
}
void apr_connection_read(uint32_t id,unsigned path) {
    BEGIN_ROW(id)
    (void)r;increment(&v[APR_R_READS],1);v[APR_R_PATH]=path;
    END_ROW
}
void apr_connection_received(uint32_t id,size_t bytes,bool complete,unsigned domain,int error) {
    BEGIN_ROW(id)
    (void)r;increment(&v[APR_R_RECEIVED],1);increment(&v[APR_R_BYTES],bytes);
    /* is_complete describes a content context/message, not necessarily TCP EOF. */
    if(complete) increment(&v[APR_R_COMPLETES],1);
    if(domain) {v[APR_R_ERROR_INFO]=(APR_ERROR_RECEIVE<<8)|(domain&255U);v[APR_R_ERROR_CODE]=(uint32_t)error;}
    END_ROW
}
void apr_connection_cancel(uint32_t id,bool force,unsigned path) {
    BEGIN_ROW(id)
    (void)r;unsigned shift=force?16:0;uint32_t count=(v[APR_R_CANCELS]>>shift)&65535U;
    if(count!=65535) v[APR_R_CANCELS]+=1U<<shift;
    v[APR_R_PATH]=path;
    END_ROW
}
#undef BEGIN_ROW
#undef END_ROW
