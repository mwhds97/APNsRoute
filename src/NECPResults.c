/* Read-only observations of the caller's NECP results. Darwin 20 ABI:
   xnu-7195.141.2/bsd/net/necp.h and necp_client_copy_internal(). No extra
   syscalls, query actions, result rewriting, packet data or persistent logs. */
#include "NECPResults.h"
#include "Diagnostics.h"
#include "InterfaceName.h"
#include "BindingStatus.h"
#include <errno.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
/* IDs associate live matched clients/flows with later results; never published.
   A full table only disables new observations. It cannot change routing. */
enum { TRACKED=64 };
typedef struct {bool used;int fd;uint8_t id[16],root[16];uint32_t generation,requested_index;} Client;
static Client clients[TRACKED];
static pthread_mutex_t clients_lock=PTHREAD_MUTEX_INITIALIZER;
static bool same(const uint8_t a[16],const uint8_t b[16]) {return !memcmp(a,b,16);}
static bool root_for(int fd,const uint8_t id[16],uint8_t root[16],uint32_t *generation,uint32_t *requested_index) {
    bool found=false;pthread_mutex_lock(&clients_lock);
    for(unsigned i=0;i<TRACKED;++i)
        if(clients[i].used && clients[i].fd==fd && same(clients[i].id,id)) {
            memcpy(root,clients[i].root,16);*generation=clients[i].generation;
            *requested_index=clients[i].requested_index;found=true;break;
        }
    pthread_mutex_unlock(&clients_lock);return found;
}
static void record(int fd,const uint8_t id[16],const uint8_t root[16],uint32_t generation,uint32_t requested_index) {
    const uint8_t empty[16]={0};if(same(id,empty)) return;
    pthread_mutex_lock(&clients_lock);
    unsigned chosen=TRACKED;
    for(unsigned i=0;i<TRACKED;++i) {
        if(clients[i].used && clients[i].fd==fd && same(clients[i].id,id)) {chosen=i;break;}
        if(!clients[i].used && chosen==TRACKED) chosen=i;
    }
    if(chosen<TRACKED) {
        clients[chosen].used=true;clients[chosen].fd=fd;
        clients[chosen].generation=generation;clients[chosen].requested_index=requested_index;
        memcpy(clients[chosen].id,id,16);memcpy(clients[chosen].root,root,16);
    }
    pthread_mutex_unlock(&clients_lock);
    if(chosen==TRACKED) apr_diag_event(APR_NECP_TRACK_FULL);
}
void apr_necp_record_binding(int fd,const uint8_t id[16],uint32_t generation,uint32_t requested_index) {
    int saved=errno;record(fd,id,id,generation,requested_index);errno=saved;
}
static void forget(int fd,const uint8_t id[16],bool whole_client) {
    pthread_mutex_lock(&clients_lock);
    for(unsigned i=0;i<TRACKED;++i)
        if(clients[i].used && clients[i].fd==fd &&
            (same(clients[i].id,id) || (whole_client && same(clients[i].root,id))))
            memset(&clients[i],0,sizeof(clients[i]));
    pthread_mutex_unlock(&clients_lock);
}
typedef struct {uint64_t events;bool interface;uint32_t index,policy,flags;} Result;
static void interface_result(uint32_t index,bool primary,Result *out) {
    if(!index) return;
    out->interface=true;char name[IF_NAMESIZE]={0};
    if(primary) {out->index=index;out->flags|=APR_BIND_RESULT_INTERFACE;}
    if(if_indextoname(index,name)) {
        if(apr_index_name(name,"utun")) {
            out->events|=UINT64_C(1)<<APR_NECP_RESULT_UTUN;
            if(primary) out->events|=UINT64_C(1)<<APR_NECP_PRIMARY_UTUN;
        }
        if(apr_index_name(name,"pdp_ip")) {
            out->events|=UINT64_C(1)<<APR_NECP_RESULT_CELLULAR;
            if(primary) out->events|=UINT64_C(1)<<APR_NECP_PRIMARY_CELLULAR;
        }
        if(apr_index_name(name,"lo")) {
            out->events|=UINT64_C(1)<<APR_NECP_RESULT_LOOPBACK;
            if(primary) out->events|=UINT64_C(1)<<APR_NECP_PRIMARY_LOOPBACK;
        }
    }
}
static bool parse_result(const uint8_t *b,size_t size,unsigned depth,Result *out) {
    if(depth>2) return false;
    for(size_t at=0;at<size;) {
        if(size-at<5) return false;
        uint8_t type=b[at];uint32_t n;memcpy(&n,b+at+1,4);
        if(n>size-at-5) return false;
        const uint8_t *p=b+at+5;
        if(type==5 || type==2) {
            if(n<4) return false;
            uint32_t value;memcpy(&value,p,4);
            if(type==5) {
                if(!depth && (out->flags&APR_BIND_RESULT_INTERFACE) && out->index!=value)return false;
                interface_result(value,depth==0,out);
            }
            else {
                if(!depth) {
                    if((out->flags&APR_BIND_RESULT_POLICY) && out->policy!=value)return false;
                    out->policy=value;out->flags|=APR_BIND_RESULT_POLICY;
                }
                if(value==6) out->events|=UINT64_C(1)<<APR_NECP_RESULT_TUNNEL_POLICY;
                if(!depth && (value==12 || value==16)) out->events|=UINT64_C(1)<<APR_NECP_SCOPED_POLICY;
                if(!depth && (value==0 || value==1)) out->events|=UINT64_C(1)<<APR_NECP_PASS_POLICY;
            }
        } else if(type==8) {
            if(n<8) return false;
            uint32_t index;memcpy(&index,p+4,4);interface_result(index,false,out);
        } else if(type==11) {
            if(!parse_result(p,n,depth+1,out)) return false;
        } else if(type==100) {
            if(n<16) return false;
            const uint8_t empty[16]={0};
            if(!same(p,empty)) out->events|=UINT64_C(1)<<APR_NECP_RESULT_NEXUS;
        }
        at+=5+n;
    }
    return true;
}
void apr_necp_result_action(int fd,uint32_t action,const uint8_t id[16],
    const uint8_t *buffer,size_t capacity,int result) {
    int saved=errno;uint8_t root[16];uint32_t generation=0,requested_index=0;
    if(result<0) goto done;
    if((action==2 || action==18) && !result) {forget(fd,id,action==2);goto done;}
    if(!root_for(fd,id,root,&generation,&requested_index)) goto done;
    if(action==17 && !result) {
        /* Packed add_flow: UUID agent, UUID registration, uint16 flags/count. */
        if(buffer && capacity>=36) record(fd,buffer+16,root,generation,requested_index);
    } else if((action==4 || action==16) && result>0) {
        Result found={0};
        if(!buffer || (size_t)result>capacity || result>65536 ||
            !parse_result(buffer,(size_t)result,0,&found)) {
            apr_diag_event(APR_NECP_RESULT_INVALID);
            apr_diag_binding_result(generation,APR_BIND_RESULT_READ|APR_BIND_RESULT_INVALID,0,0);goto done;
        }
        apr_diag_event(APR_NECP_RESULT);
        if(!found.interface) apr_diag_event(APR_NECP_RESULT_NO_INTERFACE);
        if(found.events&(UINT64_C(1)<<APR_NECP_RESULT_NEXUS))found.flags|=APR_BIND_RESULT_NEXUS;
        if(requested_index && (found.flags&APR_BIND_RESULT_INTERFACE) && found.index==requested_index)
            found.flags|=APR_BIND_RESULT_MATCH;
        apr_diag_binding_result(generation,APR_BIND_RESULT_READ|found.flags,found.policy,found.index);
        for(unsigned i=APR_NECP_RESULT_UTUN;i<64 && i<APR_EVENT_COUNT;++i)
            if(found.events&(UINT64_C(1)<<i)) apr_diag_event((enum apr_event)i);
    }
done:
    errno=saved;
}
