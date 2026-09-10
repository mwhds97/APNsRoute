/* Actual bounded observer against independent Darwin result TLVs. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "../src/Diagnostics.h"
static uint64_t events;
void apr_diag_event(enum apr_event e) {events|=UINT64_C(1)<<e;errno=EIO;}
static char *interface_name(unsigned index,char *name) {
    errno=EIO;if(index!=7 && index!=9 && index!=1) return NULL;
    strcpy(name,index==7?"pdp_ip0":index==9?"utun3":"lo0");return name;
}
#define if_indextoname interface_name
static uint32_t result_generation,result_flags,result_policy,result_index;
void apr_diag_binding_result(uint32_t g,uint32_t f,uint32_t p,uint32_t i) {
    result_generation=g;result_flags=f;result_policy=p;result_index=i;
}
#include "../src/NECPResults.c"
#undef if_indextoname
static size_t put(uint8_t *b,size_t at,uint8_t type,const void *value,uint32_t n) {
    b[at]=type;memcpy(b+at+1,&n,4);memcpy(b+at+5,value,n);return at+5+n;
}
static void observe(int fd,unsigned action,const uint8_t id[16],uint8_t *b,size_t cap,int result) {
    uint8_t original[512];assert(cap<=sizeof(original));memcpy(original,b,cap);
    events=0;errno=EDOM;apr_necp_result_action(fd,action,id,b,cap,result);
    assert(errno==EDOM && !memcmp(original,b,cap));
}
int main(void) {
    uint8_t id[16]={1},alias[16]={2},other[16]={3},buffer[512]={0},nested[128]={0};
    uint32_t index=9,policy=6,flow_interface[]={17,7};uint8_t nexus[16]={7};
    size_t n=put(buffer,0,2,&policy,4);n=put(buffer,n,5,&index,4);
    size_t inner=put(nested,0,8,flow_interface,8);inner=put(nested,inner,100,nexus,16);
    n=put(buffer,n,11,nested,(uint32_t)inner);
    observe(7,4,id,buffer,sizeof(buffer),(int)n);assert(!events);
    errno=EDOM;apr_necp_record_binding(7,id,0,0);assert(errno==EDOM);
    observe(8,4,id,buffer,sizeof(buffer),(int)n);assert(!events);
    observe(7,4,other,buffer,sizeof(buffer),(int)n);assert(!events);
    observe(7,4,id,buffer,sizeof(buffer),-1);assert(!events);
    observe(7,4,id,buffer,sizeof(buffer),0);assert(!events);
    /* Parse only bytes returned by the syscall, not unused capacity. */
    memset(buffer+n,0xff,sizeof(buffer)-n);
    observe(7,4,id,buffer,sizeof(buffer),(int)n);
    assert(events&(UINT64_C(1)<<APR_NECP_RESULT));
    assert(events&(UINT64_C(1)<<APR_NECP_RESULT_UTUN));
    assert(events&(UINT64_C(1)<<APR_NECP_RESULT_CELLULAR));
    assert(events&(UINT64_C(1)<<APR_NECP_RESULT_NEXUS));
    assert(events&(UINT64_C(1)<<APR_NECP_RESULT_TUNNEL_POLICY));
    assert(events&(UINT64_C(1)<<APR_NECP_PRIMARY_UTUN));
    assert(!(events&(UINT64_C(1)<<APR_NECP_PRIMARY_CELLULAR)));
    observe(7,16,id,buffer,n-1,(int)n);assert(events==(UINT64_C(1)<<APR_NECP_RESULT_INVALID));
    observe(7,16,id,buffer,sizeof(buffer),(int)n-1);assert(events==(UINT64_C(1)<<APR_NECP_RESULT_INVALID));
    uint8_t sample[64]={0};uint32_t local=1,scoped=12;
    size_t sample_n=put(sample,0,5,&local,4);sample_n=put(sample,sample_n,2,&scoped,4);
    observe(7,4,id,sample,sizeof(sample),(int)sample_n);
    assert(events&(UINT64_C(1)<<APR_NECP_PRIMARY_LOOPBACK));
    assert(events&(UINT64_C(1)<<APR_NECP_RESULT_LOOPBACK));
    assert(events&(UINT64_C(1)<<APR_NECP_SCOPED_POLICY));
    assert(!(events&(UINT64_C(1)<<APR_NECP_PASS_POLICY)));
    scoped=1;sample_n=put(sample,0,2,&scoped,4);
    observe(7,4,id,sample,sizeof(sample),(int)sample_n);
    assert(events&(UINT64_C(1)<<APR_NECP_PASS_POLICY));
    uint8_t add_flow[36]={0};memcpy(add_flow+16,alias,16);
    observe(7,17,id,add_flow,sizeof(add_flow),0);assert(!events);
    observe(7,16,alias,buffer,sizeof(buffer),(int)n);assert(events&(UINT64_C(1)<<APR_NECP_RESULT));
    observe(7,18,alias,buffer,0,0);
    observe(7,4,alias,buffer,sizeof(buffer),(int)n);assert(!events);
    observe(7,17,id,add_flow,sizeof(add_flow),0);
    observe(7,2,id,buffer,0,0);
    observe(7,4,alias,buffer,sizeof(buffer),(int)n);assert(!events);
    observe(7,4,id,buffer,sizeof(buffer),(int)n);assert(!events);
    apr_necp_record_binding(7,id,42,9);
    observe(7,4,id,buffer,sizeof(buffer),(int)n);
    assert(result_generation==42 && (result_flags&APR_BIND_RESULT_MATCH) && result_index==9 && result_policy==6);
    observe(7,17,id,add_flow,sizeof(add_flow),0);
    observe(7,16,alias,buffer,sizeof(buffer),(int)n);
    assert(result_generation==42 && (result_flags&APR_BIND_RESULT_MATCH));
    apr_necp_record_binding(7,id,43,7);
    observe(7,4,id,buffer,sizeof(buffer),(int)n);
    assert(result_generation==43 && !(result_flags&APR_BIND_RESULT_MATCH));
    observe(7,16,alias,buffer,sizeof(buffer),(int)n);
    assert(result_generation==42); /* Older alias retains its original generation. */
    uint32_t conflict=7;
    size_t contradictory=put(buffer,n,5,&conflict,4);
    observe(7,4,id,buffer,sizeof(buffer),(int)contradictory);
    assert(result_generation==43 && (result_flags&APR_BIND_RESULT_INVALID));
    observe(7,2,id,buffer,0,0);
    for(unsigned i=1;i<=64;++i) {uint8_t key[16]={0};key[0]=(uint8_t)i;apr_necp_record_binding(8,key,0,0);}
    events=0;uint8_t overflow[16]={65};apr_necp_record_binding(8,overflow,0,0);
    assert(events==(UINT64_C(1)<<APR_NECP_TRACK_FULL));
    observe(8,4,overflow,buffer,sizeof(buffer),(int)n);assert(!events);
    puts("PASS: rule-matched NECP result/flow tracking, returned-length bounds, nested Nexus/interface results, cleanup, capacity, input immutability and errno");
}
