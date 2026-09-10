#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "../src/InterfaceCheck.c"
int (*apr_original_necp)(int,uint32_t,uint8_t *,size_t,uint8_t *,size_t);
static unsigned calls,scenario,returned_type;
static uint32_t prohibited[8]={1U<<7};
static int query(int fd,uint32_t action,uint8_t *id,size_t id_length,uint8_t *output,size_t size) {
    assert(fd==7 && action==9 && id_length==4 && size==256 && errno==0);
    uint32_t index;memcpy(&index,id,4);++calls;
    if(scenario==1) {errno=EPERM;return -1;}
    if(scenario==2)return 0; /* Removed interface: Darwin can return an empty structure. */
    memset(output,0,size);
    memcpy(output,index==12?"utun7":"pdp_ip0",index==12?6:8);
    memcpy(output+24,&index,4);
    uint32_t generation=17;memcpy(output+28,&generation,4);
    uint32_t type=index==12?0:5,next=index==12?5:0;
    if(scenario==13 && index==5)type=returned_type;
    if(scenario==14 && index==12)type=returned_type;
    if(scenario==3 && index==5)type=7;
    if(scenario==4 && index==12)type=7;
    if(scenario==5)type=8;
    if(scenario==6 && index==12)memcpy(output,"utun8",6);
    if(scenario==7 && index==5)next=12;
    if(scenario==8)next=index+1;
    if(scenario==9)memset(output,'X',24);
    if(scenario==10) {uint32_t wrong=index+1;memcpy(output+24,&wrong,4);}
    if(scenario==11 && index==12)next=12;
    if(scenario==12) {errno=0;return -1;}
    memcpy(output+32,&type,4);memcpy(output+36,&next,4);return 0;
}
int main(void) {
    apr_original_necp=query;APRTunnel tunnel={.name="utun7",.index=12};
    const enum apr_interface_check expected[]={APR_IF_ALLOWED,APR_IF_QUERY_FAILED,APR_IF_CHANGED,
        APR_IF_EXCLUDED,APR_IF_EXCLUDED,APR_IF_UNSUPPORTED,APR_IF_CHANGED,
        APR_IF_CYCLE,APR_IF_LIMIT,APR_IF_CHANGED,APR_IF_CHANGED,APR_IF_CYCLE,APR_IF_QUERY_FAILED};
    for(scenario=0;scenario<sizeof(expected)/sizeof(*expected);++scenario) {
        APRInterfaceEvidence evidence={0};int error=-1;calls=0;errno=EDOM;
        assert(apr_check_interface_exclusions(7,&tunnel,prohibited,&evidence,&error)==expected[scenario]);
        assert(errno==EDOM && (evidence.detail&255)==expected[scenario] && calls<=8);
        assert(((evidence.detail>>8)&255)==calls);
        if(!scenario)assert(calls==2 && evidence.index==5 && (evidence.detail>>16)==((1U<<0)|(1U<<5)));
        if(scenario==1)assert(error==EPERM);
        else if(scenario==12)assert(error==EIO);
        else assert(!error);
        if(scenario==3)assert(evidence.index==5 && (evidence.detail&(1U<<23)));
        if(scenario==4)assert(evidence.index==12 && calls==1);
        if(scenario==8)assert(calls==8);
    }
    /* Every declared type, checked on both the selected interface and its
       delegate. Zero is a sentinel in a prohibition list, never a restriction. */
    for(scenario=13;scenario<=14;++scenario)for(returned_type=0;returned_type<=7;++returned_type)
        for(unsigned excluded=0;excluded<256;++excluded) {
            memset(prohibited,0,sizeof(prohibited));prohibited[excluded/32]=UINT32_C(1)<<(excluded%32);
            calls=0;errno=EDOM;int error=-1;APRInterfaceEvidence evidence;
            bool conflict=excluded && (excluded==returned_type || (scenario==14 && excluded==5));
            assert(apr_check_interface_exclusions(7,&tunnel,prohibited,&evidence,&error)==
                (conflict?APR_IF_EXCLUDED:APR_IF_ALLOWED));
            assert(errno==EDOM && !error && calls>=1 && calls<=2);
        }
    /* Multiple unrelated exclusions, zero, and the highest possible byte
       retain meaning together. Adding the actual delegate type rejects it. */
    scenario=0;memset(prohibited,0,sizeof(prohibited));
    prohibited[0]=(1U<<0)|(1U<<4)|(1U<<6)|(1U<<7);prohibited[7]=UINT32_C(1)<<31;
    int error;APRInterfaceEvidence evidence;
    assert(apr_check_interface_exclusions(7,&tunnel,prohibited,&evidence,&error)==APR_IF_ALLOWED);
    prohibited[0]|=1U<<5;
    assert(apr_check_interface_exclusions(7,&tunnel,prohibited,&evidence,&error)==APR_IF_EXCLUDED);
    assert(evidence.index==5 && (evidence.detail>>16)==((1U<<0)|(1U<<5)));
    scenario=5;
    assert(apr_check_interface_exclusions(7,&tunnel,prohibited,&evidence,&error)==APR_IF_UNSUPPORTED);
    tunnel.index=0;calls=0;
    assert(apr_check_interface_exclusions(7,&tunnel,prohibited,&evidence,&error)==APR_IF_CHANGED && !calls);
    puts("PASS: actual COPY_INTERFACE ABI, tunnel/delegate exclusion, unknown/missing/reused interfaces, cycles/depth, denied query and errno");
}
