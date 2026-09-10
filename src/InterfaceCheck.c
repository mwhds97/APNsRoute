/* Darwin 20 necp_client_copy_interface (xnu-7195.141.2): action 9 uses a
   FOUR-byte index, not the header comment's UUID. Success returns zero and
   copies necp_interface_details. Its fixed prefix is name[24], index,
   generation, functional_type, delegate_index. A 256-byte buffer covers the
   100-byte declared structure (IFNET_SIGNATURELEN=20); only validated prefix
   fields are inspected here.
   Queries are read-only and sent through the original NECP function. */
#include "InterfaceCheck.h"
#include "NECPHooks.h"
#include <errno.h>
#include <string.h>
enum apr_interface_check apr_check_interface_exclusions(int fd,const APRTunnel *tunnel,
    const uint32_t prohibited_types[8],
    APRInterfaceEvidence *evidence,int *error) {
    int saved=errno;uint32_t index=tunnel->index,visited[8]={0};unsigned depth=0,types=0;
    enum apr_interface_check status=APR_IF_ALLOWED;*error=0;*evidence=(APRInterfaceEvidence){0};
    if(!index || !tunnel->name[0]) {status=APR_IF_CHANGED;goto done;}
    while(index) {
        evidence->index=index;
        for(unsigned i=0;i<depth;++i)if(visited[i]==index) {status=APR_IF_CYCLE;goto done;}
        if(depth==8) {status=APR_IF_LIMIT;goto done;}
        visited[depth++]=index;
        uint8_t wire[256]={0};errno=0;
        int result=apr_original_necp(fd,9,(uint8_t *)&index,sizeof(index),wire,sizeof(wire));
        if(result) {*error=errno?errno:EIO;status=APR_IF_QUERY_FAILED;goto done;}
        uint32_t returned,type,next;
        memcpy(&returned,wire+24,4);memcpy(&type,wire+32,4);memcpy(&next,wire+36,4);
        if(returned!=index || !wire[0] || !memchr(wire,0,24)) {status=APR_IF_CHANGED;goto done;}
        if(depth==1 && strcmp((const char *)wire,tunnel->name)) {status=APR_IF_CHANGED;goto done;}
        if(type>7) {status=APR_IF_UNSUPPORTED;goto done;}
        types|=1U<<type;
        if(type && (prohibited_types[type/32] & (UINT32_C(1)<<(type%32)))) {
            status=APR_IF_EXCLUDED;goto done;
        }
        index=next;
    }
done:
    evidence->detail=(uint32_t)status | (depth<<8) | (types<<16);
    errno=saved;return status;
}
