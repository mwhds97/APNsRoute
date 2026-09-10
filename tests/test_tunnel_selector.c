#define _DEFAULT_SOURCE 1
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
static struct ifaddrs items[8];static struct sockaddr_in v4[8];static struct sockaddr_in6 v6[8];
static unsigned count,freed;
static int fail;static unsigned mock_index=12;
static int fake_getifaddrs(struct ifaddrs **out) {if(fail){errno=EPERM;return -1;}*out=count?items:NULL;return 0;}
static void fake_freeifaddrs(struct ifaddrs *p) {assert(p==items);++freed;}
static unsigned fake_if_nametoindex(const char *name) {assert(!strcmp(name,"utun7"));return mock_index;}
#define getifaddrs fake_getifaddrs
#define freeifaddrs fake_freeifaddrs
#define if_nametoindex fake_if_nametoindex
#include "../src/TunnelSelector.c"
static void reset(void){memset(items,0,sizeof(items));memset(v4,0,sizeof(v4));memset(v6,0,sizeof(v6));count=freed=0;fail=0;mock_index=12;}
static void add(const char *name,unsigned family,unsigned kind,bool up) {
    assert(count<8);unsigned i=count++;if(i)items[i-1].ifa_next=&items[i];
    items[i].ifa_name=(char *)name;items[i].ifa_flags=up?IFF_UP:0;
    if(family==4) {v4[i].sin_family=AF_INET;v4[i].sin_addr.s_addr=htonl(kind);items[i].ifa_addr=(struct sockaddr *)&v4[i];}
    else {v6[i].sin6_family=AF_INET6;v6[i].sin6_addr.s6_addr[0]=kind>>8;v6[i].sin6_addr.s6_addr[1]=kind;v6[i].sin6_addr.s6_addr[15]=1;items[i].ifa_addr=(struct sockaddr *)&v6[i];}
}
static APRTunnel run(unsigned family,enum apr_tunnel_choice expected) {
    APRTunnel t;int error;errno=EDOM;assert(apr_tunnel_select(family,&t,&error)==expected && errno==EDOM);return t;
}
int main(void) {
    reset();run(0,APR_TUN_NONE);
    add("utun3",6,0xfe80,true);add("utun4",4,0xa9fe0101,true);add("utun5",4,0x0a000001,false);add("en0",4,0xc0a80101,true);
    run(0,APR_TUN_NONE);
    add("utun7",4,0xc6120001,true);APRTunnel t=run(APR_TUN_V4,APR_TUN_UNIQUE);assert(t.index==12 && t.count==1 && t.families==1);
    run(APR_TUN_V6,APR_TUN_FAMILY);
    add("utun7",6,0xfd00,true);t=run(APR_TUN_V6,APR_TUN_UNIQUE);assert(t.count==1 && t.families==3);
    add("utun8",4,0x0a000001,true);t=run(0,APR_TUN_AMBIGUOUS);assert(t.count==2);
    reset();add("utun7",4,0xc6120001,true);mock_index=0;run(0,APR_TUN_CHANGED);
    fail=1;run(0,APR_TUN_UNAVAILABLE);
    puts("PASS: tunnel selection ignores down/link-local/non-tunnel addresses, merges same interface families, rejects ambiguity/family mismatch/disappearance, preserves errno");
}
