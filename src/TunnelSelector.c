/* Select only one up utun with a usable non-link-local IP address. Interface
   presence does not establish its owner or prove a usable destination route. */
#include "TunnelSelector.h"
#include "InterfaceName.h"
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
static unsigned address_family(const struct sockaddr *address) {
    if(!address) return 0;
    if(address->sa_family==AF_INET) {
        uint32_t ip=ntohl(((const struct sockaddr_in *)address)->sin_addr.s_addr);
        if(!ip || (ip>>24)==127 || (ip>>16)==0xa9fe || (ip>>28)>=14) return 0;
        return APR_TUN_V4;
    }
    if(address->sa_family==AF_INET6) {
        const struct in6_addr *ip=&((const struct sockaddr_in6 *)address)->sin6_addr;
        if(IN6_IS_ADDR_UNSPECIFIED(ip) || IN6_IS_ADDR_LOOPBACK(ip) ||
           IN6_IS_ADDR_LINKLOCAL(ip) || IN6_IS_ADDR_MULTICAST(ip)) return 0;
        return APR_TUN_V6;
    }
    return 0;
}
enum apr_tunnel_choice apr_tunnel_select(unsigned family,APRTunnel *out,int *error) {
    int saved=errno;struct ifaddrs *all=NULL;*out=(APRTunnel){0};*error=0;
    enum apr_tunnel_choice result=APR_TUN_NONE;
    if(getifaddrs(&all)) {*error=errno;result=APR_TUN_UNAVAILABLE;goto done;}
    for(struct ifaddrs *p=all;p;p=p->ifa_next) {
        if(!(p->ifa_flags&IFF_UP) || !apr_index_name(p->ifa_name,"utun")) continue;
        unsigned f=address_family(p->ifa_addr);if(!f)continue;
        if(out->name[0] && strcmp(out->name,p->ifa_name)) {
            out->count=2;result=APR_TUN_AMBIGUOUS;goto done;
        }
        if(strlen(p->ifa_name)>=sizeof(out->name)) {result=APR_TUN_UNAVAILABLE;*error=ENAMETOOLONG;goto done;}
        strcpy(out->name,p->ifa_name);out->families|=f;out->count=1;
    }
    if(out->count) {
        errno=0;out->index=if_nametoindex(out->name);
        if(!out->index) {result=APR_TUN_CHANGED;*error=errno?errno:ENXIO;goto done;}
        result=family && !(family&out->families)?APR_TUN_FAMILY:APR_TUN_UNIQUE;
    }
done:
    if(all)freeifaddrs(all);
    errno=saved;return result;
}
