/* One-shot doctor inspection. No injection, logs, reverse DNS or socket writes. */
#include "LiveSockets.h"
#include "Policy.h"
#include "vendor/proc_info.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*PIDInfo)(int,int,uint64_t,void *,int);
typedef int (*FDInfo)(int,int,int,void *,int);
static const char *tcp_state(int state) {
    const char *names[]={"closed","listen","SYN-sent","SYN-received","established",
        "close-wait","fin-wait-1","closing","last-ack","fin-wait-2","time-wait"};
    return state>=0 && state<11 ? names[state] : "unknown";
}
static const char *source_interface(struct ifaddrs *all,int family,const void *local) {
    for(struct ifaddrs *p=all;p;p=p->ifa_next) {
        if(!p->ifa_addr || p->ifa_addr->sa_family!=family) continue;
        const void *a=family==AF_INET ? (const void *)&((struct sockaddr_in *)p->ifa_addr)->sin_addr :
            (const void *)&((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;
        if(!memcmp(a,local,family==AF_INET ? 4 : 16)) return p->ifa_name;
    }
    return "unmatched";
}
void apr_live_sockets(pid_t pid) {
    puts("Live apsd TCP sockets (one-shot, independent of hook events):");
    PIDInfo pid_info=(PIDInfo)dlsym(RTLD_DEFAULT,"proc_pidinfo");
    FDInfo fd_info=(FDInfo)dlsym(RTLD_DEFAULT,"proc_pidfdinfo");
    if(!pid_info || !fd_info) { puts("  Socket inspection API unavailable on this device."); return; }
    errno=0; int wanted=pid_info(pid,PROC_PIDLISTFDS,0,NULL,0);
    if(wanted<=0 || wanted>1024*1024) {
        printf("  Cannot enumerate descriptors: result=%d errno=%d (%s).\n",wanted,errno,strerror(errno));
        puts("  This does not establish that apsd has no connection."); return;
    }
    int capacity=wanted+(int)(32*sizeof(struct proc_fdinfo));
    struct proc_fdinfo *fds=malloc((size_t)capacity);
    if(!fds) { puts("  Descriptor allocation failed."); return; }
    int used=pid_info(pid,PROC_PIDLISTFDS,0,fds,capacity);
    if(used<=0 || used>capacity || used%(int)sizeof(*fds)) {
        printf("  Descriptor snapshot failed: errno=%d (%s).\n",errno,strerror(errno)); free(fds); return;
    }
    struct ifaddrs *interfaces=NULL; (void)getifaddrs(&interfaces);
    unsigned shown=0,denied=0,socket_count=0,policy_count=0;
    for(size_t i=0;i<(size_t)used/sizeof(*fds);++i) {
        if(fds[i].proc_fdtype==PROX_FDTYPE_NETPOLICY) ++policy_count;
        if(fds[i].proc_fdtype!=PROX_FDTYPE_SOCKET) continue;
        ++socket_count;
        struct socket_fdinfo socket={0};
        if(fd_info(pid,fds[i].proc_fd,PROC_PIDFDSOCKETINFO,&socket,sizeof(socket))!=(int)sizeof(socket)) { ++denied; continue; }
        if(socket.psi.soi_kind!=SOCKINFO_TCP) continue;
        const struct tcp_sockinfo *tcp=&socket.psi.soi_proto.pri_tcp;
        const struct in_sockinfo *ip=&tcp->tcpsi_ini;
        unsigned port=ntohs((uint16_t)ip->insi_fport);
        int family; const void *local,*remote;
        if(ip->insi_vflag & INI_IPV4) {
            family=AF_INET; local=&ip->insi_laddr.ina_46.i46a_addr4; remote=&ip->insi_faddr.ina_46.i46a_addr4;
        } else if(ip->insi_vflag & INI_IPV6) {
            family=AF_INET6; local=&ip->insi_laddr.ina_6; remote=&ip->insi_faddr.ina_6;
        } else continue;
        if(shown++>=16) continue;
        char src[INET6_ADDRSTRLEN]={0},dst[INET6_ADDRSTRLEN]={0};
        if(!inet_ntop(family,local,src,sizeof(src)) || !inet_ntop(family,remote,dst,sizeof(dst))) continue;
        bool ip_match=family==AF_INET?apr_ipv4_target(remote):apr_ipv6_target(remote);
        printf("  fd=%d TCP/%u %s local=%s remote=%s CIDR-match=%s source-address-match=%s\n",
            fds[i].proc_fd,port,tcp_state(tcp->tcpsi_state),src,dst,ip_match?"yes":"no",
            source_interface(interfaces,family,local));
    }
    if(!shown) puts("  No readable TCP socket found in this snapshot.");
    printf("  Descriptor counts: sockets=%u network-policy=%u total=%zu.\n",
        socket_count,policy_count,(size_t)used/sizeof(*fds));
    puts("  BSD sockets do not cover every Network.framework/Nexus flow; see NECP results above.");
    if(shown>16) printf("  %u additional TCP sockets omitted.\n",shown-16);
    if(denied) printf("  %u sockets could not be inspected (closed concurrently or access denied).\n",denied);
    if(used==capacity) puts("  Descriptor list may be truncated; rerun doctor.");
    puts("  Socket snapshots have no hostname metadata. CIDR/source-address matches do not prove Surge capture.");
    if(interfaces) freeifaddrs(interfaces);
    free(fds);
}
