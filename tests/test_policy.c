/* Independent literal fixtures for the user's 13 rules and their boundaries. */
#include <assert.h>
#include <stdio.h>
#include "../src/Policy.h"
#include "../src/InterfaceName.h"

static void address_case(const char *text, int family, bool expected) {
    uint8_t raw[17]={0}; /* Deliberately unaligned address. */
    assert(inet_pton(family,text,raw+1)==1);
    bool actual=family==AF_INET?apr_ipv4_target(raw+1):apr_ipv6_target(raw+1);
    if(actual!=expected || apr_host_target(text)!=expected) {
        fprintf(stderr,"Address policy mismatch: %s (expected %d)\n",text,expected);
        assert(false);
    }
    assert(!apr_domain_target(text));
}
int main(void) {
    const char *accepted[]={
        "identity.apple.com", "IDENTITY.APPLE.COM.",
        "push.apple.com", "init.push.apple.com", "any.push.apple.com",
        "x.y.push.apple.com", "12-COURIER4.PUSH.APPLE.COM.",
        "courier.sandbox.push.apple.com", "akadns.net", "x.AKADNS.NET.",
        "apple.com.edgekey.net", "e123.apple.com.edgekey.net",
        "prefixapple.com.edgekey.netextra.example", "APPLE.COM.EDGEKEY.NET.example"
    };
    const char *rejected[]={
        "", ".", "example.net", "identity.apple.com.example", "x.identity.apple.com",
        "notidentity.apple.com", "evilpush.apple.com", "push.apple.com.example",
        "notakadns.net", "akadns.net.example", "apple.com.edgekeyXnet",
        "appleXcom.edgekey.net", "apple.com.other.edgekey.net", "apple.com",
        "push.apple.com..", "x..push.apple.com", "-x.push.apple.com",
        "x-.push.apple.com", "*.push.apple.com", "x_.push.apple.com",
        "push.apple.com:443", " push.apple.com", "https://identity.apple.com"
    };
    for(size_t i=0;i<sizeof(accepted)/sizeof(*accepted);++i) {
        assert(apr_domain_target(accepted[i]));assert(apr_host_target(accepted[i]));
    }
    for(size_t i=0;i<sizeof(rejected)/sizeof(*rejected);++i)assert(!apr_host_target(rejected[i]));
    assert(!apr_host_target(NULL) && !apr_ipv4_target(NULL) && !apr_ipv6_target(NULL));

    const char *v4[][4]={
        {"17.249.0.0","17.249.255.255","17.248.255.255","17.250.0.0"},
        {"17.252.0.0","17.252.255.255","17.251.255.255","17.253.0.0"},
        {"17.57.144.0","17.57.147.255","17.57.143.255","17.57.148.0"},
        {"17.188.128.0","17.188.191.255","17.188.127.255","17.188.192.0"},
        {"17.188.20.0","17.188.21.255","17.188.19.255","17.188.22.0"}
    };
    for(size_t i=0;i<sizeof(v4)/sizeof(*v4);++i)
        for(unsigned j=0;j<4;++j)address_case(v4[i][j],AF_INET,j<2);
    address_case("17.0.0.1",AF_INET,false);
    address_case("127.0.0.1",AF_INET,false);
    address_case("18.249.0.1",AF_INET,false);
    /* All /24 blocks around the non-byte-aligned IPv4 prefixes. */
    for(unsigned third=0;third<256;++third) {
        uint8_t ip[]={17,188,third,123};
        assert(apr_ipv4_target(ip)==((third>=128 && third<=191) || third==20 || third==21));
        ip[1]=57;assert(apr_ipv4_target(ip)==(third>=144 && third<=147));
    }
    const char *v6[][4]={
        {"2620:149:a44::","2620:149:a44:ffff:ffff:ffff:ffff:ffff","2620:149:a43:ffff:ffff:ffff:ffff:ffff","2620:149:a45::"},
        {"2403:300:a42::","2403:300:a42:ffff:ffff:ffff:ffff:ffff","2403:300:a41:ffff:ffff:ffff:ffff:ffff","2403:300:a43::"},
        {"2403:300:a51::","2403:300:a51:ffff:ffff:ffff:ffff:ffff","2403:300:a50:ffff:ffff:ffff:ffff:ffff","2403:300:a52::"},
        {"2a01:b740:a42::","2a01:b740:a42:ffff:ffff:ffff:ffff:ffff","2a01:b740:a41:ffff:ffff:ffff:ffff:ffff","2a01:b740:a43::"}
    };
    for(size_t i=0;i<sizeof(v6)/sizeof(*v6);++i)
        for(unsigned j=0;j<4;++j)address_case(v6[i][j],AF_INET6,j<2);
    address_case("2A01:B740:0A42:0000:0000:0000:0000:1234",AF_INET6,true);
    address_case("::ffff:17.249.1.2",AF_INET6,true);
    address_case("::ffff:17.57.148.0",AF_INET6,false);
    address_case("::17.249.1.2",AF_INET6,false); /* Not IPv4-mapped. */
    address_case("64:ff9b::11f9:102",AF_INET6,false); /* No inferred NAT64 ranges. */
    address_case("::1",AF_INET6,false);
    assert(!apr_host_target("17.249.1.2:443"));
    assert(!apr_host_target("17.249.1.999"));
    assert(!apr_host_target("[2620:149:a44::1]"));
    assert(!apr_host_target("2620:149:a44::1%en0"));

    char name[300];memset(name,'a',63);strcpy(name+63,".push.apple.com");
    assert(apr_host_target(name));
    memset(name,'a',64);strcpy(name+64,".push.apple.com");assert(!apr_host_target(name));
    size_t at=0;
    const unsigned labels[]={63,63,63,46};
    for(unsigned i=0;i<4;++i) {memset(name+at,'a',labels[i]);at+=labels[i];name[at++]='.';}
    strcpy(name+at,"push.apple.com");assert(strlen(name)==253 && apr_host_target(name));
    strcat(name,".");assert(strlen(name)==254 && apr_host_target(name));
    strcat(name,".");assert(!apr_host_target(name));
    memset(name,'a',sizeof(name));name[sizeof(name)-1]=0;assert(!apr_host_target(name));
    assert(apr_index_name("utun12","utun") && apr_index_name("pdp_ip0","pdp_ip"));
    assert(!apr_index_name("utun","utun") && !apr_index_name("utunx","utun"));
    puts("PASS: all 13 rules, domain semantics and lengths, IPv4/IPv6 CIDR boundaries, mapped IPv4 and literal parsing");
}
