#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/Diagnostics.h"
#include "../src/TunnelSelector.h"
#include "../src/BindingStatus.h"
static bool enabled=true,allocation_fails,changed;
static uint64_t events;
static unsigned bind_status,bind_index,selected,calls,expected_action=1;
static int bind_error,syscall_result;
static APRConstraints bind_constraints;
static size_t convert_at[4];static unsigned conversions,queries,query_mode;
static enum apr_tunnel_choice choice=APR_TUN_UNIQUE;
void apr_diag_event(enum apr_event e) {if(e<64)events|=UINT64_C(1)<<e;errno=EIO;}
void apr_diag_necp_reject(enum apr_necp_reject r,unsigned t,uint32_t n) {(void)r;(void)t;(void)n;errno=EIO;}
uint32_t apr_diag_binding(uint32_t status,uint32_t index,int error,const APRConstraints *constraints) {
    assert(constraints);bind_constraints=*constraints;
    bind_status=status&255;bind_index=index;bind_error=error;return 1;
}
void apr_diag_binding_result(uint32_t g,uint32_t f,uint32_t p,uint32_t i) {(void)g;(void)f;(void)p;(void)i;}
bool apr_can_modify(void) {errno=EIO;return enabled;}
enum apr_tunnel_choice apr_tunnel_select(unsigned family,APRTunnel *out,int *error) {
    assert(family<=3);++selected;*out=(APRTunnel){.name="utun7",.index=12,.families=3,.count=1};
    *error=choice==APR_TUN_UNAVAILABLE?EPERM:0;
    if(changed && selected==2)out->index=13;
    return choice;
}
static void *allocate(size_t n) {if(allocation_fails){errno=ENOMEM;return NULL;}return malloc(n);}
#define malloc allocate
#include "../src/NECPHooks.c"
#undef malloc
static uint8_t original[65536],client[16];
static uint8_t *input;
static size_t input_size;
static bool expect_change;
static int kernel_call(int fd,uint32_t action,uint8_t *id,size_t id_size,uint8_t *b,size_t n) {
    if(action==9) {
        assert(fd==7 && id_size==4 && n==256 && errno==0);++queries;
        uint32_t index;memcpy(&index,id,4);assert(index==12 || index==5);
        if(query_mode==2) {errno=EPERM;return -1;}
        memset(b,0,n);memcpy(b,index==12?"utun7":"pdp_ip0",index==12?6:8);
        memcpy(b+24,&index,4);uint32_t type=index==12?0:(query_mode==1?7:5),next=index==12?5:0;
        memcpy(b+32,&type,4);memcpy(b+36,&next,4);return 0;
    }
    assert(fd==7 && action==expected_action && id==client && id_size==16 && errno==EDOM);
    ++calls;
    for(size_t i=0;i<input_size;++i) {
        bool converted=false;
        for(unsigned j=0;j<conversions;++j)if(i==convert_at[j]) {assert(original[i]==113);converted=true;}
        assert(b[i]==(converted?123:original[i]));
    }
    if(expect_change) {
        /* Darwin 20 BOUND_INTERFACE is one-byte type 9, uint32 length 6,
           then the interface name including NUL. This is an independent wire fixture. */
        const uint8_t tail[]={9,6,0,0,0,'u','t','u','n','7',0};
        assert(b!=input && n==input_size+sizeof(tail));assert(!memcmp(b+input_size,tail,sizeof(tail)));
    } else assert(b==input && n==input_size);
    id[0]=99;errno=syscall_result?EPERM:ERANGE;return syscall_result;
}
static size_t tlv(uint8_t *b,size_t at,uint8_t type,const void *p,uint32_t n) {
    b[at]=type;memcpy(b+at+1,&n,4);if(n)memcpy(b+at+5,p,n);return at+5+n;
}
static size_t fixture(uint8_t *b,const char *host,unsigned port,unsigned family) {
    uint8_t endpoint[28]={0},tcp=6;uint32_t uid=123;
    endpoint[0]=family==30?28:16;endpoint[1]=family;endpoint[2]=port>>8;endpoint[3]=port&255;
    size_t n=host?tlv(b,0,3,host,(uint32_t)strlen(host)+1):0;
    n=tlv(b,n,201,endpoint,28);n=tlv(b,n,11,&tcp,1);return tlv(b,n,7,&uid,4);
}
/* Independent Darwin wire layout: legacy prefix byte, then sockaddr union. */
static size_t ip_fixture(uint8_t *b,const char *host,unsigned port,const char *ip,bool legacy) {
    uint8_t endpoint[29]={0},tcp=6;uint8_t *a=endpoint+(legacy?1:0);
    if(inet_pton(AF_INET,ip,a+4)==1) {a[0]=16;a[1]=2;endpoint[0]=legacy?32:16;}
    else {assert(inet_pton(AF_INET6,ip,a+8)==1);a[0]=28;a[1]=30;endpoint[0]=legacy?128:28;}
    a[2]=port>>8;a[3]=port&255;
    size_t n=host?tlv(b,0,3,host,(uint32_t)strlen(host)+1):0;
    n=tlv(b,n,legacy?13:201,endpoint,legacy?29:28);
    return tlv(b,n,11,&tcp,1);
}
static void run(uint8_t *b,size_t n,bool modify,unsigned status) {
    assert(n<=sizeof(original));memcpy(original,b,n);input=b;input_size=n;expect_change=modify;
    events=0;calls=selected=queries=0;bind_status=bind_index=bind_error=0;bind_constraints=(APRConstraints){0};errno=EDOM;
    assert(apr_necp(7,expected_action,client,16,b,n)==syscall_result);
    assert(errno==(syscall_result?EPERM:ERANGE) && calls==1 && client[0]==99);
    assert(!memcmp(original,b,n) && bind_status==status);
    assert((bind_constraints.edit&255)==conversions);
    if(modify)assert((bind_constraints.edit&APR_EDIT_SUBMITTED) &&
        !!(bind_constraints.edit&APR_EDIT_ACCEPTED)==!syscall_result);
    else assert(!bind_constraints.edit);
    conversions=0;
}
int main(void) {
    apr_original_necp=kernel_call;uint8_t b[65536];size_t n;
    const char *hosts[]={"courier.push.apple.com","12-courier3.push.apple.com","apac-courier-v2.push.apple.com","12-COURIER4.PUSH.APPLE.COM.","12-courier.sandbox.push.apple.com"};
    for(unsigned i=0;i<sizeof(hosts)/sizeof(*hosts);++i)for(unsigned family=2;family<=30;family+=28) {
        n=fixture(b,hosts[i],443,family);run(b,n,true,APR_BIND_ACCEPTED);
        assert(selected==2 && bind_index==12 && (events&(UINT64_C(1)<<APR_NECP_CHANGED)));
    }
    n=fixture(b,"17.0.0.1",5223,2);run(b,n,false,APR_BIND_NONE);
    n=fixture(b,"courier.push.apple.com",0,2);run(b,n,true,APR_BIND_ACCEPTED);
    const char *other[]={"x.identity.apple.com","example.net","evilpush.apple.com","courier.push.apple.com.example.net","12-courier3..push.apple.com"};
    for(unsigned i=0;i<sizeof(other)/sizeof(*other);++i) {
        n=fixture(b,other[i],443,2);run(b,n,false,APR_BIND_NONE);assert(!selected);
    }
    const char *domains[]={"identity.apple.com","init.push.apple.com","push.apple.com",
        "any.push.apple.com","akadns.net","foo.akadns.net","prefixapple.com.edgekey.netextra.example"};
    const unsigned ports[]={0,1,80,443,5223,8443,65535};
    for(unsigned i=0;i<sizeof(domains)/sizeof(*domains);++i)
        for(unsigned j=0;j<sizeof(ports)/sizeof(*ports);++j) {
            n=fixture(b,domains[i],ports[j],2);run(b,n,true,APR_BIND_ACCEPTED);
            assert(events&(UINT64_C(1)<<APR_NECP_MATCHED));
            enabled=false;run(b,n,false,APR_BIND_NATIVE);assert(!selected && !queries);enabled=true;
        }
    n=fixture(b,NULL,5223,2);run(b,n,false,APR_BIND_NONE);assert(!selected);
    n=fixture(b,"example.net",5223,2);run(b,n,false,APR_BIND_NONE);assert(!selected);
    const char *addresses[]={"17.249.12.34","17.252.255.255","17.57.147.255",
        "17.188.191.255","17.188.21.255","2620:149:a44::123",
        "2403:300:a42::abcd","2403:300:a51::4321","2a01:b740:a42::ffff","::ffff:17.249.1.2"};
    for(unsigned i=0;i<sizeof(addresses)/sizeof(*addresses);++i)
        for(unsigned legacy=0;legacy<2;++legacy) {
            n=ip_fixture(b,NULL,8443,addresses[i],legacy);run(b,n,true,APR_BIND_ACCEPTED);
            n=ip_fixture(b,"unlisted.example.net",12345,addresses[i],legacy);run(b,n,true,APR_BIND_ACCEPTED);
            enabled=false;run(b,n,false,APR_BIND_NATIVE);assert(!selected && !queries);enabled=true;
        }
    /* Domain and address criteria are OR: neither needs the other's approval. */
    n=ip_fixture(b,"identity.apple.com",80,"192.0.2.12",false);run(b,n,true,APR_BIND_ACCEPTED);
    n=ip_fixture(b,"unlisted.example.net",5223,"17.188.22.0",false);run(b,n,false,APR_BIND_NONE);
    n=ip_fixture(b,NULL,5223,"2403:300:a43::1",true);run(b,n,false,APR_BIND_NONE);
    /* Address-based matches keep non-TCP/listener/inbound guards and malformed
       or conflicting endpoint metadata cannot trigger a changed ADD. */
    n=ip_fixture(b,NULL,80,addresses[0],false);b[n-1]=17;run(b,n,false,APR_BIND_NONE);
    n=ip_fixture(b,NULL,80,addresses[0],false);uint8_t udp=17;n=tlv(b,n,221,&udp,1);run(b,n,false,APR_BIND_NONE);
    const uint32_t no_outgoing[]={8,0x4000};
    for(unsigned i=0;i<2;++i) {n=ip_fixture(b,NULL,80,addresses[0],false);n=tlv(b,n,250,&no_outgoing[i],4);run(b,n,false,APR_BIND_NONE);}
    uint8_t duplicate[29]={32,16,2,0,80,17,249,12,34};
    n=ip_fixture(b,NULL,80,addresses[0],false);n=tlv(b,n,13,duplicate,29);run(b,n,true,APR_BIND_ACCEPTED);
    duplicate[8]=35;n=ip_fixture(b,NULL,80,addresses[0],false);n=tlv(b,n,13,duplicate,29);
    run(b,n,false,APR_BIND_NONE);assert(events&(UINT64_C(1)<<APR_NECP_INVALID));
    n=ip_fixture(b,NULL,80,addresses[0],false);n=tlv(b,n,13,duplicate,28);
    run(b,n,false,APR_BIND_NONE);assert(events&(UINT64_C(1)<<APR_NECP_INVALID));
    n=ip_fixture(b,NULL,80,addresses[0],false);b[5]=15;
    run(b,n,false,APR_BIND_NONE);assert(events&(UINT64_C(1)<<APR_NECP_INVALID));
    uint8_t tcp=6;uint16_t tcp16=6;
    n=fixture(b,hosts[0],443,2);n=tlv(b,n,11,&tcp16,2);run(b,n,true,APR_BIND_ACCEPTED);
    uint8_t legacy[29]={32,16,2,0x14,0x67,17,249,12,34};n=tlv(b,0,13,legacy,29);n=tlv(b,n,11,&tcp,1);run(b,n,true,APR_BIND_ACCEPTED);
    /* Parent UUID and resolver tag are an independent Darwin 20 wire fixture.
       The old presence-only guard rejected this valid metadata-only request. */
    uint8_t parent[16],tag[32];memset(parent,0xa5,sizeof(parent));memset(tag,0x5a,sizeof(tag));
    n=fixture(b,hosts[0],443,2);n=tlv(b,n,150,parent,16);n=tlv(b,n,203,tag,32);
    run(b,n,true,APR_BIND_ACCEPTED);
    assert(bind_constraints.seen==APR_C_PARENT && !bind_constraints.restricted &&
        !bind_constraints.inert && !bind_constraints.unsupported && !bind_constraints.first);
    enabled=false;run(b,n,false,APR_BIND_NATIVE);assert(!selected && bind_constraints.seen==APR_C_PARENT);enabled=true;
    /* Every guarded constraint has a declared-width zero and nonzero fixture.
       Duplicate inert/empty values cannot clear an earlier blocker, in either order. */
    const unsigned types[]={9,100,101,102,103,111,112,113};
    const unsigned widths[]={8,8,1,16,64,1,16,64};
    for(unsigned i=0;i<7;++i) {
        if(types[i]==101)continue; /* Full type-set fixtures below exercise exclusions. */
        uint8_t zero[65]={0},nonzero[65]={5};unsigned bit=1U<<i;
        if(types[i]==9 || types[i]==100)memcpy(nonzero,"pdp_ip0",8);
        n=fixture(b,hosts[0],443,2);n=tlv(b,n,types[i],zero,widths[i]);
        run(b,n,true,APR_BIND_ACCEPTED);
        assert(bind_constraints.seen==bit && bind_constraints.inert==bit &&
            !bind_constraints.restricted && !bind_constraints.unsupported && !bind_constraints.first);
        n=tlv(b,n,types[i],nonzero,widths[i]);
        run(b,n,false,APR_BIND_CONSTRAINT);assert(!selected);
        assert(bind_constraints.restricted==bit && bind_constraints.inert==bit && !bind_constraints.unsupported);
        assert((bind_constraints.first&255)==types[i] && ((bind_constraints.first>>8)&65535)==widths[i]);
        assert((bind_constraints.first>>24)==((types[i]==101 || types[i]==111)?5U:0U));
        n=fixture(b,hosts[0],443,2);n=tlv(b,n,types[i],nonzero,widths[i]);
        n=tlv(b,n,types[i],zero,widths[i]);n=tlv(b,n,types[i],NULL,0);n=tlv(b,n,150,parent,16);
        run(b,n,false,APR_BIND_CONSTRAINT);assert(!selected);
        assert(bind_constraints.seen==(bit|APR_C_PARENT) && bind_constraints.restricted==bit && bind_constraints.inert==bit);
        enabled=false;run(b,n,false,APR_BIND_NATIVE);assert(!selected && bind_constraints.restricted==bit);enabled=true;
        /* Familiar type with unsupported length: conservatively untouched,
           even if all zero and followed by an otherwise valid inert value. */
        unsigned unsupported_width=i<2?25:widths[i]+1;
        n=fixture(b,hosts[0],443,2);n=tlv(b,n,types[i],zero,unsupported_width);
        n=tlv(b,n,types[i],zero,widths[i]);run(b,n,false,APR_BIND_CONSTRAINT);
        assert(!selected && bind_constraints.unsupported==bit && !bind_constraints.restricted && bind_constraints.inert==bit);
        assert((bind_constraints.first&255)==types[i] && ((bind_constraints.first>>8)&65535)==unsupported_width);
        if(widths[i]>1 && i>=2) {
            n=fixture(b,hosts[0],443,2);n=tlv(b,n,types[i],zero,widths[i]-1);run(b,n,false,APR_BIND_CONSTRAINT);
            assert(bind_constraints.unsupported==bit && !selected);
        }
    }
    /* Empty TLVs are ignored by Darwin; valid parent metadata may coexist. */
    n=fixture(b,hosts[0],443,2);
    for(unsigned i=0;i<8;++i)n=tlv(b,n,types[i],NULL,0);
    n=tlv(b,n,150,NULL,0);n=tlv(b,n,150,parent,16);run(b,n,true,APR_BIND_ACCEPTED);
    assert(bind_constraints.seen==511 && bind_constraints.inert==511 && !bind_constraints.first);
    /* Parent widths must be exact. A bad parent is not mistaken for metadata. */
    n=fixture(b,hosts[0],443,2);n=tlv(b,n,150,parent,15);n=tlv(b,n,150,parent,16);
    run(b,n,false,APR_BIND_CONSTRAINT);
    assert(bind_constraints.unsupported==APR_C_PARENT && !bind_constraints.restricted && bind_constraints.first==(150U|(15U<<8)));
    /* All fields remain represented, with first blocker stable in wire order. */
    n=fixture(b,hosts[0],443,2);uint8_t iftype=5;n=tlv(b,n,111,&iftype,1);
    n=tlv(b,n,112,parent,16);n=tlv(b,n,150,parent,15);run(b,n,false,APR_BIND_CONSTRAINT);
    assert(bind_constraints.restricted==(APR_C_REQUIRE_TYPE|APR_C_REQUIRE_AGENT) && bind_constraints.unsupported==APR_C_PARENT);
    assert(bind_constraints.first==(111U|(1U<<8)|(5U<<24)));
    /* Device-shaped input: Companion Link prohibition + required agent type +
       parent/resolver metadata. Only the exact type byte at this known offset
       may change; all value bytes and unrelated fields must remain intact. */
    uint8_t agent[64]={0},companion=7;
    memcpy(agent,"Cellular",9);memcpy(agent+32,"Internet",9);
    n=fixture(b,hosts[0],443,2);n=tlv(b,n,101,&companion,1);
    size_t agent_at=n;n=tlv(b,n,113,agent,64);n=tlv(b,n,150,parent,16);n=tlv(b,n,203,tag,32);
    convert_at[0]=agent_at;conversions=1;run(b,n,true,APR_BIND_ACCEPTED);
    assert(queries==2 && !bind_constraints.blocked && (bind_constraints.agent_info&APR_AGENT_NAMES));
    assert((bind_constraints.agent_info&255)==1 && !memcmp(bind_constraints.agent,agent,64));
    assert((bind_constraints.check&255)==APR_IF_ALLOWED && bind_constraints.check_index==5);
    enabled=false;run(b,n,false,APR_BIND_NATIVE);assert(!queries && !selected && !bind_constraints.check);enabled=true;
    query_mode=1;run(b,n,false,APR_BIND_INTERFACE_CHECK);
    assert(queries==2 && (bind_constraints.check&255)==APR_IF_EXCLUDED && bind_constraints.check_index==5);
    query_mode=2;run(b,n,false,APR_BIND_INTERFACE_CHECK);
    assert(queries==1 && bind_error==EPERM && (bind_constraints.check&255)==APR_IF_QUERY_FAILED);query_mode=0;
    choice=APR_TUN_NONE;run(b,n,false,APR_BIND_NO_TUNNEL);assert(!queries);choice=APR_TUN_UNIQUE;
    changed=true;run(b,n,false,APR_BIND_CHANGED);assert(!queries);changed=false;
    syscall_result=-1;convert_at[0]=agent_at;conversions=1;run(b,n,true,APR_BIND_KERNEL);
    assert(queries==2 && bind_error==EPERM && calls==1);syscall_result=0;
    /* A prohibited cellular delegate, a UUID requirement, or an existing
       preferred-agent-type list still prevents this rewrite. */
    uint8_t cell=5;size_t base_n=n;n=tlv(b,n,101,&cell,1);run(b,n,false,APR_BIND_INTERFACE_CHECK);
    assert(queries==2 && selected==2 && (bind_constraints.check&255)==APR_IF_EXCLUDED);
    n=tlv(b,base_n,112,parent,16);run(b,n,false,APR_BIND_CONSTRAINT);assert(!queries && !selected);
    n=tlv(b,base_n,123,agent,64);run(b,n,false,APR_BIND_CONSTRAINT);
    assert(!queries && (bind_constraints.agent_info&APR_AGENT_EXISTING_PREFERENCE));
    n=fixture(b,"unmatched.example.net",443,2);n=tlv(b,n,101,&companion,1);n=tlv(b,n,113,agent,64);
    run(b,n,false,APR_BIND_NONE);assert(!queries && !selected);
    n=fixture(b,hosts[0],443,2);n=tlv(b,n,101,&companion,1);run(b,n,true,APR_BIND_ACCEPTED);
    assert(queries==2 && !bind_constraints.blocked);
    /* The confirmed device exclusions are 4 and 7. Also exercise other and
       duplicate values: every original TLV byte must remain in the copy. */
    n=fixture(b,hosts[0],443,2);
    const uint8_t multiple[]={7,4,6,0,7,255};
    for(unsigned i=0;i<sizeof(multiple);++i)n=tlv(b,n,101,multiple+i,1);
    agent_at=n;n=tlv(b,n,113,agent,64);convert_at[0]=agent_at;conversions=1;
    run(b,n,true,APR_BIND_ACCEPTED);
    assert(queries==2 && bind_constraints.prohibited_types[0]==((1U<<7)|(1U<<4)|(1U<<6)|1U));
    assert(bind_constraints.prohibited_types[7]==(UINT32_C(1)<<31));
    for(unsigned i=1;i<7;++i)assert(!bind_constraints.prohibited_types[i]);
    enabled=false;run(b,n,false,APR_BIND_NATIVE);assert(!queries && !selected);enabled=true;
    n=tlv(b,n,101,&cell,1);run(b,n,false,APR_BIND_INTERFACE_CHECK);
    assert(queries==2 && (bind_constraints.check&255)==APR_IF_EXCLUDED);
    /* Even a restriction after a zero / beyond the kernel's four slots must
       not be silently erased by the tweak's conservative union. */
    assert(bind_constraints.prohibited_types[0]&(1U<<5));
    uint8_t zero=0;
    n=fixture(b,hosts[0],443,2);n=tlv(b,n,101,&zero,1);run(b,n,true,APR_BIND_ACCEPTED);
    assert(!queries && bind_constraints.prohibited_types[0]==1U && !bind_constraints.restricted);
    n=tlv(b,n,101,&cell,1);n=tlv(b,n,101,&zero,1);run(b,n,false,APR_BIND_INTERFACE_CHECK);
    assert(queries==2 && bind_constraints.prohibited_types[0]==((1U<<5)|1U));
    uint8_t wrong_width[2]={7,0};n=fixture(b,hosts[0],443,2);
    n=tlv(b,n,101,wrong_width,2);n=tlv(b,n,101,&companion,1);
    run(b,n,false,APR_BIND_CONSTRAINT);
    assert(!queries && !selected && (bind_constraints.unsupported&APR_C_PROHIBIT_TYPE));
    /* Different, wildcard, or mixed requirements must remain native in both
       wire orders; a later matching/nil value cannot erase the blocker. */
    for(unsigned other=0;other<4;++other)for(unsigned order=0;order<2;++order) {
        uint8_t unrelated[64]={0};
        if(other==0) {memcpy(unrelated,"example.system",15);memcpy(unrelated+32,"transport",10);}
        if(other==1)memcpy(unrelated,"Cellular",9);
        if(other==2)memcpy(unrelated+32,"Internet",9);
        if(other==3) {memcpy(unrelated,"cellular",9);memcpy(unrelated+32,"Internet",9);}
        n=fixture(b,hosts[0],443,2);n=tlv(b,n,101,&companion,1);
        n=tlv(b,n,113,order?agent:unrelated,64);n=tlv(b,n,113,order?unrelated:agent,64);
        uint8_t nil[64]={0};n=tlv(b,n,113,nil,64);
        run(b,n,false,APR_BIND_CONSTRAINT);
        assert(!queries && !selected && (bind_constraints.agent_info&APR_AGENT_OTHER));
        assert((bind_constraints.agent_info&APR_AGENT_MULTIPLE) && (bind_constraints.blocked&APR_C_REQUIRE_AGENT_TYPE));
    }
    /* Only the exact Cellular / Internet pair may use all four kernel slots. */
    n=fixture(b,hosts[0],443,2);
    for(unsigned i=0;i<4;++i) {convert_at[i]=n;n=tlv(b,n,113,agent,64);}
    conversions=4;run(b,n,true,APR_BIND_ACCEPTED);
    assert(!queries && !(bind_constraints.agent_info&APR_AGENT_MULTIPLE) && (bind_constraints.agent_info&255)==4);
    n=tlv(b,n,113,agent,64);run(b,n,false,APR_BIND_CONSTRAINT);
    assert(!queries && (bind_constraints.agent_info&APR_AGENT_TOO_MANY));
    memset(agent,0,32);n=fixture(b,hosts[0],443,2);convert_at[0]=n;n=tlv(b,n,113,agent,64);
    run(b,n,false,APR_BIND_CONSTRAINT);assert(!queries && (bind_constraints.agent_info&APR_AGENT_OTHER));
    memset(agent,0,64);n=fixture(b,hosts[0],443,2);n=tlv(b,n,113,agent,64);
    run(b,n,true,APR_BIND_ACCEPTED);assert(!(bind_constraints.agent_info&APR_AGENT_NAMES) && !bind_constraints.blocked);
    /* Unreadable/noncanonical names and widths never reach a modified ADD.
       They publish flags, never raw control/nonterminated bytes. */
    for(unsigned bad=0;bad<5;++bad) {
        memset(agent,0,64);memcpy(agent,"example",8);memcpy(agent+32,"transport",10);
        unsigned width=64;
        if(bad==0)agent[1]=1;
        if(bad==1)memset(agent,'X',32);
        if(bad==2)agent[31]='X';
        if(bad==3)agent[32]=0xff;
        if(bad==4)width=63;
        n=fixture(b,hosts[0],443,2);n=tlv(b,n,113,agent,width);run(b,n,false,APR_BIND_CONSTRAINT);
        assert(!queries && !selected && (bind_constraints.unsupported&APR_C_REQUIRE_AGENT_TYPE));
        assert(!(bind_constraints.agent_info&APR_AGENT_NAMES));
        for(unsigned i=0;i<64;++i)assert(!bind_constraints.agent[i]);
    }
    n=fixture(b,hosts[0],443,2);n=tlv(b,n,9,"pdp_ip0",8);run(b,n,false,APR_BIND_CONSTRAINT);
    n=fixture(b,hosts[0],443,2);n=tlv(b,n,9,"utun7",6);run(b,n,false,APR_BIND_CONSTRAINT);
    uint8_t local[28]={16,2};n=fixture(b,hosts[0],443,2);n=tlv(b,n,200,local,28);run(b,n,true,APR_BIND_ACCEPTED);
    local[4]=10;n=fixture(b,hosts[0],443,2);n=tlv(b,n,200,local,28);run(b,n,false,APR_BIND_LOCAL);
    const uint32_t blocked[]={1,2,4,0x200,0x400,0x800,0x1000,0x8000};
    for(unsigned i=0;i<sizeof(blocked)/sizeof(*blocked);++i) {
        n=fixture(b,hosts[0],443,2);n=tlv(b,n,250,&blocked[i],4);run(b,n,false,APR_BIND_UNSUPPORTED_FLAGS);
    }
    uint32_t flag=0x80;n=fixture(b,hosts[0],443,2);n=tlv(b,n,250,&flag,4);run(b,n,true,APR_BIND_ACCEPTED);
    flag=8;n=fixture(b,hosts[0],443,2);n=tlv(b,n,250,&flag,4);run(b,n,false,APR_BIND_NONE);
    n=fixture(b,hosts[0],443,2);enabled=false;run(b,n,false,APR_BIND_NATIVE);assert(!selected);enabled=true;
    const enum apr_tunnel_choice choices[]={APR_TUN_NONE,APR_TUN_AMBIGUOUS,APR_TUN_FAMILY,APR_TUN_UNAVAILABLE,APR_TUN_CHANGED};
    const unsigned statuses[]={APR_BIND_NO_TUNNEL,APR_BIND_AMBIGUOUS,APR_BIND_FAMILY,APR_BIND_SELECTION,APR_BIND_CHANGED};
    for(unsigned i=0;i<5;++i) {choice=choices[i];run(b,n,false,statuses[i]);assert(selected==1);}
    choice=APR_TUN_UNIQUE;changed=true;run(b,n,false,APR_BIND_CHANGED);assert(selected==2);changed=false;
    allocation_fails=true;run(b,n,false,APR_BIND_ALLOCATION);allocation_fails=false;
    syscall_result=-1;run(b,n,true,APR_BIND_KERNEL);assert(bind_error==EPERM);syscall_result=0;
    expected_action=4;run(b,n,false,APR_BIND_NONE);assert(!selected);expected_action=1;
    n=fixture(b,hosts[0],443,2);b[n++]=0xff;run(b,n,false,APR_BIND_NONE);assert(events&(UINT64_C(1)<<APR_NECP_INVALID));
    n=fixture(b,hosts[0],443,2);uint32_t huge=UINT32_MAX;memcpy(b+1,&huge,4);run(b,n,false,APR_BIND_NONE);
    n=fixture(b,hosts[0],443,2);uint8_t v6[28]={28,30,1,187};
    n=tlv(b,n,201,v6,28);run(b,n,false,APR_BIND_NONE);
    assert(events&(UINT64_C(1)<<APR_NECP_INVALID));
    /* The kernel limit is 1024, not the observer's defensive 64 KiB bound. */
    n=fixture(b,hosts[0],443,2);uint32_t pad1024=1024-(uint32_t)n-5;
    b[n]=240;memcpy(b+n+1,&pad1024,4);memset(b+n+5,0,pad1024);
    run(b,1024,false,APR_BIND_CAPACITY);
    n=fixture(b,hosts[0],443,2);memset(b+n+5,0,sizeof(b)-n-5);uint32_t padding=sizeof(b)-n-5;
    b[n]=240;memcpy(b+n+1,&padding,4);run(b,sizeof(b),false,APR_BIND_CAPACITY);
    puts("PASS: domain/IP rule matching, arbitrary ports, address conflicts, agent preference/tunnel copy, exact changed-byte offsets, complete preserved exclusions and parent/resolver data, checked delegates, native/failure passthrough, bounds and errno");
}
