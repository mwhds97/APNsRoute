#ifndef APNSROUTE_TRANSPORT_SNAPSHOT_H
#define APNSROUTE_TRANSPORT_SNAPSHOT_H
#include "Diagnostics.h"
#include "ConnectionStatus.h"
static inline bool apr_transport_snapshot(bool (*read)(void *,const char *,uint64_t *),
                                          void *context,uint32_t values[APR_TRANSPORT_SLOTS]) {
    for(unsigned retry=0;retry<3;++retry) {
        uint64_t first=0,last=0;
        if(!read(context,apr_transport_field_name(APR_T_SEQ),&first) || (first&UINT64_C(0xffffffff00000000))!=APR_DIAG_MAGIC)
            return false;
        if(first&1) continue;
        for(unsigned i=1;i<APR_TRANSPORT_SLOTS;++i) {
            uint64_t value=0;
            if(!read(context,apr_transport_field_name(i),&value) || (value&UINT64_C(0xffffffff00000000))!=APR_DIAG_MAGIC)
                return false;
            values[i]=(uint32_t)value;
        }
        if(!read(context,apr_transport_field_name(APR_T_SEQ),&last)) return false;
        if(first==last) {values[0]=(uint32_t)first;return true;}
    }
    return false;
}
#endif
