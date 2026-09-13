#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "../src/Diagnostics.h"
#include "../src/ConnectionStatus.h"
static uint32_t output[APR_CONNECTION_COUNT][APR_CONNECTION_FIELD_COUNT];
static unsigned published,overflows;
void apr_diag_connection(unsigned slot,const uint32_t v[APR_CONNECTION_FIELD_COUNT]) {
    assert(slot<APR_CONNECTION_COUNT);memcpy(output[slot],v,sizeof(output[slot]));++published;errno=EIO;
}
void apr_diag_connection_overflow(void) {++overflows;errno=EIO;}
#include "../src/Connections.c"
int main(void) {
    errno=EDOM;
    assert(!apr_connection_observe(0,APR_ROLE_COURIER,true));
    uint32_t a=apr_connection_observe(100,APR_ROLE_COURIER,true);
    uint32_t b=apr_connection_observe(200,APR_ROLE_INIT,true);
    assert(a==1 && b==2 && apr_connection_find(100)==a);
    assert(apr_connection_observe(100,APR_ROLE_COURIER,false)==a);
    apr_connection_handler(a,1);apr_connection_handler(b,2);
    assert(apr_connection_handler_id(a)==1 && apr_connection_handler_id(b)==2);
    assert(!apr_connection_handler_id(0) && !apr_connection_handler_id(99));
    apr_connection_state(a,1,3,0,0);apr_connection_state(b,2,1,1,50);
    assert((output[0][APR_R_STATE]&255)==3 && (output[1][APR_R_STATE]&255)==1);
    apr_connection_read(a,APR_PATH_SEEN|APR_PATH_PRESENT|APR_PATH_CELL|1);
    apr_connection_received(a,123,true,0,0);apr_connection_send(a);
    apr_connection_cancel(a,false,APR_PATH_SEEN|APR_PATH_LOOP);
    apr_connection_cancel(a,true,APR_PATH_SEEN|APR_PATH_LOOP);
    apr_connection_retire_requested(a);assert(output[0][APR_R_RETIRE_REQUESTS]==1 && !output[1][APR_R_RETIRE_REQUESTS]);
    assert(output[0][APR_R_READS]==1 && output[0][APR_R_RECEIVED]==1 && output[0][APR_R_BYTES]==123);
    assert(output[0][APR_R_COMPLETES]==1 && output[0][APR_R_SENDS]==1 && output[0][APR_R_CANCELS]==65537);
    assert(!output[1][APR_R_READS] && (int32_t)output[1][APR_R_ERROR_CODE]==50);
    apr_connection_handler(a,3);unsigned before=published;
    apr_connection_state(a,1,5,1,54);assert(published==before); /* replaced handler */
    apr_connection_state(a,3,4,3,-9807);
    apr_connection_received(a,0,false,1,54);
    assert(output[0][APR_R_ERROR_INFO]==((APR_ERROR_RECEIVE<<8)|1) && output[0][APR_R_ERROR_CODE]==54);
    uint32_t c=apr_connection_observe(300,APR_ROLE_COURIER,true);
    assert(c==3 && output[0][APR_R_ID]==a && output[2][APR_R_ID]==c); /* empty first */
    apr_connection_handler(a,0);
    assert(!apr_connection_handler_id(a));
    assert(output[0][APR_R_STATE]==APR_ROW_HANDLER_CLEARED);
    before=published;apr_connection_state(a,3,3,0,0);assert(published==before);
    uint32_t reused=apr_connection_observe(100,APR_ROLE_HOST,true);assert(reused==4);
    before=published;apr_connection_received(a,999,true,1,50);apr_connection_send(a);
    apr_connection_state(a,3,3,0,0);apr_connection_cancel(a,true,0);apr_connection_retire_requested(a);
    assert(published==before && output[0][APR_R_ID]==reused && !output[0][APR_R_RECEIVED]);
    /* Saturation and no wraparound, even for an unreasonably large content size. */
    apr_connection_received(reused,SIZE_MAX,true,0,0);apr_connection_received(reused,1,false,0,0);
    assert(output[0][APR_R_BYTES]==UINT32_MAX && output[0][APR_R_RECEIVED]==2);
    rows[0].value[APR_R_SENDS]=UINT32_MAX;apr_connection_send(reused);
    rows[0].value[APR_R_RETIRE_REQUESTS]=UINT32_MAX;apr_connection_retire_requested(reused);
    assert(output[0][APR_R_RETIRE_REQUESTS]==UINT32_MAX);
    rows[0].value[APR_R_CANCELS]=UINT32_MAX;apr_connection_cancel(reused,false,0);apr_connection_cancel(reused,true,0);
    assert(output[0][APR_R_SENDS]==UINT32_MAX && output[0][APR_R_CANCELS]==UINT32_MAX);
    for(unsigned i=3;i<APR_CONNECTION_COUNT;++i) assert(apr_connection_observe(400+i,APR_ROLE_ADDRESS,true));
    assert(!apr_connection_observe(999,APR_ROLE_COURIER,true) && overflows==1);
    apr_connection_handler(b,2);apr_connection_state(b,2,5,0,0);
    assert(apr_connection_observe(999,APR_ROLE_COURIER,true));assert(!apr_connection_find(200));
    next_id=UINT32_MAX;assert(!apr_connection_observe(100,APR_ROLE_COURIER,true) && overflows==2);
    assert(apr_connection_find(100)==reused); /* exhaustion leaves existing rows intact */
    assert(errno==EDOM);
    puts("PASS: independent connection rows, handler/address reuse, delayed callbacks, terminal reuse, capacity, saturation and errno");
}
