#!/usr/bin/env python3
"""Compile the actual doctor formatter against the successful device pattern."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'src/Diagnose.c').read_text()
formatter = source[source.index('struct transport_context'):source.index('static int report_pid')]
harness = r'''
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <net/if.h>
#include "Diagnostics.h"
#include "BindingStatus.h"
#include "TransportSnapshot.h"
#define NOTIFY_STATUS_OK 0
static uint32_t sample[APR_TRANSPORT_SLOTS];
static uint32_t read_state(pid_t pid, uint64_t incarnation, const char *name, uint64_t *value) {
    (void)pid; (void)incarnation;
    for (unsigned i=0;i<APR_TRANSPORT_SLOTS;++i) {
        if (!strcmp(name,apr_transport_field_name(i))) {
            *value=APR_DIAG_MAGIC|sample[i]; return 0;
        }
    }
    return 1;
}
''' + formatter + r'''
static void set_field(const char *name,uint32_t value) {
    for (unsigned i=0;i<APR_TRANSPORT_SLOTS;++i)
        if (!strcmp(name,apr_transport_field_name(i))) { sample[i]=value; return; }
    abort();
}
int main(int argc,char **argv) {
    if(argc>1) {
        if(!strcmp(argv[1],"disabled"))set_field("ret-status",APR_RET_DISABLED);
        else if(!strcmp(argv[1],"suspended")) {
            set_field("ret-status",APR_RET_UNKNOWN);set_field("ret-pending",2);
        } else if(!strcmp(argv[1],"recovering")) {
            set_field("ret-status",APR_RET_RECOVERING);set_field("ret-awaiting",1);
        } else {set_field("ret-status",APR_RET_UNAVAILABLE);set_field("ret-error",5);}
        report_retirement(sample);return 0;
    }
    set_field("transport-seq",2);
    set_field("nw-created",APR_CREATE_SEEN|APR_CREATE_OK);
    set_field("nw-start",APR_START_SEEN);
    set_field("nw-cancel-normal",4);
    set_field("nw-cancel-immediate",3);
    set_field("nw-cancel-app-force",2);
    set_field("nw-cancel-action",APR_CANCEL_IMMEDIATE);
    set_field("nw-state",APR_STATE_REGISTERED|APR_STATE_CALLBACK|3|(1U<<(APR_STATE_HISTORY_SHIFT+3)));
    set_field("nw-handler-id",1);
    set_field("nw-report",APR_REPORT_REQUESTED|APR_REPORT_RETURNED|APR_REPORT_AVAILABLE|APR_REPORT_CONFIGURED|APR_REPORT_USED);
    set_field("necp-binding-id",3);
    set_field("necp-binding-index",19);
    set_field("necp-binding-status",APR_BIND_ACCEPTED|(1U<<8)|(3U<<16));
    set_field("necp-binding-result",APR_BIND_RESULT_READ|APR_BIND_RESULT_INTERFACE|APR_BIND_RESULT_POLICY|APR_BIND_RESULT_MATCH);
    set_field("necp-binding-policy",12);
    set_field("necp-binding-result-index",19);
    set_field("necp-constraints-seen",APR_C_PROHIBIT_TYPE|APR_C_REQUIRE_AGENT_TYPE|APR_C_PARENT);
    set_field("necp-constraints-restricted",APR_C_PROHIBIT_TYPE|APR_C_REQUIRE_AGENT_TYPE);
    set_field("necp-constraints-first",101U|(1U<<8)|(7U<<24));
    set_field("necp-agent-info",1|APR_AGENT_NAMES);
    set_field("necp-agent-edit",1|APR_EDIT_SUBMITTED|APR_EDIT_ACCEPTED);
    set_field("necp-interface-check",1|(2U<<8)|((1U<<0)|(1U<<5))<<16);
    set_field("necp-interface-check-index",4);
    set_field("necp-prohibited-types-0",(1U<<4)|(1U<<7));
    uint8_t agent[64]={0}; memcpy(agent,"Cellular",9); memcpy(agent+32,"Internet",9);
    for(unsigned i=0;i<16;++i) {
        char name[32]; uint32_t word; memcpy(&word,agent+4*i,4);
        snprintf(name,sizeof(name),"necp-agent-name-%u",i); set_field(name,word);
    }
    set_field("necp-client-flags",0x1000);
    set_field("conn-0-id",1);set_field("conn-0-handler",2);set_field("conn-0-role",APR_ROLE_COURIER);
    set_field("conn-0-state",3|(1U<<(APR_ROW_HISTORY_SHIFT+3)));
    set_field("conn-0-reads",4);set_field("conn-0-received",3);set_field("conn-0-bytes",1234);
    set_field("conn-0-path",APR_PATH_SEEN|APR_PATH_PRESENT|APR_PATH_CELL|1);
    set_field("conn-1-id",3);set_field("conn-1-handler",4);set_field("conn-1-role",APR_ROLE_COURIER);
    set_field("conn-1-state",3|(1U<<(APR_ROW_HISTORY_SHIFT+3)));
    set_field("conn-2-id",4);set_field("conn-2-handler",8);set_field("conn-2-role",APR_ROLE_COURIER);
    set_field("conn-2-state",4|(1U<<(APR_ROW_HISTORY_SHIFT+4)));
    set_field("conn-2-error-info",(APR_ERROR_RECEIVE<<8)|1);set_field("conn-2-error-code",50);
    set_field("connection-overflow",2);
    set_field("ret-status",APR_RET_IDLE);set_field("ret-network",APR_RET_WIFI);
    set_field("ret-epoch",3);set_field("ret-held",2);set_field("ret-requests",1);
    set_field("ret-last-id",1);set_field("ret-reason",APR_RET_DEADLINE);set_field("ret-skipped",1);
    set_field("conn-0-retire-requests",1);
    report_transport(1,1,true);
}
'''
harness = '#include <stdlib.h>\n' + harness
with tempfile.TemporaryDirectory(prefix='apnsroute-doctor-test-') as directory:
    path = Path(directory)
    (path / 'doctor.c').write_text(harness)
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
        '-std=c11', '-Wall', '-Wextra', '-Werror', '-I' + str(root / 'src'),
        str(path / 'doctor.c'), '-o', str(path / 'doctor')], check=True)
    output = subprocess.run([str(path / 'doctor')], check=True, capture_output=True, text=True).stdout
    for expected in (
        'Latest matched NECP request #3: tunnel-binding ADD accepted',
        'Original client flags: 0x00001000 (guards unchanged)',
        'Handover retirement: watching; no older established connections',
        'Monitor network: Wi-Fi; generation=3',
        'Held connections=2/8; older established connections pending=0',
        'Endpoint retirement requests=1; last connection=#1',
        'Last retirement reason: three-second handover window elapsed',
        'Tracking attempts skipped (capacity/ID/handler unavailable): 1',
        'No handover restart of apsd. Native endpoint fallback/failure handles recovery',
        'These diagnostic rows own no references',
        '    Endpoint retirement requests=1\n',
        'Connection #1 (courier hint), handler #2: ready',
        'Connection #3 (courier hint), handler #4: ready',
        'Connection #4 (courier hint), handler #8: failed',
        'Received bytes=1234; complete callbacks=0; cancels: normal=0 force=0',
        'Last error: POSIX (1), code=50; from receive callback',
        'Path at last receive/cancel call: satisfied; Wi-Fi=no cellular=yes loopback=no',
        'Record attempts skipped (capacity/ID exhaustion): 2',
        'not a live-connection list or Surge row mapping',
        'Complete callbacks need not mean TCP EOF',
        '4 (Wi-Fi AWDL)', '7 (Companion Link)',
        'First readable domain: Cellular', 'First readable type: Internet',
        'Agent REQUIRE -> PREFER fields supplied: 1; ADD accepted: yes',
        'Observed functional types: 0 (unknown); 5 (cellular);',
        'Candidate/requested interface index: 19', 'Returned top-level interface index: 19',
        'Kernel result matches requested tunnel index: yes',
        'Matched cancellation calls since apsd start: normal=4; apsd force=2',
        'Normal cancels upgraded to immediate teardown: 3',
        'Last matched cancellation dispatch: immediate teardown requested by APNsRoute',
        'not unique connections or confirmed Surge closures',
        'Latest matched handler #1: ready', 'Last error: none observed for this handler',
        'Establishment report: proxy configured=yes; proxy used=yes',
    ):
        assert expected in output, expected
    for retired in ('proxy copy supplied', 'Proxy readback', 'noProxy', '6153', 'Parameters inspected'):
        assert retired not in output, retired
    for scenario,expected in (
        ('disabled','disabled; native lifetime'),
        ('suspended','suspended; physical path unknown or unsatisfied'),
        ('failure','Retirement error: 5'),
        ('recovering','endpoint request awaiting native readiness or closure'),
    ):
        result=subprocess.run([str(path/'doctor'),scenario],check=True,capture_output=True,text=True)
        assert expected in result.stdout
        if scenario=="recovering": assert "Awaiting native readiness/closure=1" in result.stdout
print('PASS: actual doctor renders request/results, independent rows and retirement states/counts without stale proxy diagnostics')
