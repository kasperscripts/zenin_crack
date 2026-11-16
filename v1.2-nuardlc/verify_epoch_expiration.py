#!/usr/bin/env python3
"""Exercise local login with real Unix epochs up to five years in the future."""
import argparse,datetime,hashlib,json
from pathlib import Path
from verify_startup import Image

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('payload',type=Path);p.add_argument('--report',type=Path,required=True)
    args=p.parse_args();image=Image(args.payload)
    epoch=int(datetime.datetime(2026,11,16,tzinfo=datetime.timezone.utc).timestamp());cases=[]
    for delta in [0,86401,7*86400,365*86400,5*365*86400]:
        image.reset();image.clock_seconds=epoch+delta;image.submit('@NuarDLC_News');image.call(0x16b138)
        state=image.snapshots[0]
        assert state['phase']==6 and state['ui_state']==4 and state['hooks_enabled']==1 and state['bootstrap_binding_ready']==1,state
        cases.append({'seconds_since_2026_11_16':delta,'login_and_original_hook_activation_passed':True})
    report={'payload_sha256':hashlib.sha256(args.payload.read_bytes()).hexdigest(),'key':'@NuarDLC_News','actual_arm64_functions_executed':True,'epoch_start_utc':'2026-11-16T00:00:00Z','cases':cases,'server_calls':0,'android_device_tested':False}
    args.report.write_text(json.dumps(report,indent=2)+'\n');print('PASS: original ARM64 login/hook paths at current epoch, +1 day, +1 week, +1 year and +5 years')
if __name__=='__main__':main()
