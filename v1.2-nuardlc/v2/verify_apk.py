#!/usr/bin/env python3
"""Audit final signatures, original compressed spans, CRCs and visible app labels."""
import argparse,hashlib,json,struct,subprocess,zipfile
from pathlib import Path
from manifest_label import PAYLOAD,chunks,length8
from repack_preserve_layout import stream_hash,digest
SOURCE_CERT='a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc'

def labels(data):
    parts=list(chunks(data));pool=next(b for k,b in parts if k==1)
    count,styles,flags,start,_=struct.unpack_from('<5I',pool,8);names=[]
    for i in range(count):
        pos=start+struct.unpack_from('<I',pool,28+4*i)[0]
        if flags&256:
            _,pos=length8(pool,pos);n,pos=length8(pool,pos);names.append(pool[pos:pos+n].decode())
        else:
            n=struct.unpack_from('<H',pool,pos)[0];names.append(pool[pos+2:pos+2+2*n].decode('utf-16le'))
    result=[]
    for kind,part in parts:
        if kind!=0x102:continue
        tag=names[struct.unpack_from('<I',part,20)[0]]
        a,sz,n=struct.unpack_from('<HHH',part,24);assert sz==20;begin=16+a
        records=[part[begin+j*20:begin+(j+1)*20] for j in range(n)]
        main=any(names[struct.unpack_from('<I',r,4)[0]]=='name' and r[15]==3 and names[struct.unpack_from('<I',r,16)[0]]=='com.google.firebase.MessagingUnityPlayerActivity' for r in records)
        if tag=='application' or tag=='activity' and main:
            for r in records:
                if names[struct.unpack_from('<I',r,4)[0]]=='label':
                    assert r[15]==3;result.append(names[struct.unpack_from('<I',r,16)[0]])
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('apk',type=Path)
    p.add_argument('--streams',type=Path,required=True);p.add_argument('--native-report',type=Path,required=True)
    p.add_argument('--apksigner',required=True);p.add_argument('--zipalign',required=True);p.add_argument('--report',type=Path,required=True)
    a=p.parse_args();streams=json.loads(a.streams.read_text());native=json.loads(a.native_report.read_text())
    sign=subprocess.run([a.apksigner,'verify','--verbose','--print-certs',str(a.apk)],check=True,capture_output=True,text=True).stdout
    assert 'Verified using v2 scheme (APK Signature Scheme v2): true' in sign
    assert 'Verified using v3 scheme (APK Signature Scheme v3): true' in sign
    assert f'Signer #1 certificate SHA-256 digest: {SOURCE_CERT}' in sign
    subprocess.run([a.zipalign,'-c','-P','16','4',str(a.apk)],check=True,capture_output=True)
    with zipfile.ZipFile(a.apk) as z,a.apk.open('rb') as f:
        assert len(z.infolist())==len(streams)
        for i,s in zip(z.infolist(),streams):
            assert (i.filename,i.header_offset,i.compress_size,i.file_size,i.CRC)==(s['name'],s['offset'],s['compressed_size'],s['size'],s['crc'])
            f.seek(i.header_offset);h=f.read(30);n,x=struct.unpack_from('<HH',h,26);offset=i.header_offset+30+n+x
            assert offset==s['data_offset']
            assert stream_hash(f,offset,i.compress_size)==s['compressed_sha256'],i.filename
        assert z.testzip() is None
        assert labels(z.read('AndroidManifest.xml'))==['@NuarDLC_News','@NuarDLC_News']
        with z.open(PAYLOAD) as source:assert hashlib.file_digest(source,'sha256').hexdigest()==native['patched_sha256']
    report={'apk_size':a.apk.stat().st_size,'apk_sha256':digest(a.apk),'payload_sha256':native['patched_sha256'],
        'apk_signature_v2_v3_valid':True,'certificate_sha256':SOURCE_CERT,'same_certificate_as_original_source':True,
        'zipalign_16kb_check_passed':True,'all_apk_zip_crcs_valid':True,'all_local_record_and_data_offsets_match_original':True,
        'all_compressed_spans_preserved':True,'unchanged_compressed_streams_verified':len(streams)-2,
        'only_changed_entries':[s['name'] for s in streams if s['changed']],
        'application_and_main_activity_labels':['@NuarDLC_News','@NuarDLC_News'],'android_device_tested':False,
        'physical_vk_account_loading_tested':False}
    a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
if __name__=='__main__':main()
