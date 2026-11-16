#!/usr/bin/env python3
"""Stream the unchanged signed APK into a standard LZMA2 7z archive."""
import argparse,hashlib,json,subprocess,time,zipfile
from pathlib import Path
SOURCE_SHA256='a5269c95b04bff67532379d184b2d525947091cfa827764bfb88294971c7c77a'
APK_SHA256='96656cba9da615a4a8f103fc5ee2469c8fbd1a77d203561c251ad4c86840e0ae'
SEVENZIP_SHA256='a1860fdf0d6ec395e0e277e5222e9aa488747db4aa5c87d1ec879a0916ba0b2f'
APK_NAME='NuarDLC_News_v1.2_fix_v2.apk'

def digest(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--sevenzip',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    assert not a.output.exists() and a.source.resolve()!=a.output.resolve()
    assert digest(a.source)==SOURCE_SHA256 and digest(a.sevenzip)==SEVENZIP_SHA256
    options=['-t7z','-mx=1','-m0=LZMA2:d=1m:fb=5:mf=hc4:mc=1:a=0:lc=0:lp=0:pb=0','-mmt=2','-ms=off','-mtm=off','-mta=off','-mtc=off','-bsp0','-bb0','-y']
    command=[str(a.sevenzip),'a',str(a.output),'-si'+APK_NAME,*options]
    child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    h=hashlib.sha256();count=0;last=time.monotonic()
    try:
        with zipfile.ZipFile(a.source) as z:
            assert z.namelist()==[APK_NAME];size=z.getinfo(APK_NAME).file_size
            with z.open(APK_NAME) as f:
                while b:=f.read(4*1024*1024):
                    child.stdin.write(b);h.update(b);count+=len(b)
                    if time.monotonic()-last>20:
                        print(f'7z packaging: {count/size:.0%}',flush=True);last=time.monotonic()
        child.stdin.close();log=child.stdout.read().decode(errors='replace');assert child.wait()==0,log
        assert count==size and h.hexdigest()==APK_SHA256
    except BaseException:
        child.kill();child.wait();raise
    assert a.output.stat().st_size<2**31,'Archive exceeds the release file size limit'
    result={'format':'7z','compression':'LZMA2','dictionary_bytes':1024*1024,'solid':False,'archive_size':a.output.stat().st_size,'archive_sha256':digest(a.output),'apk_name':APK_NAME,'apk_size':count,'apk_sha256':h.hexdigest(),'apk_changed':False,'source_zip_sha256':SOURCE_SHA256,'sevenzip_binary_sha256':SEVENZIP_SHA256,'encoder_options':options,'android_mt_manager_tested':False}
    a.report.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2),flush=True)
if __name__=='__main__':main()
