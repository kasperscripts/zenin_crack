#!/usr/bin/env python3
"""Rewrap the verified APK deflate stream in ordinary ZIP32 metadata."""
import argparse,hashlib,json,struct,zipfile
from pathlib import Path
SOURCE_SHA256='a5269c95b04bff67532379d184b2d525947091cfa827764bfb88294971c7c77a'
APK_SHA256='96656cba9da615a4a8f103fc5ee2469c8fbd1a77d203561c251ad4c86840e0ae'
APK_NAME='NuarDLC_News_v1.2_fix_v2.apk'

def digest(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    assert a.source.resolve()!=a.output.resolve() and not a.output.exists()
    assert digest(a.source)==SOURCE_SHA256
    with zipfile.ZipFile(a.source) as z:
        assert z.namelist()==[APK_NAME];i=z.getinfo(APK_NAME)
    assert i.compress_type==8 and i.flag_bits==0 and i.file_size<0xffffffff and i.compress_size<0xffffffff
    name=i.filename.encode('ascii');hour,minute,second=i.date_time[3:];year,month,day=i.date_time[:3]
    stamp=hour<<11|minute<<5|second//2;date=(year-1980)<<9|month<<5|day
    compressed_hash=hashlib.sha256()
    with a.source.open('rb') as source,a.output.open('xb') as out:
        source.seek(i.header_offset);h=source.read(30);assert h[:4]==b'PK\x03\x04';n,x=struct.unpack_from('<HH',h,26);source.seek(n+x,1)
        out.write(struct.pack('<4s5H3I2H',b'PK\x03\x04',20,0,8,stamp,date,i.CRC,i.compress_size,i.file_size,len(name),0)+name)
        remaining=i.compress_size
        while remaining:
            b=source.read(min(8*1024*1024,remaining));assert b;out.write(b);compressed_hash.update(b);remaining-=len(b)
        start=out.tell();assert start<0xffffffff
        central=struct.pack('<4s6H3I5H2I',b'PK\x01\x02',(i.create_system<<8)|20,20,0,8,stamp,date,i.CRC,i.compress_size,i.file_size,len(name),0,0,0,i.internal_attr,i.external_attr,0)+name
        out.write(central);out.write(struct.pack('<4s4H2IH',b'PK\x05\x06',0,0,1,1,len(central),start,0))
    with zipfile.ZipFile(a.output) as z:
        j=z.getinfo(APK_NAME);assert j.extra==b'' and j.extract_version==20 and j.create_version==20
        assert (j.CRC,j.file_size,j.compress_size)==(i.CRC,i.file_size,i.compress_size)
        with z.open(APK_NAME) as f:apk_hash=hashlib.file_digest(f,'sha256').hexdigest()
        assert apk_hash==APK_SHA256
    assert a.output.stat().st_size<2**31
    report={'format':'ZIP32','zip64_extensions':False,'source_zip_sha256':SOURCE_SHA256,'zip_size':a.output.stat().st_size,'zip_sha256':digest(a.output),'apk_name':APK_NAME,'apk_size':i.file_size,'apk_sha256':apk_hash,'apk_changed':False,'compressed_stream_sha256':compressed_hash.hexdigest(),'compressed_stream_copied_without_recompression':True,'full_extraction_sha256_and_crc_verified':True,'android_archiver_tested':False}
    a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
if __name__=='__main__':main()
