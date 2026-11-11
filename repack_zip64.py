#!/usr/bin/env python3
"""Wrap the verified APK's existing Deflate stream in a full ZIP64 container."""
import argparse,hashlib,json,struct,zipfile
from pathlib import Path

SOURCE_ZIP_SHA256='2f4a1bb850e5189a5d1466d7fae00db5a33a6ce9d43be33cca088f71db882bdb'
APK_SHA256='1fdc769fc79852bb8ddfe768da5fb5009fd02e9d81085ad23087647667d65ce2'
def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def repack(source,output,report_path):
    assert len({p.resolve() for p in [source,output,report_path]})==3
    assert sha(source)==SOURCE_ZIP_SHA256
    with zipfile.ZipFile(source) as z:
        assert z.namelist()==['Zenin_Icon_Crack.apk']
        i=z.infolist()[0];assert i.compress_type==8 and not i.flag_bits&1
    name=i.filename.encode('utf-8');flags=(i.flag_bits&~8)|0x800
    year,month,day,hour,minute,second=i.date_time
    stamp=(hour<<11)|(minute<<5)|(second//2);date=((year-1980)<<9)|(month<<5)|day
    local_extra=struct.pack('<HHQQ',1,16,i.file_size,i.compress_size)
    with source.open('rb') as inp,output.open('wb') as out:
        inp.seek(i.header_offset);header=inp.read(30);n,x=struct.unpack_from('<HH',header,26);inp.seek(n+x,1)
        out.write(struct.pack('<4s5H3I2H',b'PK\x03\x04',45,flags,8,stamp,date,i.CRC,0xffffffff,0xffffffff,len(name),len(local_extra))+name+local_extra)
        remaining=i.compress_size
        while remaining:
            block=inp.read(min(16*1024*1024,remaining));assert block;out.write(block);remaining-=len(block)
        central_offset=out.tell()
        extra=struct.pack('<HHQQQ',1,24,i.file_size,i.compress_size,0)
        central=struct.pack('<4s6H3I5H2I',b'PK\x01\x02',(i.create_system<<8)|45,45,flags,8,stamp,date,i.CRC,0xffffffff,0xffffffff,len(name),len(extra),0,0,i.internal_attr,i.external_attr,0xffffffff)+name+extra
        out.write(central);end64_offset=out.tell()
        out.write(struct.pack('<4sQHHIIQQQQ',b'PK\x06\x06',44,45,45,0,0,1,1,len(central),central_offset))
        out.write(struct.pack('<4sIQI',b'PK\x06\x07',0,end64_offset,1))
        out.write(struct.pack('<4s4H2IH',b'PK\x05\x06',0,0,0xffff,0xffff,0xffffffff,0xffffffff,0))
    with zipfile.ZipFile(output) as z:
        i=z.infolist()[0];assert i.extract_version==45 and i.file_size>2**31
        digest=hashlib.sha256();crc=0;count=0
        import zlib
        with z.open(i) as f:
            while True:
                block=f.read(8*1024*1024)
                if not block:break
                digest.update(block);crc=zlib.crc32(block,crc);count+=len(block)
        assert digest.hexdigest()==APK_SHA256 and crc==i.CRC and count==i.file_size
    report={'source_zip_sha256':SOURCE_ZIP_SHA256,'zip_sha256':sha(output),'zip_size':output.stat().st_size,
            'format':'ZIP64','required_zip_version':45,'apk_sha256':APK_SHA256,'apk_size':count,
            'apk_bytes_unchanged':True,'apk_crc_valid':True,'compressed_stream_copied_without_changes':True}
    report_path.write_text(json.dumps(report,indent=2)+'\n');return report
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    print(json.dumps(repack(a.source,a.output,a.report),indent=2))
