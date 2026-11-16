#!/usr/bin/env python3
"""Replace two APK entries without moving any original local ZIP record."""
import argparse,hashlib,json,shutil,struct,zipfile,zlib
from pathlib import Path
from manifest_label import manifest,SOURCE_SHA256,PAYLOAD

def digest(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def fit_deflate(raw,capacity):
    for level,mem in [(9,8),(9,7),(8,8),(9,6),(7,8),(6,8)]:
        c=zlib.compressobj(level,zlib.DEFLATED,-15,mem)
        stream=c.compress(raw)+c.flush(zlib.Z_SYNC_FLUSH)
        gap=capacity-len(stream)
        choices=[k for k in range(1,5) if gap>=(10*k+7)//8 and (gap-(10*k+7)//8)%5==0]
        if not choices:continue
        k=choices[0];tail=(10*k+7)//8;empty=(gap-tail)//5
        bits=sum((3 if j==k-1 else 2)<<(10*j) for j in range(k))
        packed=stream+b'\x00\x00\x00\xff\xff'*empty+bits.to_bytes(tail,'little')
        assert len(packed)==capacity
        check=zlib.decompressobj(-15);assert check.decompress(packed)+check.flush()==raw
        assert check.eof and not check.unused_data and not check.unconsumed_tail
        return packed,{'level':level,'mem_level':mem,'legal_padding_bytes':gap}
    raise ValueError(f'Replacement does not fit original deflate span: {capacity}')

def stream_hash(f,offset,size):
    f.seek(offset);h=hashlib.sha256()
    while size:
        b=f.read(min(size,8*1024*1024));assert b;h.update(b);size-=len(b)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ['source','payload','output']:p.add_argument(n,type=Path)
    p.add_argument('--report',type=Path,required=True);p.add_argument('--streams',type=Path,required=True);a=p.parse_args()
    assert len({x.resolve() for x in [a.source,a.payload,a.output]})==3 and not a.output.exists()
    assert digest(a.source)==SOURCE_SHA256
    with zipfile.ZipFile(a.source) as z,a.source.open('rb') as f:
        replacements={PAYLOAD:a.payload.read_bytes(),'AndroidManifest.xml':manifest(z.read('AndroidManifest.xml'))}
        prepared={};changed=[];streams=[]
        for name,raw in replacements.items():
            i=z.getinfo(name);assert i.compress_type==8 and not i.flag_bits&9
            packed,compression=fit_deflate(raw,i.compress_size)
            prepared[name]=(raw,packed)
            changed.append({'name':name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'compression':compression})
        for i in z.infolist():
            f.seek(i.header_offset);h=f.read(30);assert h[:4]==b'PK\x03\x04'
            n,x=struct.unpack_from('<HH',h,26);data=i.header_offset+30+n+x
            raw,packed=prepared.get(i.filename,(None,None))
            streams.append({'name':i.filename,'offset':i.header_offset,'data_offset':data,'compressed_size':i.compress_size,
                'size':len(raw) if raw is not None else i.file_size,'crc':zlib.crc32(raw) if raw is not None else i.CRC,
                'compressed_sha256':hashlib.sha256(packed).hexdigest() if packed is not None else stream_hash(f,data,i.compress_size),
                'changed':raw is not None})
        cd=z.start_dir
    shutil.copyfile(a.source,a.output)
    with a.output.open('r+b') as f:
        for s in streams:
            if not s['changed']:continue
            f.seek(s['data_offset']);f.write(prepared[s['name']][1])
            f.seek(s['offset']+14);f.write(struct.pack('<I',s['crc']))
            f.seek(s['offset']+22);f.write(struct.pack('<I',s['size']))
        f.seek(cd)
        for s in streams:
            at=f.tell();h=f.read(46);assert h[:4]==b'PK\x01\x02'
            n,x,c=struct.unpack_from('<3H',h,28);name=f.read(n).decode('utf-8');assert name==s['name']
            if s['changed']:
                f.seek(at+16);f.write(struct.pack('<I',s['crc']))
                f.seek(at+24);f.write(struct.pack('<I',s['size']))
            f.seek(at+46+n+x+c)
    assert a.output.stat().st_size==a.source.stat().st_size
    a.streams.write_text(json.dumps(streams,separators=(',',':'))+'\n')
    report={'source_sha256':SOURCE_SHA256,'source_size':a.source.stat().st_size,'changed_entries':changed,
            'local_record_offsets_preserved':True,'compressed_spans_preserved':True,'unchanged_entries':len(streams)-len(changed),
            'unchanged_entries_expected_compressed_sha256_recorded':True,'unsigned_size':a.output.stat().st_size}
    a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
if __name__=='__main__':main()
