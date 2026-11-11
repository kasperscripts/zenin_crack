#!/usr/bin/env python3
"""Replace the Zenin payload while copying other ZIP compressed streams verbatim."""
import argparse,hashlib,json,re,struct,zipfile,zlib
from pathlib import Path

SOURCE_SHA256='f8fd2c7bdf39f2774923925f08fe33e3e5967e46e170eeaf3c83aba5a80958e3'
UPDATE_SOURCE_SHA256='1fdc769fc79852bb8ddfe768da5fb5009fd02e9d81085ad23087647667d65ce2'
PAYLOAD='assets/VozmiteMeniaNaRabotuNoTolkoNeTolchkiPidoritIseAndRestPidorasi'
SIGNATURE=re.compile(r'META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))',re.I)
def chunks(data):
    pos=8
    while pos<len(data):
        kind,header,size=struct.unpack_from('<HHI',data,pos);assert 8<=header<=size
        yield kind,data[pos:pos+size];pos+=size
    assert pos==len(data)
def length8(data,pos):
    v=data[pos];return (((v&127)<<8)|data[pos+1],pos+2) if v&128 else (v,pos+1)
def manifest(data):
    parts=list(chunks(data));pool=next(b for k,b in parts if k==1)
    count,styles,flags,start,_=struct.unpack_from('<5I',pool,8);assert styles==0
    names=[];raw=[]
    for i in range(count):
        pos=start+struct.unpack_from('<I',pool,28+4*i)[0];begin=pos
        if flags&0x100:
            _,pos=length8(pool,pos);n,pos=length8(pool,pos);names.append(pool[pos:pos+n].decode());raw.append(pool[begin:pos+n+1])
        else:
            n=struct.unpack_from('<H',pool,pos)[0];pos+=2;assert n<32768
            names.append(pool[pos:pos+2*n].decode('utf-16le'));raw.append(pool[begin:pos+2*n+2])
    label='Zenin @Icon_Crack';index=len(names)
    raw.append(bytes([len(label),len(label)])+label.encode()+b'\0' if flags&0x100 else struct.pack('<H',len(label))+label.encode('utf-16le')+b'\0\0')
    offsets=[];body=b''
    for value in raw:offsets.append(len(body));body+=value
    body+=bytes((-len(body))%4);start=28+4*len(raw)
    newpool=struct.pack('<HHIIIIII',1,28,start+len(body),len(raw),0,flags&~1,start,0)+struct.pack('<'+'I'*len(offsets),*offsets)+body
    out=[];modified=0
    for kind,part in parts:
        if kind==1:out.append(newpool);continue
        if kind==0x102:
            tag=names[struct.unpack_from('<I',part,20)[0]]
            attrstart,attrsize,n=struct.unpack_from('<HHH',part,24);assert attrsize==20
            begin=16+attrstart;records=[part[begin+i*20:begin+(i+1)*20] for i in range(n)]
            main=any(names[struct.unpack_from('<I',r,4)[0]]=='name' and r[15]==3 and names[struct.unpack_from('<I',r,16)[0]]=='com.google.firebase.MessagingUnityPlayerActivity' for r in records)
            if tag=='application' or tag=='activity' and main:
                b=bytearray(part)
                for i,r in enumerate(records):
                    if names[struct.unpack_from('<I',r,4)[0]]=='label':
                        pos=begin+i*20;struct.pack_into('<I',b,pos+8,index);b[pos+15]=3;struct.pack_into('<I',b,pos+16,index);modified+=1
                part=bytes(b)
        out.append(part)
    assert modified==2
    body=b''.join(out);return struct.pack('<HHI',3,8,len(body)+8)+body

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('payload',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    assert len({x.resolve() for x in [a.source,a.payload,a.output]})==3
    with a.source.open('rb') as f:source_hash=hashlib.file_digest(f,'sha256').hexdigest()
    assert source_hash in [SOURCE_SHA256,UPDATE_SOURCE_SHA256]
    central=[];changed=[];unchanged=[]
    with zipfile.ZipFile(a.source) as src,a.source.open('rb') as inp,a.output.open('wb') as out:
        replacements={PAYLOAD:a.payload.read_bytes()}
        if source_hash==SOURCE_SHA256:replacements['AndroidManifest.xml']=manifest(src.read('AndroidManifest.xml'))
        for info in src.infolist():
            if SIGNATURE.fullmatch(info.filename):continue
            name=info.filename.encode('utf-8');method=info.compress_type;assert method in [0,8] and not info.flag_bits&1
            flags=(info.flag_bits&~8)|0x800
            size=info.file_size;compressed=info.compress_size;crc=info.CRC;replacement=None
            if info.filename in replacements:
                value=replacements[info.filename];size=len(value);crc=zlib.crc32(value)
                c=zlib.compressobj(6,zlib.DEFLATED,-15) if method==8 else None
                replacement=c.compress(value)+c.flush() if c else value;compressed=len(replacement)
                changed.append({'name':info.filename,'size':size,'sha256':hashlib.sha256(value).hexdigest()})
            else:unchanged.append(info.filename)
            hour,minute,second=info.date_time[3:];year,month,day=info.date_time[:3]
            stamp=(hour<<11)|(minute<<5)|(second//2);date=((year-1980)<<9)|(month<<5)|day
            offset=out.tell();alignment=16384 if method==0 and info.filename.endswith('.so') else 4
            padding=(-(offset+30+len(name)))%alignment
            if padding and padding<4:padding+=alignment
            extra=struct.pack('<HH',0xffff,padding-4)+bytes(padding-4) if padding else b''
            out.write(struct.pack('<4s5H3I2H',b'PK\x03\x04',20,flags,method,stamp,date,crc,compressed,size,len(name),len(extra))+name+extra)
            if replacement is not None:out.write(replacement)
            else:
                inp.seek(info.header_offset);header=inp.read(30);n,x=struct.unpack_from('<HH',header,26);inp.seek(n+x,1)
                remaining=compressed
                while remaining:
                    block=inp.read(min(16*1024*1024,remaining));assert block;out.write(block);remaining-=len(block)
            central.append(struct.pack('<4s6H3I5H2I',b'PK\x01\x02',(info.create_system<<8)|info.create_version,20,flags,method,stamp,date,crc,compressed,size,len(name),0,0,0,info.internal_attr,info.external_attr,offset)+name)
        start=out.tell();body=b''.join(central);out.write(body);assert len(central)<65535
        out.write(struct.pack('<4s4H2IH',b'PK\x05\x06',0,0,len(central),len(central),len(body),start,0))
    a.report.write_text(json.dumps({'original_sha256':source_hash,'changed_entries':changed,'unchanged_compressed_streams':len(unchanged),'unsigned_size':a.output.stat().st_size},indent=2)+'\n');print(a.output,flush=True)
if __name__=='__main__':main()
