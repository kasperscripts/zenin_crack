#!/usr/bin/env python3
"""Update the two Android display labels while retaining binary XML attribute IDs."""
import struct

SOURCE_SHA256='58754df98745abaf69db351d3fd3d0a7f45306995731dc3c1a0964907e307f1e'
PAYLOAD='assets/VozmiteMeniaNaRabotuNoTolkoNeTolchkiPidoritIseAndRestPidorasi'
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
    label='@NuarDLC_News';index=len(names)
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
