#!/usr/bin/env python3
"""Execute the patched ARM64 key path and original UI/gate methods in Unicorn."""
import argparse,hashlib,json,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.arm64_const import *
from elftools.elf.elffile import ELFFile

parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('payload',type=Path);parser.add_argument('--report',type=Path,required=True);args=parser.parse_args()
raw=args.payload.read_bytes();elf=ELFFile(args.payload.open('rb'))
u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM64_MAX);u.mem_map(0,0x9000000);u.mem_map(0x20000000,0x3000000)
for p in elf.iter_segments():
    if p['p_type']=='PT_LOAD':u.mem_write(p['p_vaddr'],p.data())
symbols=list(elf.get_section_by_name('.dynsym').iter_symbols());imports={};names={}
for s in symbols:
    if s.name and s['st_shndx']=='SHN_UNDEF':
        address=0x20000000+16*len(imports);imports[s.name]=address;names[address]=s.name
        u.mem_write(address,bytes.fromhex('c0035fd6'))
for section in ['.rela.dyn','.rela.plt']:
    for r in elf.get_section_by_name(section).iter_relocations():
        value=r['r_addend'];ty=r['r_info_type'];index=r['r_info_sym']
        if ty==1027:pass
        elif ty in [257,1025,1026]:value+=imports.get(symbols[index].name,symbols[index]['st_value'])
        else:raise AssertionError(('unsupported relocation',ty))
        u.mem_write(r['r_offset'],struct.pack('<Q',value&((1<<64)-1)))
STACK=0x22fff000;STOP=0x200ff000;UI=0x7dfe7b8;FLAGS=0x75f9000;INPUT=0x21000000;OUTPUT=0x21001000
u.reg_write(UC_ARM64_REG_TPIDR_EL0,0x22f00000);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
def ret(value=0):
    u.reg_write(UC_ARM64_REG_X0,value);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
def hook_import(machine,pc,size,data):
    name=names[pc];a=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(4)]
    if name.startswith('pthread_mutex_'):ret()
    elif name=='clock_gettime':u.mem_write(a[1],struct.pack('<QQ',1000,123456));ret()
    elif name in ['memcpy','memmove','__memcpy_chk']:u.mem_write(a[0],bytes(u.mem_read(a[1],a[2])));ret(a[0])
    elif name=='memset':u.mem_write(a[0],bytes([a[1]&255])*a[2]);ret(a[0])
    else:raise AssertionError(('unexpected native import',name))
u.hook_add(UC_HOOK_CODE,hook_import,begin=0x20000000,end=0x20010000)
def interrupt(machine,number,data):
    syscall=u.reg_read(UC_ARM64_REG_X8)
    assert number==2 and syscall==113,('unexpected syscall',number,syscall)
    u.mem_write(u.reg_read(UC_ARM64_REG_X1),struct.pack('<QQ',1000,123456))
    u.reg_write(UC_ARM64_REG_X0,0)
u.hook_add(UC_HOOK_INTR,interrupt)
sleep_count=0
def sleep_hook(machine,pc,size,data):
    global sleep_count
    sleep_count+=1;u.mem_write(FLAGS+0x6b0,b'\1');ret()
u.hook_add(UC_HOOK_CODE,sleep_hook,begin=0x67eebc,end=0x67eebc)
def call(pc,*values,out=None):
    u.reg_write(UC_ARM64_REG_SP,STACK);u.reg_write(UC_ARM64_REG_LR,STOP)
    for i,v in enumerate(values):u.reg_write(UC_ARM64_REG_X0+i,v)
    if out is not None:u.reg_write(UC_ARM64_REG_X8,out)
    try:u.emu_start(pc,STOP,count=2_000_000)
    except Exception:
        print('NATIVE_EXECUTION_STOPPED',hex(pc),hex(u.reg_read(UC_ARM64_REG_PC)),flush=True)
        raise
    assert u.reg_read(UC_ARM64_REG_PC)==STOP,hex(u.reg_read(UC_ARM64_REG_PC))
    return u.reg_read(UC_ARM64_REG_X0)
def small(text):
    value=text.encode();assert len(value)<23
    return (bytes([len(value)*2])+value+b'\0').ljust(24,b'\0')
def reset():
    u.mem_write(UI,bytes(0x220));u.mem_write(FLAGS+0x6b0,bytes(0x200));u.mem_write(FLAGS+0x6b4,b'\1')
cases=['@Icon_Crack','ZAPKFREE-EXAMPLE1','@icon_crack',' @Icon_Crack ','','random','@Icon_CracK']
for text in cases:
    value=text.encode();u.mem_write(INPUT,value+b'\0');u.mem_write(OUTPUT,bytes(32))
    call(0x1a056c,INPUT,len(value),out=OUTPUT)
    result=bytes(u.mem_read(OUTPUT,24));assert result==(small('@Icon_Crack') if text=='@Icon_Crack' else bytes(24)),text
positive=[0x16a944,0x16aef0,0x16af60,0x16afd0,0x16b040]
reset();call(0x1a090c,UI)
for pc in positive:assert call(pc)==0,hex(pc)
for text,expected in [('@Icon_Crack',4),('bad-key',3)]:
    reset();call(0x1a090c,UI);u.mem_write(INPUT,small(text));call(0x1a0ee4,UI,INPUT)
    assert struct.unpack('<I',u.mem_read(UI+0x28,4))[0]==2
    before=sleep_count;call(0x169a00);assert sleep_count==before+1
    assert struct.unpack('<I',u.mem_read(UI+0x28,4))[0]==expected
    u.mem_write(FLAGS+0x6b0,b'\0')
    for pc in positive:assert call(pc)==(1 if expected==4 else 0),(hex(pc),text)
    assert call(0x16ac14)==(0 if expected==4 else 1)
    assert call(0x16a9b4,0)==(1 if expected==4 else 0)
    if expected==4:
        u.mem_write(INPUT,struct.pack('<Q',1));assert call(0x16ab84,INPUT)==1
        u.mem_write(INPUT,struct.pack('<Q',2));assert call(0x16ab84,INPUT)==0
        u.mem_write(FLAGS+0x6b0,b'\1')
        for pc in positive:assert call(pc)==0
contacts=[]
def contact_hook(machine,pc,size,data):
    if pc==0x6810bc:ret(1)
    elif pc==0x6811ec:
        u.mem_write(u.reg_read(UC_ARM64_REG_X0),b'\1');ret()
    else:
        address=u.reg_read(UC_ARM64_REG_X3)
        contacts.append(bytes(u.mem_read(address,64)).split(b'\0')[0].decode());ret()
for pc in [0x6810bc,0x6811ec,0x536f60]:u.hook_add(UC_HOOK_CODE,contact_hook,begin=pc,end=pc)
call(0x536c88)
assert contacts==['https://t.me/Icon_Crack','https://t.me/Icon_Crack'],contacts
assert bytes(u.mem_read(0x828a688,1))==bytes(u.mem_read(0x828a6c8,1))==b'\1'
report={'payload_sha256':hashlib.sha256(raw).hexdigest(),'normalizer_cases':len(cases),
        'original_ui_submit_and_success_failure_paths_executed':True,
        'local_worker_accepts_new_key_and_rejects_invalid_input':True,
        'original_public_authorization_gates_tested':len(positive),
        'original_blocking_gate_and_token_validation_tested':True,
        'incorrect_stored_token_rejected':True,'shutdown_respected':True,
        'original_contact_initializer_and_decoder_executed':True,
        'contact_urls':contacts,'contact_buffer_guard_bytes_preserved':True,
        'native_network_functions_called':0,'android_device_tested':False,
        'stubs':['pthread mutex operations','clock_gettime','sleep (one iteration)','static initialization guards','contact UI drawing'],
        'limits':'ARM64 emulation covers key submission and authorization state, not Android UI rendering, game startup or game features.'}
args.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
