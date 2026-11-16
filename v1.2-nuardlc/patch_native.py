#!/usr/bin/env python3
"""Patch the pinned Zenin ARM64 payload for a local NuarDLC_News key workflow."""
import argparse,hashlib,json,struct
from pathlib import Path
from keystone import Ks,KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN

SOURCE_SHA256='21b27156f62d4a1755dbe6c94de378723da9904d0f93f314212fc0da18b97702'
MASK=(1<<64)-1
def crypt(data,key):
    out=[]
    for i,c in enumerate(data):
        x=(key+i)&MASK;x=((x^(x>>30))*0xbf58476d1ce4e5b9)&MASK
        x=((x^(x>>27))*0x94d049bb133111eb)&MASK
        out.append(c^((x^(x>>31))&255))
    return bytes(out)

def patch(source):
    original=source.read_bytes();assert hashlib.sha256(original).hexdigest()==SOURCE_SHA256
    data=bytearray(original);ks=Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN);changes=[]
    def put(address,new,label):
        old=bytes(data[address:address+len(new)]);data[address:address+len(new)]=new
        changes.append({'offset':address,'length':len(new),'description':label,'original_hex':old.hex(),'patched_hex':new.hex()})
    def asm(address,text):return bytes(ks.asm(text,addr=address)[0])
    def function(address,end,text,label):
        code=asm(address,text);assert len(code)<=end-address
        put(address,code+bytes.fromhex('1f2003d5')*((end-address-len(code))//4),label)
    function(0x1aa6f8,0x1aaa98,"""
        stp xzr, xzr, [x8]
        str xzr, [x8, #16]
        cbz x0, invalid
    trim_start:
        cbz x1, invalid
        ldrb w9, [x0]
        cmp w9, #32
        b.eq skip_start
        sub w10, w9, #9
        cmp w10, #4
        b.hi trim_end
    skip_start:
        add x0, x0, #1
        sub x1, x1, #1
        b trim_start
    trim_end:
        cbz x1, invalid
        sub x10, x1, #1
        ldrb w9, [x0, x10]
        cmp w9, #32
        b.eq skip_end
        sub w10, w9, #9
        cmp w10, #4
        b.hi compare
    skip_end:
        sub x1, x1, #1
        b trim_end
    compare:
        cmp x1, #13
        b.ne invalid
        adrp x9, 0x1aa000
        add x9, x9, #0x88c
        mov x10, #0
    check:
        ldrb w11, [x0, x10]
        ldrb w12, [x9, x10]
        cmp w11, w12
        b.ne invalid
        add x10, x10, #1
        cmp x10, #13
        b.ne check
        mov w11, #26
        strb w11, [x8]
        ldr x11, [x9]
        str x11, [x8, #1]
        ldr x11, [x9, #8]
        str x11, [x8, #9]
    invalid:
        ret
    """,'Trim pasted ASCII whitespace and normalize the exact local key; invalid input returns an empty std::string')
    function(0x63d008,0x63d140,"""
        cmp x1, #13
        b.ne invalid_clipboard
        cbz x0, invalid_clipboard
        adrp x9, 0x1aa000
        add x9, x9, #0x88c
        mov x10, #0
    clipboard_compare:
        ldrb w11, [x0, x10]
        ldrb w12, [x9, x10]
        cmp w11, w12
        b.ne invalid_clipboard
        add x10, x10, #1
        cmp x10, #13
        b.ne clipboard_compare
        mov w0, #1
        ret
    invalid_clipboard:
        mov w0, #0
        ret
    """,'Use the local key in the original Android clipboard validation path')
    put(0x1aa88c,b'@NuarDLC_News\0','Local key literal')
    put(0x1aa8ac,b'Invalid key\0','Local failure caption')
    put(0x1aa8dc,b't.me/NuarDLC_News\0','Menu channel caption')
    put(0x1aa8fc,b'https://t.me/NuarDLC_News\0','Contact URL')
    put(0x1aa98c,b'Clipboard unavailable\0','Clipboard failure caption')
    put(0x1aa9cc,b'Initialization failed\0','Session initialization failure caption')
    function(0x16b138,0x16bc88,"""
        stp x29, x30, [sp, #-0x60]!
        stp x28, x27, [sp, #0x10]
        stp x26, x25, [sp, #0x20]
        stp x24, x23, [sp, #0x30]
        stp x22, x21, [sp, #0x40]
        stp x20, x19, [sp, #0x50]
        mov x29, sp
        sub sp, sp, #0x260
        stp xzr, xzr, [sp, #0x40]
        str xzr, [sp, #0x50]
        stp xzr, xzr, [sp, #0xa0]
        str xzr, [sp, #0xb0]
        stp xzr, xzr, [sp, #0xc0]
        str xzr, [sp, #0xd0]
        adrp x9, 0x7603000
        add x9, x9, #0xa0c
        stlr wzr, [x9]
        adrp x9, 0x7603000
        add x9, x9, #0xbe8
        stlrb wzr, [x9]
        add x9, x9, #4
        mov w10, #1
        stlrb w10, [x9]
        adrp x0, 0x7e09000
        add x0, x0, #0xa8
        bl 0x1aaa98
    poll:
        adrp x9, 0x7603000
        add x9, x9, #0x9f0
        ldarb w9, [x9]
        tbnz w9, #0, done
        bl 0x1ae7b0
        cbz w0, submitted
        add x0, sp, #0xa0
        bl 0x63c3a8
        cbnz w0, clipboard_error
        ldrb w9, [sp, #0xa0]
        tbnz w9, #0, clipboard_long
        add x0, sp, #0xa1
        lsr x1, x9, #1
        b clipboard_result
    clipboard_long:
        ldp x1, x0, [sp, #0xa8]
    clipboard_result:
        mov x2, #0
        mov x3, #0
        bl 0x1ae808
        b clipboard_clear
    clipboard_error:
        cmp w0, #7
        adrp x2, 0x1aa000
        b.eq clipboard_invalid
        add x2, x2, #0x98c
        mov x3, #21
        b clipboard_report
    clipboard_invalid:
        add x2, x2, #0x8ac
        mov x3, #11
    clipboard_report:
        mov x0, #0
        mov x1, #0
        bl 0x1ae808
    clipboard_clear:
        ldrb w9, [sp, #0xa0]
        tbz w9, #0, clipboard_small
        ldr x0, [sp, #0xb0]
        bl 0x6a5114
    clipboard_small:
        stp xzr, xzr, [sp, #0xa0]
        str xzr, [sp, #0xb0]
    submitted:
        add x0, sp, #0x40
        bl 0x1ae678
        cbnz w0, have_key
        adrp x9, 0x7e09000
        ldr w9, [x9, #0xd0]
        cmp w9, #2
        b.eq rejected
        b activate
    have_key:
        ldrb w9, [sp, #0x40]
        tbnz w9, #0, submitted_long
        add x0, sp, #0x41
        lsr x1, x9, #1
        b normalize
    submitted_long:
        ldp x1, x0, [sp, #0x48]
    normalize:
        add x8, sp, #0x70
        bl 0x1aa6f8
        ldrb w9, [sp, #0x70]
        cmp w9, #26
        b.ne rejected
        add x0, sp, #0x70
        add x1, sp, #0xc0
        bl 0x63ff74
        bl 0x6403fc
        cbz w0, initialization_failed
        adrp x9, 0x7603000
        add x9, x9, #0xa0c
        mov w10, #6
        stlr w10, [x9]
        adrp x9, 0x7603000
        add x9, x9, #0xbec
        stlrb wzr, [x9]
        bl 0x1ae7a4
        b clear
    initialization_failed:
        adrp x0, 0x1aa000
        add x0, x0, #0x9cc
        mov x1, #21
        bl 0x1ae790
        b clear
    rejected:
        adrp x0, 0x1aa000
        add x0, x0, #0x8ac
        mov x1, #11
        bl 0x1ae790
    clear:
        ldrb w9, [sp, #0x40]
        tbz w9, #0, small
        ldr x0, [sp, #0x50]
        bl 0x6a5114
    small:
        stp xzr, xzr, [sp, #0x40]
        str xzr, [sp, #0x50]
    activate:
        adrp x9, 0x7603000
        add x9, x9, #0xa0c
        ldar w10, [x9]
        cmp w10, #6
        b.ne sleep
        mov w0, #1
        bl 0x4756f8
    sleep:
        mov x9, #0xf080
        movk x9, #0x2fa, lsl #16
        str x9, [sp, #8]
        add x0, sp, #8
        bl 0x688c50
        b poll
    done:
        adrp x9, 0x7603000
        add x9, x9, #0xa0c
        stlr wzr, [x9]
        adrp x9, 0x7603000
        add x9, x9, #0xbec
        stlrb wzr, [x9]
        mov w0, #0
        bl 0x4756f8
        mov x0, #0
        add sp, sp, #0x260
        ldp x20, x19, [sp, #0x50]
        ldp x22, x21, [sp, #0x40]
        ldp x24, x23, [sp, #0x30]
        ldp x26, x25, [sp, #0x20]
        ldp x28, x27, [sp, #0x10]
        ldp x29, x30, [sp], #0x60
        ret
    """,'Service clipboard and submitted keys, publish a persistent session, activate original game hooks, and restore hooks on shutdown')
    gate="""
        adrp x9, 0x7603000
        add x9, x9, #0x9f0
        ldarb w10, [x9]
        tbnz w10, #0, no
        adrp x9, 0x7603000
        add x9, x9, #0xa0c
        ldar w10, [x9]
        cmp w10, #6
        cset w0, eq
        ret
    no:
        mov x0, #0
        ret
    """
    function(0x16c0ec,0x16c2bc,gate,'Local authorization token from the persistent service session, independent of UI visibility')
    function(0x16c3e8,0x16c628,gate,'Validate the persistent service session; original public gate accessors remain unchanged')
    def encoded(address,n,key,text):
        plain=text.encode()+b'\0';assert len(plain)<=n
        put(address,crypt(plain.ljust(n,b'\0'),key),'Updated encoded UI text: '+text)
    # Existing fixed-size hint buffers have enough room; preserve their sizes.
    # Call-site keys are read from the original instructions below to avoid
    # embedding unrelated decoded application strings in this patch.
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    def call_key(pc):
        value=None
        for i in cs.disasm(original[pc-128:pc],pc-128):
            p=i.op_str.split(', ')
            if i.mnemonic=='mov' and p[0]=='x3' and p[1].startswith('#'):value=int(p[1][1:],0)&MASK
            elif i.mnemonic=='movk' and p[0]=='x3' and value is not None:
                shift=int(p[2].split('#')[1],0) if len(p)>2 else 0
                value=(value&~(65535<<shift))|(int(p[1][1:],0)<<shift)
        assert value is not None
        return value
    for pc,address,n,text in [(0x1adfe0,0x736607,18,'@NuarDLC_News'),
                              (0x1ae57c,0x7366dd,37,'Use @NuarDLC_News'),
                              (0x63d5dc,0x640d90f,52,'Use @NuarDLC_News')]:
        encoded(address,n,call_key(pc),text)
    # Both contact buffers end exactly before their guard variables and can
    # hold 24 bytes. Store the longer ciphertexts in the reserved literal area.
    for pc,pool,adrp_pc,add_pc,size_pc in [(0x54074c,0x1aa92c,0x540730,0x540734,0x54073c),
                                        (0x540874,0x1aa94c,0x540858,0x54085c,0x540864)]:
        put(pool,crypt(b'https://t.me/NuarDLC_News\0',call_key(pc)),'Encoded contact URL')
        put(adrp_pc,asm(adrp_pc,'adrp x0, 0x1aa000'),'Relocate contact ciphertext address')
        put(add_pc,asm(add_pc,f'add x0, x0, #{pool&4095}'),'Relocate contact ciphertext offset')
        put(size_pc,asm(size_pc,'mov w2, #26'),'Decode the complete URL into an extended 64-byte buffer')
    put(0x2f0968,asm(0x2f0968,'adrp x24, 0x1aa000; add x24, x24, #0x8dc'),'Menu channel text pointer')
    put(0x2f0b50,asm(0x2f0b50,'cmp x27, #17'),'Menu channel character count')
    from elftools.elf.elffile import ELFFile
    with source.open('rb') as stream:
        elf=ELFFile(stream)
        index,segment=max(((i,p) for i,p in enumerate(elf.iter_segments()) if p['p_type']=='PT_LOAD'),key=lambda item:item[1]['p_vaddr'])
        bss_index,bss=next((i,s) for i,s in enumerate(elf.iter_sections()) if s.name=='.bss')
        assert segment['p_flags']&2 and segment['p_vaddr']+segment['p_memsz']==0x82a3b80
        assert bss['sh_addr']+bss['sh_size']==0x82a3b80
        put(elf['e_phoff']+index*elf['e_phentsize']+40,struct.pack('<Q',segment['p_memsz']+128),'Reserve two 64-byte writable Telegram URL buffers')
        put(elf['e_shoff']+bss_index*elf['e_shentsize']+32,struct.pack('<Q',bss['sh_size']+128),'Declare the URL buffers in BSS')
    for adrp_pc,add_pc,reg,address in [
        (0x5405b4+0x64,0x5405b4+0x68,'x3',0x82a3b80),
        (0x5405b4+0x170,0x5405b4+0x174,'x1',0x82a3b80),
        (0x5405b4+0xb8,0x5405b4+0xbc,'x3',0x82a3bc0),
        (0x5405b4+0x298,0x5405b4+0x29c,'x1',0x82a3bc0)]:
        put(adrp_pc,asm(adrp_pc,f'adrp {reg}, {address&~4095}'),'Relocate Telegram URL buffer page')
        put(add_pc,asm(add_pc,f'add {reg}, {reg}, #{address&4095}'),'Relocate Telegram URL buffer offset')
    assert len(data)==len(original)
    return bytes(data),{'source_sha256':SOURCE_SHA256,'patched_sha256':hashlib.sha256(data).hexdigest(),
        'size':len(data),'key':'@NuarDLC_News','telegram':'https://t.me/NuarDLC_News',
        'local_license_worker':True,'server_key_used':False,'local_key_expiration':None,'url_buffers':[0x82a3b80,0x82a3bc0],'changes':changes}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',type=Path,required=True)
    a=p.parse_args();assert a.source.resolve()!=a.output.resolve()
    result,report=patch(a.source);a.output.write_bytes(result);a.report.write_text(json.dumps(report,indent=2)+'\n');print(a.output)
