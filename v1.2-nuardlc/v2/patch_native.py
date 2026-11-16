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
    function(0x16c0ec,0x16c2bc,"""
        stp x29, x30, [sp, #-16]!
        adrp x9, 0x7603000
        add x9, x9, #0x9f0
        ldarb w10, [x9]
        tbnz w10, #0, no
        adrp x9, 0x7603000
        add x9, x9, #0xa0c
        ldar w10, [x9]
        cmp w10, #6
        b.ne no
        bl 0x6403fc
        cbz w0, no
        adrp x9, 0x829c000
        ldr x0, [x9, #0x710]
        cbz x0, no
        orr x0, x0, #0x100000001
        b done
    no:
        mov x0, #0
    done:
        ldp x29, x30, [sp], #16
        ret
    """,'Return a binding-backed 64-bit lease token with the original mandatory marker bits')
    function(0x16c3e8,0x16c628,"""
        stp x29, x30, [sp, #-16]!
        bl 0x16c0ec
        cmp x0, #0
        cset w0, ne
        ldp x29, x30, [sp], #16
        ret
    """,'Suspend access while the original SDK binding is invalid; retain local activation without a deadline')
    put(0x16c1a0,asm(0x16c1a0,"""
        cbz x25, skip
        ldp x9, x10, [x27, #8]
        cbz x9, pending
        cbz x10, pending
        b 0x475594
    pending:
        b 0x47555c
    skip:
        b 0x475560
    """),'Reject incomplete hook records without overwriting an original method and keep retry pending')
    put(0x475590,asm(0x475590,'b 0x16c1a0'),'Guard hook activation during partial method initialization')
    put(0x16c1c0,asm(0x16c1c0,"""
        cbz x24, skip
        ldp x9, x10, [x28, #-0x18]
        cbz x9, skip
        cbz x10, skip
        b 0x475398
    skip:
        b 0x475370
    """),'Do not restore a method to an unknown or empty original address')
    put(0x475394,asm(0x475394,'b 0x16c1c0'),'Guard restoration of incomplete hook records')
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
                              (0x63d5dc,0x640d90f,52,'Use @NuarDLC_News'),
                              (0x5795f8,0x64059bb,24,'@NuarDLC_News')]:
        encoded(address,n,call_key(pc),text)
    # The original short URL initializers remain unchanged. Only their read
    # consumers receive the complete immutable URL; no BSS extension is needed.
    for pc in [0x540618,0x54066c]:
        put(pc,asm(pc,'adrp x3, 0x1aa000; add x3, x3, #0x8fc'),'Redirect the URL read to the full immutable channel link')
    put(0x2f0968,asm(0x2f0968,'adrp x24, 0x1aa000; add x24, x24, #0x8dc'),'Menu channel text pointer')
    put(0x2f0b50,asm(0x2f0b50,'cmp x27, #17'),'Menu channel character count')
    def pointer(page_pc,add_pc,reg,address,label):
        put(page_pc,asm(page_pc,f'adrp {reg}, {address&~4095}'),label+' page')
        put(add_pc,asm(add_pc,f'add {reg}, {reg}, #{address&4095}'),label+' offset')
    for page_pc,add_pc,reg in [
        (0x179ae0,0x179ae4,'x8'),(0x179b20,0x179b24,'x8'),(0x179b7c,0x179b80,'x8'),
        (0x4c21b4,0x4c21b8,'x4'),(0x4c3150,0x4c3154,'x1'),(0x4c33a8,0x4c33ac,'x4'),
        (0x56ef50,0x56ef54,'x4')]:
        pointer(page_pc,add_pc,reg,0x1aa88c,'Use the complete branding text at the display consumer')
    put(0x16c440,b'@NuarDLC_News-%02d.%02d.%02d%02d\0','Config filename branding')
    pointer(0x15a0a0,0x15a0a4,'x2',0x16c440,'Config filename format')
    assert original[0x6af53c:0x6af53c+19] == b'not a Zenin config\0'
    put(0x6af53c,b'Config is invalid.\0','Remove product branding from the configuration error')
    put(0x1431f0,asm(0x1431f0,'mov w8, #0x2e64'),'Match the compiler-inlined last two error characters')
    item=b'Butt Plug \"Zenin\"\0'
    assert original[0x6bf193:0x6bf193+len(item)] == item
    put(0x6bf193,b'@NuarDLC_News\0'.ljust(len(item),b'\0'),'Rename the pointer-table display item within its original bounds')
    # Keep the original ELF header, segment sizes and section sizes byte-identical.
    import struct as _st
    phoff,shoff=_st.unpack_from('<QQ',original,32)
    phsize,phcount,shsize,shcount=_st.unpack_from('<4H',original,54)
    for at,n in [(0,64),(phoff,phsize*phcount),(shoff,shsize*shcount)]:assert data[at:at+n]==original[at:at+n]
    assert len(data)==len(original)
    return bytes(data),{'source_sha256':SOURCE_SHA256,'patched_sha256':hashlib.sha256(data).hexdigest(),
        'size':len(data),'key':'@NuarDLC_News','telegram':'https://t.me/NuarDLC_News',
        'local_license_worker':True,'server_key_used':False,'local_key_expiration':None,'elf_load_and_section_layout_preserved':True,'incomplete_hook_records_guarded':True,'binding_backed_64bit_token':True,'immutable_contact_url':True,'changes':changes}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',type=Path,required=True)
    a=p.parse_args();assert a.source.resolve()!=a.output.resolve()
    result,report=patch(a.source);a.output.write_bytes(result);a.report.write_text(json.dumps(report,indent=2)+'\n');print(a.output)
