#!/usr/bin/env python3
"""Patch the pinned Zenin ARM64 payload for a local Icon_Crack key workflow."""
import argparse,hashlib,json,struct
from pathlib import Path
from keystone import Ks,KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN

SOURCE_SHA256='e50bd056c3e3174c358c5c86508ac7c2eea82215c912d2de30482e91cd036a96'
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
    function(0x1a056c,0x1a090c,"""
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
        cmp x1, #11
        b.ne invalid
        adrp x9, 0x1a0000
        add x9, x9, #0x700
        mov x10, #0
    check:
        ldrb w11, [x0, x10]
        ldrb w12, [x9, x10]
        cmp w11, w12
        b.ne invalid
        add x10, x10, #1
        cmp x10, #11
        b.ne check
        mov w11, #22
        strb w11, [x8]
        ldr x11, [x9]
        str x11, [x8, #1]
        ldr w11, [x9, #8]
        str w11, [x8, #9]
    invalid:
        ret
    """,'Trim pasted ASCII whitespace and normalize the exact local key; invalid input returns an empty std::string')
    function(0x633274,0x6333ac,"""
        cmp x1, #11
        b.ne invalid_clipboard
        cbz x0, invalid_clipboard
        adrp x9, 0x1a0000
        add x9, x9, #0x700
        mov x10, #0
    clipboard_compare:
        ldrb w11, [x0, x10]
        ldrb w12, [x9, x10]
        cmp w11, w12
        b.ne invalid_clipboard
        add x10, x10, #1
        cmp x10, #11
        b.ne clipboard_compare
        mov w0, #1
        ret
    invalid_clipboard:
        mov w0, #0
        ret
    """,'Use the local key in the original Android clipboard validation path')
    put(0x1a0700,b'@Icon_Crack\0','Local key literal')
    put(0x1a0720,b'Invalid key\0','Local failure caption')
    put(0x1a0750,b't.me/Icon_Crack\0','Menu channel caption')
    put(0x1a0770,b'https://t.me/Icon_Crack\0','Contact URL')
    put(0x1a0800,b'Clipboard unavailable\0','Clipboard failure caption')
    put(0x1a0840,b'Initialization failed\0','Session initialization failure caption')
    function(0x169a00,0x16a550,"""
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
        adrp x9, 0x75f9000
        add x9, x9, #0x6cc
        stlr wzr, [x9]
        adrp x9, 0x75f9000
        add x9, x9, #0x8a8
        stlrb wzr, [x9]
        add x9, x9, #4
        mov w10, #1
        stlrb w10, [x9]
        adrp x0, 0x7dfe000
        add x0, x0, #0x7b8
        bl 0x1a090c
    poll:
        adrp x9, 0x75f9000
        add x9, x9, #0x6b0
        ldarb w9, [x9]
        tbnz w9, #0, done
        bl 0x1a4624
        cbz w0, submitted
        add x0, sp, #0xa0
        bl 0x632614
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
        bl 0x1a467c
        b clipboard_clear
    clipboard_error:
        cmp w0, #7
        adrp x2, 0x1a0000
        b.eq clipboard_invalid
        add x2, x2, #0x800
        mov x3, #21
        b clipboard_report
    clipboard_invalid:
        add x2, x2, #0x720
        mov x3, #11
    clipboard_report:
        mov x0, #0
        mov x1, #0
        bl 0x1a467c
    clipboard_clear:
        ldrb w9, [sp, #0xa0]
        tbz w9, #0, clipboard_small
        ldr x0, [sp, #0xb0]
        bl 0x69b380
    clipboard_small:
        stp xzr, xzr, [sp, #0xa0]
        str xzr, [sp, #0xb0]
    submitted:
        add x0, sp, #0x40
        bl 0x1a44ec
        cbnz w0, have_key
        adrp x9, 0x7dfe000
        ldr w9, [x9, #0x7e0]
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
        bl 0x1a056c
        ldrb w9, [sp, #0x70]
        cmp w9, #22
        b.ne rejected
        add x0, sp, #0x70
        add x1, sp, #0xc0
        bl 0x6361e0
        bl 0x636668
        cbz w0, initialization_failed
        adrp x9, 0x75f9000
        add x9, x9, #0x6cc
        mov w10, #6
        stlr w10, [x9]
        adrp x9, 0x75f9000
        add x9, x9, #0x8ac
        stlrb wzr, [x9]
        bl 0x1a4618
        b clear
    initialization_failed:
        adrp x0, 0x1a0000
        add x0, x0, #0x840
        mov x1, #21
        bl 0x1a4604
        b clear
    rejected:
        adrp x0, 0x1a0000
        add x0, x0, #0x720
        mov x1, #11
        bl 0x1a4604
    clear:
        ldrb w9, [sp, #0x40]
        tbz w9, #0, small
        ldr x0, [sp, #0x50]
        bl 0x69b380
    small:
        stp xzr, xzr, [sp, #0x40]
        str xzr, [sp, #0x50]
    activate:
        adrp x9, 0x75f9000
        add x9, x9, #0x6cc
        ldar w10, [x9]
        cmp w10, #6
        b.ne sleep
        mov w0, #1
        bl 0x46bdcc
    sleep:
        mov x9, #0xf080
        movk x9, #0x2fa, lsl #16
        str x9, [sp, #8]
        add x0, sp, #8
        bl 0x67eebc
        b poll
    done:
        adrp x9, 0x75f9000
        add x9, x9, #0x6cc
        stlr wzr, [x9]
        adrp x9, 0x75f9000
        add x9, x9, #0x8ac
        stlrb wzr, [x9]
        mov w0, #0
        bl 0x46bdcc
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
        adrp x9, 0x75f9000
        add x9, x9, #0x6b0
        ldarb w10, [x9]
        tbnz w10, #0, no
        adrp x9, 0x75f9000
        add x9, x9, #0x6cc
        ldar w10, [x9]
        cmp w10, #6
        cset w0, eq
        ret
    no:
        mov x0, #0
        ret
    """
    function(0x16a9b4,0x16ab84,gate,'Local authorization token from the persistent service session, independent of UI visibility')
    function(0x16acb0,0x16aef0,gate,'Validate the persistent service session; original public gate accessors remain unchanged')
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
    for pc,address,n,text in [(0x1a3e54,0x72c3a7,18,'@Icon_Crack'),
                              (0x1a43f0,0x72c47d,37,'Use @Icon_Crack'),
                              (0x633848,0x6403667,52,'Use @Icon_Crack')]:
        encoded(address,n,call_key(pc),text)
    # Both contact buffers end exactly before their guard variables and can
    # hold 24 bytes. Store the longer ciphertexts in the reserved literal area.
    for pc,pool,adrp_pc,add_pc,size_pc in [(0x536e20,0x1a07a0,0x536e04,0x536e08,0x536e10),
                                        (0x536f48,0x1a07c0,0x536f2c,0x536f30,0x536f38)]:
        put(pool,crypt(b'https://t.me/Icon_Crack\0',call_key(pc)),'Encoded contact URL')
        put(adrp_pc,asm(adrp_pc,'adrp x0, 0x1a0000'),'Relocate contact ciphertext address')
        put(add_pc,asm(add_pc,f'add x0, x0, #{pool&4095}'),'Relocate contact ciphertext offset')
        put(size_pc,asm(size_pc,'mov w2, #24'),'Contact buffer length remains within its 24-byte allocation')
    put(0x2e6cb0,asm(0x2e6cb0,'adrp x24, 0x1a0000; add x24, x24, #0x750'),'Menu channel text pointer')
    put(0x2e6e98,asm(0x2e6e98,'cmp x27, #15'),'Menu channel character count')
    assert len(data)==len(original)
    return bytes(data),{'source_sha256':SOURCE_SHA256,'patched_sha256':hashlib.sha256(data).hexdigest(),
        'size':len(data),'key':'@Icon_Crack','telegram':'https://t.me/Icon_Crack',
        'local_license_worker':True,'server_key_used':False,'changes':changes}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',type=Path,required=True)
    a=p.parse_args();assert a.source.resolve()!=a.output.resolve()
    result,report=patch(a.source);a.output.write_bytes(result);a.report.write_text(json.dumps(report,indent=2)+'\n');print(a.output)
