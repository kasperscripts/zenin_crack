"""Exercise incomplete hook records and SDK-binding resets, including the v1 failures."""
from pathlib import Path
import struct
from verify_startup import Image,BASE,FLAGS,HOOK_SLOT,HOOK_VECTOR,ORIGINAL,REPLACEMENT,INPUT

def active(path):
    i=Image(path);i.reset();i.submit('@NuarDLC_News');i.call(0x16b138)
    i.u.mem_write(FLAGS+0x6b0,b'\0');i.u.mem_write(FLAGS+0x6cc,struct.pack('<I',6));return i

def setup(i,slot,original,replacement):
    i.u.mem_write(BASE+0x7e05cd0,b'\0');i.u.mem_write(BASE+0x7febd10,b'\1')
    i.u.mem_write(HOOK_SLOT,struct.pack('<Q',slot));i.u.mem_write(HOOK_VECTOR,struct.pack('<QQQQ',HOOK_SLOT,original,replacement,0))

def verify_loading(path,baseline=None):
    regressions={}
    if baseline:
        b=active(baseline);setup(b,ORIGINAL,ORIGINAL,0);b.call(0x4756f8,1)
        regressions['previous_null_replacement_overwrote_original']=b.integer(HOOK_SLOT,8)==0
        setup(b,0,0,REPLACEMENT);b.call(0x4756f8,1)
        regressions['previous_missing_original_was_activated']=b.integer(HOOK_SLOT,8)==REPLACEMENT
        setup(b,REPLACEMENT,0,REPLACEMENT);b.call(0x475308)
        regressions['previous_cleanup_restored_null']=b.integer(HOOK_SLOT,8)==0
        # A phase flag alone must not keep hooks active when SDK data is invalid.
        setup(b,ORIGINAL,ORIGINAL,REPLACEMENT);b.u.mem_write(BASE+0x75e0aa8,struct.pack('<QQQ',HOOK_VECTOR,HOOK_VECTOR+32,HOOK_VECTOR+32));b.call(0x4756f8,1)
        b.u.mem_write(BASE+0x829c718,b'\0');b.call(0x4756f8,1)
        regressions['previous_invalid_binding_kept_hooks_active']=b.integer(HOOK_SLOT,8)==REPLACEMENT
        assert all(regressions.values()),regressions
        del b
    i=active(path)
    for slot,original,replacement in [(ORIGINAL,ORIGINAL,0),(0,0,REPLACEMENT)]:
        setup(i,slot,original,replacement);i.call(0x4756f8,1)
        assert i.integer(HOOK_SLOT,8)==slot and i.integer(BASE+0x7febd14,1)==0
        assert i.integer(BASE+0x7febd10,1)==1
        # Fill the record later without reauthorizing; retry must now work.
        i.u.mem_write(HOOK_SLOT,struct.pack('<Q',ORIGINAL));i.u.mem_write(HOOK_VECTOR,struct.pack('<QQQQ',HOOK_SLOT,ORIGINAL,REPLACEMENT,0));i.call(0x4756f8,1)
        assert i.integer(HOOK_SLOT,8)==REPLACEMENT and i.integer(BASE+0x7febd14,1)==1
        i.call(0x4756f8,0);assert i.integer(HOOK_SLOT,8)==ORIGINAL
    setup(i,REPLACEMENT,0,REPLACEMENT);i.call(0x475308)
    assert i.integer(HOOK_SLOT,8)==REPLACEMENT
    i.u.mem_write(BASE+0x75e0aa8,struct.pack('<QQQ',HOOK_VECTOR,HOOK_VECTOR+32,HOOK_VECTOR+32));setup(i,ORIGINAL,ORIGINAL,REPLACEMENT)
    i.call(0x4756f8,1);assert i.integer(HOOK_SLOT,8)==REPLACEMENT
    token=i.call(0x16c0ec);assert token&0x100000001==0x100000001
    i.u.mem_write(BASE+0x829c718,b'\0');i.call(0x4756f8,1)
    assert i.integer(HOOK_SLOT,8)==ORIGINAL and i.integer(BASE+0x7febd14,1)==0 and i.call(0x16c0ec)==0
    i.u.mem_write(BASE+0x829c718,b'\1');i.call(0x4756f8,1)
    assert i.integer(HOOK_SLOT,8)==REPLACEMENT and i.integer(BASE+0x7febd14,1)==1 and i.call(0x16c0ec)==token
    i.call(0x4756f8,0);assert i.integer(HOOK_SLOT,8)==ORIGINAL
    return {**regressions,'incomplete_records_preserve_original_and_retry':True,'cleanup_never_restores_null':True,'invalid_binding_suspends_and_restored_binding_resumes_hooks':True,'original_64bit_token_marker_bits_preserved':True}
