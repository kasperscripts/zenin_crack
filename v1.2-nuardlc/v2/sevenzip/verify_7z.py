#!/usr/bin/env python3
"""Independently decode 7z via libarchive and hash the complete unchanged APK."""
import argparse,ctypes,ctypes.util,hashlib,json
from pathlib import Path
APK_NAME='NuarDLC_News_v1.2_fix_v2.apk'
APK_SHA256='96656cba9da615a4a8f103fc5ee2469c8fbd1a77d203561c251ad4c86840e0ae'
APK_SIZE=2285563072

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    name=ctypes.util.find_library('archive');assert name,'libarchive is required'
    lib=ctypes.CDLL(name);P=ctypes.c_void_p
    signatures={
        'archive_read_new':([],P),'archive_read_support_filter_all':([P],ctypes.c_int),
        'archive_read_support_format_7zip':([P],ctypes.c_int),
        'archive_read_open_filename':([P,ctypes.c_char_p,ctypes.c_size_t],ctypes.c_int),
        'archive_read_next_header':([P,ctypes.POINTER(P)],ctypes.c_int),
        'archive_read_data':([P,P,ctypes.c_size_t],ctypes.c_ssize_t),
        'archive_entry_pathname':([P],ctypes.c_char_p),'archive_entry_size':([P],ctypes.c_int64),
        'archive_error_string':([P],ctypes.c_char_p),'archive_read_free':([P],ctypes.c_int),
        'archive_version_string':([],ctypes.c_char_p)}
    for fn,(args,result) in signatures.items():
        getattr(lib,fn).argtypes=args;getattr(lib,fn).restype=result
    handle=lib.archive_read_new();assert handle
    try:
        assert lib.archive_read_support_filter_all(handle)==0
        assert lib.archive_read_support_format_7zip(handle)==0
        assert lib.archive_read_open_filename(handle,str(a.archive).encode(),1024*1024)==0,lib.archive_error_string(handle)
        entry=P();assert lib.archive_read_next_header(handle,ctypes.byref(entry))==0,lib.archive_error_string(handle)
        assert lib.archive_entry_pathname(entry).decode()==APK_NAME and lib.archive_entry_size(entry)==APK_SIZE
        buffer=ctypes.create_string_buffer(4*1024*1024);h=hashlib.sha256();count=0
        while True:
            n=lib.archive_read_data(handle,buffer,len(buffer));assert n>=0,lib.archive_error_string(handle)
            if not n:break
            h.update(memoryview(buffer).cast('B')[:n]);count+=n
        assert count==APK_SIZE and h.hexdigest()==APK_SHA256
        assert lib.archive_read_next_header(handle,ctypes.byref(entry))==1,lib.archive_error_string(handle)
    finally:lib.archive_read_free(handle)
    with a.archive.open('rb') as f:checksum=hashlib.file_digest(f,'sha256').hexdigest()
    report={'format':'7z','archive_size':a.archive.stat().st_size,'archive_sha256':checksum,'decoder':lib.archive_version_string().decode(),'full_extraction_sha256_and_crc_verified':True,'apk_name':APK_NAME,'apk_size':count,'apk_sha256':h.hexdigest(),'apk_changed':False,'android_mt_manager_tested':False}
    a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
if __name__=='__main__':main()
