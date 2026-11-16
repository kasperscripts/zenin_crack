#!/usr/bin/env python3
"""Fetch and verify the pinned official 7-Zip 25.01 Linux executable."""
import argparse,hashlib,io,tarfile,urllib.request
from pathlib import Path
URL='https://www.7-zip.org/a/7z2501-linux-x64.tar.xz'
TAR_SHA256='4ca3b7c6f2f67866b92622818b58233dc70367be2f36b498eb0bdeaaa44b53f4'
BINARY_SHA256='a1860fdf0d6ec395e0e277e5222e9aa488747db4aa5c87d1ec879a0916ba0b2f'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path);a=p.parse_args()
    with urllib.request.urlopen(URL,timeout=45) as r:data=r.read(2*1024*1024)
    assert hashlib.sha256(data).hexdigest()==TAR_SHA256
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:xz') as t:binary=t.extractfile('7zz').read()
    assert hashlib.sha256(binary).hexdigest()==BINARY_SHA256
    a.directory.mkdir(parents=True,exist_ok=True);target=a.directory/'7zz';target.write_bytes(binary);target.chmod(0o700)
    print(target)
if __name__=='__main__':main()
