#!/usr/bin/env python3
"""Fail-closed archive extractor for live release qualification."""
import argparse, inspect, os, pathlib, stat, tarfile, zipfile

def reject(name, mode=0, link=None):
    p = pathlib.PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise ValueError(f"unsafe path: {name}")
    if mode & (stat.S_ISUID | stat.S_ISGID):
        raise ValueError(f"privileged mode: {name}")
    if link is not None:
        raise ValueError(f"links are forbidden: {name}")

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("archive"); ap.add_argument("destination")
    ap.add_argument("--max-files",type=int,default=2000); ap.add_argument("--max-bytes",type=int,default=268435456)
    a=ap.parse_args(); entries=[]; total=0
    if tarfile.is_tarfile(a.archive):
        with tarfile.open(a.archive,"r:*") as f:
            for m in f.getmembers():
                reject(m.name,m.mode,m.linkname if (m.issym() or m.islnk()) else None)
                if m.isdev() or m.isfifo(): raise ValueError(f"special file: {m.name}")
                if not (m.isfile() or m.isdir()): raise ValueError(f"unsupported entry: {m.name}")
                total += m.size; entries.append(m)
            if len(entries)>a.max_files or total>a.max_bytes: raise ValueError("archive expansion budget exceeded")
            # Links and special entries were rejected above, so older Python
            # runtimes without the 3.12 `filter` argument remain safe here.
            for member in entries:
                if "filter" in inspect.signature(f.extract).parameters:
                    f.extract(member, a.destination, filter="data")
                else:
                    f.extract(member, a.destination)
    elif zipfile.is_zipfile(a.archive):
        with zipfile.ZipFile(a.archive) as f:
            for m in f.infolist():
                mode=(m.external_attr>>16)&0xffff; reject(m.filename,mode,"link" if stat.S_ISLNK(mode) else None)
                total += m.file_size; entries.append(m)
            if len(entries)>a.max_files or total>a.max_bytes: raise ValueError("archive expansion budget exceeded")
            f.extractall(a.destination)
    else: raise ValueError("unsupported archive format")
    print(f"files={len(entries)} bytes={total}")
if __name__=="__main__": main()
