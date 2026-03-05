#!/usr/bin/env python3
# Usage:
#   python zhp_tool.py extract <Resource.zhp> <out_dir> [--encoding cp932]
#   python zhp_tool.py repack  <template Resource.zhp> <extracted_dir> <out.zhp>

import os
import re
import sys
import json
import struct
import zlib
from pathlib import Path
from typing import Dict, Iterator, Tuple, Optional

# ---- Signatures ----
EOCD_SIG = b"PK\x05\x06"
LH_SIG   = b"PK\x03\x04"
CD_SIG   = b"RK\x01\x12"  # ZHP central directory signature (mangled from PK 01 02)

# ---- Structs ----
# Local file header: 30 bytes
# sig, ver, flag, comp, mtime, mdate, crc32, csize, usize, nlen, xlen
LH_STRUCT = struct.Struct("<4sHHHHHIIIHH")

# Central directory header: 46 bytes
# sig, ver_made, ver_need, flag, comp, mtime, mdate, crc32, csize, usize,
# nlen, xlen, clen, disk, iattr, eattr, lhoff
CD_STRUCT = struct.Struct("<4sHHHHHHIIIHHHHHII")

INVALID_WIN = r'<>:"/\\|?*\x00-\x1f'
_invalid_re = re.compile(f"[{INVALID_WIN}]")

def sanitize_component(s: str) -> str:
    # Replace invalid Windows filename chars & trim trailing dot/space
    s = _invalid_re.sub("_", s)
    s = s.rstrip(" .")
    return s if s else "_"

def decode_name_bytes(name_bytes: bytes, encodings: Tuple[str, ...]) -> str:
    """
    Decode raw filename bytes into a displayable path.
    We use cp932 by default (Shift-JIS) for JP-targeted titles.
    """
    for enc in encodings:
        try:
            return name_bytes.decode(enc, errors="strict")
        except UnicodeDecodeError:
            pass
    return name_bytes.decode("latin-1", errors="replace")

def relpath_from_namehex(name_hex: str, encodings: Tuple[str, ...]) -> Path:
    nb = bytes.fromhex(name_hex)
    s = decode_name_bytes(nb, encodings=encodings)

    # Archive paths in ZHP use backslashes; normalize to forward slash for splitting
    s = s.replace("\\", "/")

    parts = [sanitize_component(p) for p in s.split("/") if p not in ("", ".", "..")]
    return Path(*parts)

def find_eocd(data: bytes) -> int:
    """
    EOCD can be up to 65535+22 bytes from end due to ZIP comment.
    We search backwards in a safe window.
    """
    start = max(0, len(data) - (65535 + 22 + 8192))
    i = data.rfind(EOCD_SIG, start)
    if i < 0:
        raise ValueError("EOCD signature PK\\x05\\x06 not found")
    return i

def parse_eocd(data: bytes) -> Dict[str, int]:
    off = find_eocd(data)
    # EOCD: sig, disk, cd_disk, disk_entries, total_entries, cd_size, cd_off, comment_len
    sig, disk, cd_disk, disk_entries, total_entries, cd_size, cd_off, cmt_len = struct.unpack_from("<4s4H2LH", data, off)
    if sig != EOCD_SIG:
        raise ValueError("EOCD parse failed (bad signature?)")
    return {"off": off, "total": total_entries, "cd_size": cd_size, "cd_off": cd_off}

def iter_cd(data: bytes, eocd: Dict[str, int]) -> Iterator[Dict[str, int]]:
    """
    Iterate central directory entries. Signature is RK 01 12 in this ZHP.
    """
    pos = eocd["cd_off"]
    end = pos + eocd["cd_size"]

    for idx in range(eocd["total"]):
        if pos + 46 > end:
            raise ValueError("Central directory truncated (ran out of bytes)")

        sig = data[pos:pos+4]
        if sig != CD_SIG:
            raise ValueError(f"Unexpected central directory signature at {pos:#x}: {sig!r} (expected RK 01 12)")

        (sig, ver_made, ver_need, flag, comp, mtime, mdate, crc, csize, usize,
         nlen, xlen, clen, disk, iattr, eattr, lhoff) = CD_STRUCT.unpack_from(data, pos)

        name = data[pos+46:pos+46+nlen]

        pos += 46 + nlen + xlen + clen

        yield {
            "idx": idx,
            "name": name,
            "name_hex": name.hex(),
            "ver_need": ver_need,
            "flag": flag,
            "comp": comp,
            "mtime": mtime,
            "mdate": mdate,
            "crc": crc,
            "csize": csize,
            "usize": usize,
            "eattr": eattr,
            "lhoff": lhoff,
        }

def read_local_entry(data: bytes, lhoff: int) -> Dict[str, object]:
    """
    Read the local header and return compressed data slice.
    """
    if data[lhoff:lhoff+4] != LH_SIG:
        raise ValueError(f"Local header signature mismatch at {lhoff:#x}")

    (sig, ver_need, flag, comp, mtime, mdate, crc, csize, usize, nlen, xlen) = LH_STRUCT.unpack_from(data, lhoff)
    name = data[lhoff+30:lhoff+30+nlen]
    # Skip extra field
    data_off = lhoff + 30 + nlen + xlen
    comp_data = data[data_off:data_off+csize]

    return {
        "ver_need": ver_need,
        "flag": flag,
        "comp": comp,
        "mtime": mtime,
        "mdate": mdate,
        "crc": crc,
        "csize": csize,
        "usize": usize,
        "name": name,
        "data_off": data_off,
        "comp_data": comp_data,
    }

def inflate_raw(comp_bytes: bytes) -> bytes:
    d = zlib.decompressobj(wbits=-15) 
    return d.decompress(comp_bytes) + d.flush()

def deflate_raw(payload: bytes, level: int = 6) -> bytes:
    co = zlib.compressobj(level=level, method=zlib.DEFLATED, wbits=-15)
    return co.compress(payload) + co.flush()

# ---- Commands ----

def cmd_extract(in_zhp: Path, out_dir: Path, encoding: str = "cp932"):
    """
    Extract using decoded names (directories + filenames), but store name_hex for exact repacking.
    """
    data = in_zhp.read_bytes()
    eocd = parse_eocd(data)
    out_dir.mkdir(parents=True, exist_ok=True)

    encodings = (encoding, "utf-8", "latin-1")

    manifest = {
        "source": in_zhp.name,
        "encoding_primary": encoding,
        "entries": []
    }

    for ent in iter_cd(data, eocd):
        lh = read_local_entry(data, ent["lhoff"])

        if lh["comp"] == 8:
            payload = inflate_raw(lh["comp_data"])
        elif lh["comp"] == 0:
            payload = lh["comp_data"]
        else:
            raise ValueError(f"Unsupported compression method {lh['comp']} at entry {ent['idx']}")

        rel = relpath_from_namehex(ent["name_hex"], encodings=encodings)
        out_path = out_dir / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(payload)

        manifest["entries"].append({
            "idx": ent["idx"],
            "name_hex": ent["name_hex"],
            "relative_path": rel.as_posix(),
            "mtime": ent["mtime"],
            "mdate": ent["mdate"],
            "eattr": ent["eattr"],
        })

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Extracted {len(manifest['entries'])} files to: {out_dir}")
    print(f"Wrote manifest: {out_dir/'manifest.json'}")

def cmd_repack(template_zhp: Path, extracted_dir: Path, out_zhp: Path):
    """
    Repack using the template's entry order and the manifest's name_hex bytes.
    """
    tdata = template_zhp.read_bytes()
    eocd = parse_eocd(tdata)

    manifest_path = extracted_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Missing manifest: {manifest_path} (run extract first)")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    by_idx = {e["idx"]: e for e in manifest["entries"]}

    out = bytearray()
    cd_records = []

    for ent in iter_cd(tdata, eocd):
        m = by_idx.get(ent["idx"])
        if not m:
            raise KeyError(f"Missing manifest entry for idx {ent['idx']}")

        src_path = extracted_dir / Path(m["relative_path"])
        if not src_path.exists() or src_path.is_dir():
            raise FileNotFoundError(f"Missing file for idx {ent['idx']}: {src_path}")

        payload = src_path.read_bytes()
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        comp = deflate_raw(payload, level=6)

        name_bytes = bytes.fromhex(m["name_hex"])
        lh_off = len(out)
        
        ver_need = 20
        flag     = 0
        method   = 8
        mtime    = m["mtime"]
        mdate    = m["mdate"]

        out += LH_STRUCT.pack(LH_SIG, ver_need, flag, method, mtime, mdate,
                              crc, len(comp), len(payload),
                              len(name_bytes), 0)
        out += name_bytes
        out += comp

        cd_records.append({
            "name": name_bytes,
            "ver_made": 20,
            "ver_need": 20,
            "flag": 0,
            "method": 8,
            "mtime": mtime,
            "mdate": mdate,
            "crc": crc,
            "csize": len(comp),
            "usize": len(payload),
            "eattr": m["eattr"],
            "lh_off": lh_off
        })

    cd_off = len(out)

    for r in cd_records:
        out += CD_STRUCT.pack(
            CD_SIG,
            r["ver_made"], r["ver_need"], r["flag"], r["method"],
            r["mtime"], r["mdate"],
            r["crc"], r["csize"], r["usize"],
            len(r["name"]), 0, 0,
            0, 0, r["eattr"],
            r["lh_off"]
        )
        out += r["name"]

    cd_size = len(out) - cd_off

    out += struct.pack(
        "<4s4H2LH",
        EOCD_SIG,
        0, 0,
        len(cd_records), len(cd_records),
        cd_size, cd_off,
        0
    )

    out_zhp.write_bytes(out)
    print(f"Wrote: {out_zhp}")
    print(f"Entries: {len(cd_records)}  CD size: {cd_size}  Total bytes: {len(out)}")

def usage():
    print("Usage:")
    print("  python zhp_tool.py extract <Resource.zhp> <out_dir> [--encoding cp932]")
    print("  python zhp_tool.py repack  <template Resource.zhp> <extracted_dir> <out.zhp>")
    sys.exit(1)

def main(argv):
    if len(argv) < 2:
        usage()

    cmd = argv[1].lower()

    if cmd == "extract":
        if len(argv) not in (4, 6):
            usage()
        in_zhp = Path(argv[2])
        out_dir = Path(argv[3])
        enc = "cp932"
        if len(argv) == 6:
            if argv[4] != "--encoding":
                usage()
            enc = argv[5]
        cmd_extract(in_zhp, out_dir, encoding=enc)
        return

    if cmd == "repack":
        if len(argv) != 5:
            usage()
        template = Path(argv[2])
        extracted = Path(argv[3])
        out_zhp = Path(argv[4])
        cmd_repack(template, extracted, out_zhp)
        return

    usage()

if __name__ == "__main__":
    main(sys.argv)
