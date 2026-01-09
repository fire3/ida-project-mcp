import os
import sys
import json
import time
import hashlib
import argparse
import subprocess
import shutil
from dataclasses import dataclass


def _now_ts():
    return time.strftime("%H:%M:%S", time.localtime())


def _sha256_prefix(path, n=8):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()[:n]


def _safe_makedirs(path):
    os.makedirs(path, exist_ok=True)


def _is_within_dir(path, root_dir):
    path = os.path.realpath(os.path.abspath(path))
    root_dir = os.path.realpath(os.path.abspath(root_dir))
    try:
        common = os.path.commonpath([path, root_dir])
    except Exception:
        return False
    return common == root_dir


@dataclass(frozen=True)
class ElfIdentity:
    elf_class: int
    elf_data: int
    e_machine: int


def _read_exact(f, size):
    b = f.read(size)
    if len(b) != size:
        raise EOFError(f"short read: want={size} got={len(b)}")
    return b


def _u16(b, off, endian):
    if endian == 1:
        return int.from_bytes(b[off:off + 2], "little")
    if endian == 2:
        return int.from_bytes(b[off:off + 2], "big")
    raise ValueError("invalid endian")


def _u32(b, off, endian):
    if endian == 1:
        return int.from_bytes(b[off:off + 4], "little")
    if endian == 2:
        return int.from_bytes(b[off:off + 4], "big")
    raise ValueError("invalid endian")


def _u64(b, off, endian):
    if endian == 1:
        return int.from_bytes(b[off:off + 8], "little")
    if endian == 2:
        return int.from_bytes(b[off:off + 8], "big")
    raise ValueError("invalid endian")


def read_elf_identity(path):
    with open(path, "rb") as f:
        ident = _read_exact(f, 64)
    if ident[0:4] != b"\x7fELF":
        return None
    elf_class = ident[4]
    elf_data = ident[5]
    if elf_class not in (1, 2):
        return None
    e_machine = _u16(ident, 18, elf_data)
    return ElfIdentity(elf_class=elf_class, elf_data=elf_data, e_machine=e_machine)


def _parse_elf_header_fields(hdr, elf_class, elf_data):
    if elf_class == 1:
        e_phoff = _u32(hdr, 28, elf_data)
        e_phentsize = _u16(hdr, 42, elf_data)
        e_phnum = _u16(hdr, 44, elf_data)
        return e_phoff, e_phentsize, e_phnum
    e_phoff = _u64(hdr, 32, elf_data)
    e_phentsize = _u16(hdr, 54, elf_data)
    e_phnum = _u16(hdr, 56, elf_data)
    return e_phoff, e_phentsize, e_phnum


def _parse_phdr(buf, elf_class, elf_data):
    if elf_class == 1:
        p_type = _u32(buf, 0, elf_data)
        p_offset = _u32(buf, 4, elf_data)
        p_vaddr = _u32(buf, 8, elf_data)
        p_filesz = _u32(buf, 16, elf_data)
        p_memsz = _u32(buf, 20, elf_data)
        return {
            "p_type": p_type,
            "p_offset": p_offset,
            "p_vaddr": p_vaddr,
            "p_filesz": p_filesz,
            "p_memsz": p_memsz,
        }
    p_type = _u32(buf, 0, elf_data)
    p_offset = _u64(buf, 8, elf_data)
    p_vaddr = _u64(buf, 16, elf_data)
    p_filesz = _u64(buf, 32, elf_data)
    p_memsz = _u64(buf, 40, elf_data)
    return {
        "p_type": p_type,
        "p_offset": p_offset,
        "p_vaddr": p_vaddr,
        "p_filesz": p_filesz,
        "p_memsz": p_memsz,
    }


def _vaddr_to_offset(phdrs, vaddr):
    for ph in phdrs:
        if ph["p_type"] != 1:
            continue
        start = ph["p_vaddr"]
        end = start + ph["p_memsz"]
        if start <= vaddr < end:
            return ph["p_offset"] + (vaddr - start)
    return None


def read_elf_needed(path):
    with open(path, "rb") as f:
        hdr = _read_exact(f, 64)
        if hdr[0:4] != b"\x7fELF":
            return []
        elf_class = hdr[4]
        elf_data = hdr[5]
        if elf_class not in (1, 2) or elf_data not in (1, 2):
            return []
        e_phoff, e_phentsize, e_phnum = _parse_elf_header_fields(hdr, elf_class, elf_data)
        if e_phoff == 0 or e_phnum == 0 or e_phentsize == 0:
            return []
        phdrs = []
        f.seek(e_phoff)
        for _ in range(e_phnum):
            ph_buf = _read_exact(f, e_phentsize)
            phdrs.append(_parse_phdr(ph_buf, elf_class, elf_data))

        dyn = None
        for ph in phdrs:
            if ph["p_type"] == 2:
                dyn = ph
                break
        if not dyn or dyn["p_filesz"] == 0:
            return []

        f.seek(dyn["p_offset"])
        dyn_bytes = _read_exact(f, dyn["p_filesz"])

        dt_needed = []
        dt_strtab = None
        dt_strsz = None
        idx = 0
        if elf_class == 1:
            ent_size = 8
            while idx + ent_size <= len(dyn_bytes):
                tag = int.from_bytes(dyn_bytes[idx:idx + 4], "little" if elf_data == 1 else "big", signed=True)
                val = int.from_bytes(dyn_bytes[idx + 4:idx + 8], "little" if elf_data == 1 else "big", signed=False)
                idx += ent_size
                if tag == 0:
                    break
                if tag == 1:
                    dt_needed.append(val)
                elif tag == 5:
                    dt_strtab = val
                elif tag == 10:
                    dt_strsz = val
        else:
            ent_size = 16
            while idx + ent_size <= len(dyn_bytes):
                tag = int.from_bytes(dyn_bytes[idx:idx + 8], "little" if elf_data == 1 else "big", signed=True)
                val = int.from_bytes(dyn_bytes[idx + 8:idx + 16], "little" if elf_data == 1 else "big", signed=False)
                idx += ent_size
                if tag == 0:
                    break
                if tag == 1:
                    dt_needed.append(val)
                elif tag == 5:
                    dt_strtab = val
                elif tag == 10:
                    dt_strsz = val

        if not dt_needed or dt_strtab is None:
            return []
        strtab_off = _vaddr_to_offset(phdrs, dt_strtab)
        if strtab_off is None:
            return []

        f.seek(strtab_off)
        if dt_strsz is not None and dt_strsz > 0:
            strtab = _read_exact(f, dt_strsz)
        else:
            strtab = f.read(1024 * 1024)

    needed_names = []
    for off in dt_needed:
        if off >= len(strtab):
            continue
        end = strtab.find(b"\x00", off)
        if end == -1:
            continue
        try:
            s = strtab[off:end].decode("utf-8", errors="replace")
        except Exception:
            continue
        if s:
            needed_names.append(s)
    return needed_names


def build_basename_index(scan_dir):
    mapping = {}
    for root, _, files in os.walk(scan_dir):
        for fn in files:
            full = os.path.join(root, fn)
            base = os.path.basename(full)
            mapping.setdefault(base, []).append(full)
    return mapping


def resolve_recursive_dependencies(scan_dir, target_path):
    scan_dir = os.path.abspath(scan_dir)
    target_path = os.path.abspath(target_path)
    idx = build_basename_index(scan_dir)

    resolved_map = {}  # name -> path
    visited_paths = set()
    queue = []

    # Start with target
    visited_paths.add(target_path)
    queue.append(target_path)

    while queue:
        curr_path = queue.pop(0)
        curr_id = read_elf_identity(curr_path)
        needed = read_elf_needed(curr_path)

        for name in needed:
            if name in resolved_map:
                continue

            candidates = idx.get(name, [])
            best = None
            if curr_id:
                for c in candidates:
                    cid = read_elf_identity(c)
                    if cid and cid == curr_id:
                        best = c
                        break
            if not best and candidates:
                best = candidates[0]

            resolved_map[name] = best
            if best and best not in visited_paths:
                visited_paths.add(best)
                queue.append(best)

    return [{"name": k, "path": v} for k, v in resolved_map.items()]


def _stream_subprocess(cmd, cwd, on_line):
    p = subprocess.Popen(
        cmd,
        cwd=cwd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    try:
        while True:
            line = p.stdout.readline()
            if not line and p.poll() is not None:
                break
            if line:
                on_line(line.rstrip("\n"))
    finally:
        rc = p.wait()
    return rc


def run_parallel_export(project_root, target_path, output_db, workers, on_line):
    parallel_path = os.path.join(project_root, "parallel_export.py")
    cmd = f"python \"{parallel_path}\" \"{target_path}\" -j {int(workers)} -o \"{output_db}\" --save-idb \"{target_path}\""
    return _stream_subprocess(cmd, cwd=project_root, on_line=on_line)


def _copy_to_out_dir(src_path, out_dir):
    src_path = os.path.abspath(src_path)
    out_dir = os.path.abspath(out_dir)
    dst_path = os.path.join(out_dir, os.path.basename(src_path))
    if os.path.abspath(dst_path) == src_path:
        return dst_path
    shutil.copy2(src_path, dst_path)
    return dst_path


def _detect_idb_path(binary_path):
    for ext in (".i64", ".idb"):
        p = binary_path + ext
        if os.path.exists(p):
            return p
    return None


def export_bundle(scan_dir, out_dir, target_path, workers, on_line):
    scan_dir = os.path.abspath(scan_dir)
    out_dir = os.path.abspath(out_dir)
    target_path = os.path.abspath(target_path)

    if not os.path.exists(target_path):
        raise FileNotFoundError(target_path)
    if not os.path.isdir(scan_dir):
        raise NotADirectoryError(scan_dir)
    if not _is_within_dir(target_path, scan_dir):
        raise ValueError("target_path_not_in_scan_dir")

    _safe_makedirs(out_dir)

    resolved = resolve_recursive_dependencies(scan_dir, target_path)

    plan = [{"role": "main", "name": os.path.basename(target_path), "path": target_path}]
    for r in resolved:
        if r.get("path"):
            plan.append({"role": "dep", "name": r["name"], "path": r["path"]})
        else:
            plan.append({"role": "dep_missing", "name": r["name"], "path": None})

    index = {
        "created_at": int(time.time()),
        "target": {"name": os.path.basename(target_path), "db": None},
        "dependencies": [],
    }

    project_root = os.path.dirname(os.path.abspath(__file__))

    for item in plan:
        if not item.get("path"):
            if item["role"] == "dep_missing":
                index["dependencies"].append({"name": item["name"], "db": None, "idb": None})
            continue

        src_path = os.path.abspath(item["path"])
        name = os.path.basename(src_path)
        out_bin = _copy_to_out_dir(src_path, out_dir)
        on_line(f"[BUNDLE {_now_ts()}] copy {name} -> {out_bin}")

        db_name = f"{name}.{_sha256_prefix(src_path)}.db"
        out_db = os.path.join(out_dir, db_name)
        on_line(f"[BUNDLE {_now_ts()}] exporting {name} -> {out_db}")
        rc = run_parallel_export(project_root, out_bin, out_db, workers, on_line)
        status = "ok" if rc == 0 else f"failed_exit_{rc}"
        out_idb = _detect_idb_path(out_bin) if status == "ok" else None

        if item["role"] == "main":
            index["target"]["db"] = os.path.basename(out_db) if out_db else None
            index["target"]["idb"] = os.path.basename(out_idb) if out_idb else None
        else:
            index["dependencies"].append({
                "name": item["name"],
                "db": os.path.basename(out_db) if out_db else None,
                "idb": os.path.basename(out_idb) if out_idb else None
            })

    index_path = os.path.join(out_dir, "export_index.json")
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    on_line(f"[BUNDLE {_now_ts()}] index -> {index_path}")
    return index_path


def main():
    parser = argparse.ArgumentParser(description="Bulk wrapper for parallel_export.py")
    parser.add_argument("--scan-dir", help="Directory to scan for target and libraries", required=True)
    parser.add_argument("--out-dir", help="Directory to write output db files", required=True)
    parser.add_argument("--target", help="Main program path (must be under scan-dir)", required=True)
    parser.add_argument("-j", "--workers", type=int, default=4, help="parallel_export workers")
    args = parser.parse_args()

    def on_line(s):
        print(s, flush=True)

    try:
        export_bundle(args.scan_dir, args.out_dir, args.target, args.workers, on_line)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()

