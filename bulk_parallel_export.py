import os
import sys
import json
import time
import hashlib
import argparse
import subprocess
import threading
import shutil
from dataclasses import dataclass
from queue import Queue, Empty


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
        "scan_dir": scan_dir,
        "output_dir": out_dir,
        "target": {"db": None},
        "dependencies": [],
        "exports": [],
    }

    project_root = os.path.dirname(os.path.abspath(__file__))

    for item in plan:
        if not item.get("path"):
            if item["role"] == "dep_missing":
                index["dependencies"].append({"name": item["name"], "path": None, "db": None, "status": "missing"})
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

        record = {
            "role": item["role"],
            "name": item["name"],
            "db": out_db,
            "idb": out_idb,
            "status": status,
        }
        index["exports"].append(record)
        if item["role"] == "main":
            index["target"]["db"] = out_db
            index["target"]["idb"] = out_idb
        else:
            index["dependencies"].append({"name": item["name"], "db": out_db, "idb": out_idb, "status": status})

    index_path = os.path.join(out_dir, "export_index.json")
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    on_line(f"[BUNDLE {_now_ts()}] index -> {index_path}")
    return index_path


def _run_cli(args):
    def on_line(s):
        print(s, flush=True)

    export_bundle(args.scan_dir, args.out_dir, args.target, args.workers, on_line)


def _run_ui():
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
    except Exception:
        raise RuntimeError("tkinter_not_available")

    root = tk.Tk()
    root.title("Parallel Export Bundle")

    scan_var = tk.StringVar()
    out_var = tk.StringVar()
    target_var = tk.StringVar()
    workers_var = tk.StringVar(value="4")
    status_var = tk.StringVar(value="")

    q = Queue()
    running = {"v": False}

    def log_line(s):
        q.put(s)

    def pick_scan_dir():
        d = filedialog.askdirectory()
        if d:
            scan_var.set(d)

    def pick_out_dir():
        d = filedialog.askdirectory()
        if d:
            out_var.set(d)

    def pick_target():
        initial = scan_var.get() or None
        p = filedialog.askopenfilename(initialdir=initial)
        if p:
            target_var.set(p)

    def set_enabled(enabled):
        state = "normal" if enabled else "disabled"
        for w in (scan_entry, out_entry, target_entry, workers_entry, scan_btn, out_btn, target_btn, start_btn):
            w.configure(state=state)

    def worker_thread(scan_dir, out_dir, target_path, workers):
        try:
            idx = export_bundle(scan_dir, out_dir, target_path, workers, log_line)
            log_line(f"[BUNDLE {_now_ts()}] done: {idx}")
        except Exception as e:
            log_line(f"[BUNDLE {_now_ts()}] error: {e}")
        finally:
            q.put(("__done__", None))

    def start():
        if running["v"]:
            return
        scan_dir = scan_var.get().strip()
        out_dir = out_var.get().strip()
        target_path = target_var.get().strip()
        try:
            workers = int(workers_var.get().strip())
        except Exception:
            messagebox.showerror("Error", "workers必须是整数")
            return
        if not scan_dir or not out_dir or not target_path:
            messagebox.showerror("Error", "scan_dir/out_dir/target不能为空")
            return
        running["v"] = True
        set_enabled(False)
        status_var.set("running")
        t = threading.Thread(target=worker_thread, args=(scan_dir, out_dir, target_path, workers), daemon=True)
        t.start()

    def pump():
        changed = False
        try:
            while True:
                item = q.get_nowait()
                if isinstance(item, tuple) and item and item[0] == "__done__":
                    running["v"] = False
                    set_enabled(True)
                    status_var.set("idle")
                    continue
                text.insert("end", str(item) + "\n")
                text.see("end")
                changed = True
        except Empty:
            pass
        if changed:
            text.update_idletasks()
        root.after(100, pump)

    frm = ttk.Frame(root, padding=10)
    frm.grid(row=0, column=0, sticky="nsew")
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    frm.columnconfigure(1, weight=1)

    ttk.Label(frm, text="扫描目录").grid(row=0, column=0, sticky="w")
    scan_entry = ttk.Entry(frm, textvariable=scan_var)
    scan_entry.grid(row=0, column=1, sticky="ew", padx=(8, 8))
    scan_btn = ttk.Button(frm, text="选择", command=pick_scan_dir)
    scan_btn.grid(row=0, column=2, sticky="e")

    ttk.Label(frm, text="输出目录").grid(row=1, column=0, sticky="w", pady=(8, 0))
    out_entry = ttk.Entry(frm, textvariable=out_var)
    out_entry.grid(row=1, column=1, sticky="ew", padx=(8, 8), pady=(8, 0))
    out_btn = ttk.Button(frm, text="选择", command=pick_out_dir)
    out_btn.grid(row=1, column=2, sticky="e", pady=(8, 0))

    ttk.Label(frm, text="主程序目标").grid(row=2, column=0, sticky="w", pady=(8, 0))
    target_entry = ttk.Entry(frm, textvariable=target_var)
    target_entry.grid(row=2, column=1, sticky="ew", padx=(8, 8), pady=(8, 0))
    target_btn = ttk.Button(frm, text="选择", command=pick_target)
    target_btn.grid(row=2, column=2, sticky="e", pady=(8, 0))

    ttk.Label(frm, text="并发workers").grid(row=3, column=0, sticky="w", pady=(8, 0))
    workers_entry = ttk.Entry(frm, textvariable=workers_var, width=8)
    workers_entry.grid(row=3, column=1, sticky="w", padx=(8, 8), pady=(8, 0))

    start_btn = ttk.Button(frm, text="开始导出", command=start)
    start_btn.grid(row=3, column=2, sticky="e", pady=(8, 0))

    ttk.Label(frm, textvariable=status_var).grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 0))

    text = tk.Text(frm, height=22, width=120)
    text.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
    frm.rowconfigure(5, weight=1)

    status_var.set("idle")
    root.after(100, pump)
    root.mainloop()


def main():
    parser = argparse.ArgumentParser(description="Bulk wrapper for parallel_export.py")
    parser.add_argument("--scan-dir", help="Directory to scan for target and libraries")
    parser.add_argument("--out-dir", help="Directory to write output db files")
    parser.add_argument("--target", help="Main program path (must be under scan-dir)")
    parser.add_argument("-j", "--workers", type=int, default=4, help="parallel_export workers")
    parser.add_argument("--gui", action="store_true", help="Run in GUI mode")
    parser.add_argument("--no-ui", action="store_true", help="Deprecated (default is CLI)")
    args = parser.parse_args()

    if args.gui:
        try:
            _run_ui()
            return
        except Exception as e:
            print(f"UI unavailable ({e}). Falling back to CLI.", file=sys.stderr)

    if not args.scan_dir or not args.out_dir or not args.target:
        print("Error: --scan-dir --out-dir --target are required for CLI mode", file=sys.stderr)
        sys.exit(2)

    _run_cli(args)


if __name__ == "__main__":
    main()

