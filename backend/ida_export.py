import os
import sys
import json
import time
import hashlib
import argparse
import subprocess
import shutil
import sqlite3
import threading
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

# =============================================================================
# Shared Utilities & Logging
# =============================================================================

PRINT_LOCK = threading.Lock()

def _now_ts():
    return time.strftime("%H:%M:%S", time.localtime())

def _default_logger(msg):
    with PRINT_LOCK:
        print(f"[HOST {_now_ts()}] {msg}", flush=True)

def _plain_logger(msg):
    with PRINT_LOCK:
        print(msg, flush=True)

# =============================================================================
# ELF Analysis Utilities (from bulk_parallel_export.py)
# =============================================================================

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
    try:
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
    except Exception:
        return None

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
    try:
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
    except Exception:
        return []

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

# =============================================================================
# Single File Parallel Export Logic (from parallel_export.py)
# =============================================================================

def run_command(cmd, stream_output=False, prefix=None, logger=_default_logger):
    if prefix:
        logger(f"{prefix} Starting...")
    else:
        logger("Starting command...")
        
    start_time = time.time()
    
    if stream_output:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        stdout_lines = []
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                stripped = line.rstrip()
                if prefix:
                    with PRINT_LOCK:
                        print(f"{prefix} {stripped}", flush=True)
                else:
                    with PRINT_LOCK:
                        print(stripped, flush=True)
                stdout_lines.append(line)
        
        returncode = process.poll()
        result_stdout = "".join(stdout_lines)
        result_stderr = "" # Merged into stdout
    else:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        returncode = result.returncode
        result_stdout = result.stdout
        result_stderr = result.stderr
        
    duration = time.time() - start_time
    
    if returncode != 0:
        if prefix:
            logger(f"{prefix} Failed (exit={returncode}, {duration:.2f}s).")
        else:
            logger(f"Command failed (exit={returncode}, {duration:.2f}s).")
        if not stream_output:
            _plain_logger(result_stdout.rstrip())
        _plain_logger(result_stderr.rstrip())
        return {"ok": False, "duration": duration, "returncode": returncode, "stdout": result_stdout, "stderr": result_stderr}
        
    if prefix:
        logger(f"{prefix} Done ({duration:.2f}s).")
    else:
        logger(f"Done ({duration:.2f}s).")
    return {"ok": True, "duration": duration, "returncode": returncode, "stdout": result_stdout, "stderr": result_stderr}

def merge_databases(main_db, worker_dbs, logger=_default_logger):
    logger(f"Merging {len(worker_dbs)} worker databases into {main_db}...")
    conn = sqlite3.connect(main_db)
    cursor = conn.cursor()
    
    # Ensure pseudocode table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pseudocode (
            function_va INTEGER PRIMARY KEY,
            content TEXT
        )
    """)
    conn.commit()
    
    count = 0
    for worker_db in worker_dbs:
        if not os.path.exists(worker_db):
            logger(f"Warning: Worker DB {worker_db} not found.")
            continue
            
        try:
            # Attach worker DB
            cursor.execute(f"ATTACH DATABASE '{worker_db}' AS worker")
            
            # Copy pseudocode
            cursor.execute("INSERT OR REPLACE INTO pseudocode SELECT * FROM worker.pseudocode")
            
            conn.commit()
            cursor.execute("DETACH DATABASE worker")
            count += 1
        except Exception as e:
            logger(f"Error merging {worker_db}: {e}")
            
    conn.close()
    logger(f"Merged {count} worker databases.")

def _load_perf_json(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None

def print_full_performance_summary(parallel_stats, master_perf, worker_perfs):
    total_time = parallel_stats.get("total_time", 0.0)
    master_time = parallel_stats.get("master_time", 0.0)
    worker_time = parallel_stats.get("worker_time", 0.0)
    merge_time = parallel_stats.get("merge_time", 0.0)
    total_funcs = parallel_stats.get("total_funcs", 0)
    workers = parallel_stats.get("workers", 0)

    attempted = 0
    decompiled = 0
    failed = 0
    pseudocode_time = 0.0

    for wp in worker_perfs:
        try:
            t = wp.get("timer", {})
            pseudocode_step = None
            for step in t.get("steps", []):
                if step.get("name") == "Pseudocode":
                    pseudocode_step = step
                    break
            if pseudocode_step:
                pseudocode_time += float(pseudocode_step.get("duration", 0.0))

            ps = (wp.get("export", {}) or {}).get("pseudocode", {}) or {}
            attempted += int(ps.get("attempted", 0))
            decompiled += int(ps.get("decompiled", 0))
            failed += int(ps.get("failed", 0))
        except Exception:
            continue

    overall_speed = (total_funcs / total_time) if total_time else 0.0
    worker_speed = (total_funcs / worker_time) if worker_time else 0.0
    pseudo_speed = (attempted / pseudocode_time) if pseudocode_time else 0.0

    _plain_logger("")
    _plain_logger("=" * 72)
    _plain_logger(f"{'FINAL EXPORT PERFORMANCE SUMMARY':^72}")
    _plain_logger("=" * 72)
    _plain_logger(f"{'Total Time':<28}: {total_time:>10.2f}s")
    _plain_logger(f"{'Master (Step 1)':<28}: {master_time:>10.2f}s")
    _plain_logger(f"{'Workers (Step 3)':<28}: {worker_time:>10.2f}s")
    _plain_logger(f"{'Merge (Step 4)':<28}: {merge_time:>10.2f}s")
    _plain_logger("-" * 72)
    _plain_logger(f"{'Total Functions':<28}: {total_funcs:>10}")
    _plain_logger(f"{'Worker Threads':<28}: {workers:>10}")
    _plain_logger(f"{'Overall Speed':<28}: {overall_speed:>10.2f} funcs/sec")
    _plain_logger(f"{'Worker Speed':<28}: {worker_speed:>10.2f} funcs/sec")
    if attempted:
        _plain_logger(f"{'Pseudocode Attempted':<28}: {attempted:>10}")
        _plain_logger(f"{'Pseudocode Decompiled':<28}: {decompiled:>10}")
        _plain_logger(f"{'Pseudocode Failed':<28}: {failed:>10}")
        _plain_logger(f"{'Pseudocode Speed':<28}: {pseudo_speed:>10.2f} funcs/sec")

    if master_perf and master_perf.get("timer", {}).get("steps"):
        _plain_logger("-" * 72)
        _plain_logger("Master Step Breakdown:")
        for step in master_perf["timer"]["steps"]:
            name = step.get("name", "")
            dur = float(step.get("duration", 0.0))
            _plain_logger(f"  {name:<26} {dur:>10.2f}s")

    if worker_perfs:
        _plain_logger("-" * 72)
        _plain_logger("Worker Pseudocode Breakdown:")
        for idx, wp in enumerate(worker_perfs):
            ps = (wp.get("export", {}) or {}).get("pseudocode", {}) or {}
            attempted_i = int(ps.get("attempted", 0))
            decompiled_i = int(ps.get("decompiled", 0))
            failed_i = int(ps.get("failed", 0))
            thunks_i = int(ps.get("thunks", 0))
            library_i = int(ps.get("library", 0))
            nofunc_i = int(ps.get("nofunc", 0))
            none_i = int(ps.get("none", 0))
            min_ea_i = ps.get("min_ea", None)
            max_ea_i = ps.get("max_ea", None)
            top_errors_i = ps.get("top_errors", []) or []

            pseudocode_dur = 0.0
            for step in (wp.get("timer", {}) or {}).get("steps", []):
                if step.get("name") == "Pseudocode":
                    pseudocode_dur = float(step.get("duration", 0.0))
                    break
            rate_i = (attempted_i / pseudocode_dur) if pseudocode_dur else 0.0

            range_str = ""
            try:
                if min_ea_i is not None and max_ea_i is not None:
                    range_str = f"{hex(int(min_ea_i))}-{hex(int(max_ea_i))}"
            except Exception:
                range_str = ""
            _plain_logger(
                f"  Worker {idx:<3} {pseudocode_dur:>7.2f}s  funcs={attempted_i:<5} ok={decompiled_i:<5} fail={failed_i:<5} thunk={thunks_i:<4} lib={library_i:<4} none={none_i:<4} nofunc={nofunc_i:<4} rate={rate_i:>7.2f}/s {range_str}".rstrip()
            )
            if failed_i and top_errors_i:
                for entry in top_errors_i[:3]:
                    err = str(entry.get("error", ""))
                    cnt = int(entry.get("count", 0))
                    _plain_logger(f"           {cnt}x {err}")

    _plain_logger("=" * 72)
    _plain_logger("")

def process_single_file(input_path, output_db, workers, save_idb=None, verbose=False, logger=_default_logger):
    input_path = os.path.abspath(input_path)
    if not os.path.exists(input_path):
        logger(f"Error: Input file '{input_path}' not found.")
        return False

    if not output_db:
        output_db = os.path.splitext(input_path)[0] + ".db"
    
    output_db = os.path.abspath(output_db)
        
    if os.path.exists(output_db):
        logger(f"Target database already exists: {output_db}")
        logger("Skipping export.")
        return True
        
    logger(f"Input  : {input_path}")
    logger(f"Output : {output_db}")
    logger(f"Workers: {workers}")
    
    # Setup temporary directory
    temp_dir = os.path.join(os.path.dirname(output_db), f"ida_parallel_temp_{os.getpid()}_{int(time.time())}")
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir)
    
    stats = {
        'start_time': time.time(),
        'workers': workers,
        'total_funcs': 0
    }

    base_name = os.path.splitext(input_path)[0]
    existing_idb = None
    for candidate in [
        input_path + ".i64",
        input_path + ".idb",
        base_name + ".i64",
        base_name + ".idb",
    ]:
        if os.path.exists(candidate):
            existing_idb = candidate
            break
    
    try:
        # Step 1: Run Master (Export Metadata + Dump Functions)
        logger("[Step 1/4] Running Master (Analysis & Metadata)")
        master_start = time.time()
        
        funcs_json = os.path.join(temp_dir, "funcs.json")
        analysis_base = os.path.join(temp_dir, "analysis")
        if save_idb:
            analysis_base = os.path.abspath(save_idb)
            low = analysis_base.lower()
            if low.endswith(".i64") or low.endswith(".idb"):
                analysis_base = os.path.splitext(analysis_base)[0]
        
        master_perf_json = os.path.join(temp_dir, "perf_master.json")
        master_input = existing_idb or input_path
        
        # NOTE: We assume ida-export-worker.py is in the same directory as this script
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        ida_export_script = os.path.join(current_script_dir, "ida-export-worker.py")
        
        master_cmd = f"python \"{ida_export_script}\" \"{master_input}\" --output \"{output_db}\" --parallel-master --dump-funcs \"{funcs_json}\" --save-idb \"{analysis_base}\" --perf-json \"{master_perf_json}\" --no-perf-report --fast"
            
        result = run_command(master_cmd, stream_output=True, prefix="[MASTER]", logger=logger)
        if not result["ok"]:
            logger("Master step failed. Aborting.")
            return False
            
        stats['master_time'] = time.time() - master_start
            
        if not os.path.exists(funcs_json):
            logger("Error: Function list was not generated.")
            return False
            
        # Step 2: Split Work
        logger("[Step 2/4] Splitting work")
        with open(funcs_json, 'r') as f:
            all_funcs = json.load(f)
            
        total_funcs = len(all_funcs)
        stats['total_funcs'] = total_funcs
        logger(f"Total functions: {total_funcs}")
        
        if total_funcs == 0:
            logger("No functions found. Nothing to parallelize.")
            # Even if no functions, metadata might have been exported.
            return True

        # Balanced partitioning
        base_size = total_funcs // workers
        remainder = total_funcs % workers
        
        chunks = []
        start = 0
        for i in range(workers):
            size = base_size + (1 if i < remainder else 0)
            if size > 0:
                chunks.append(all_funcs[start : start + size])
                start += size
        
        worker_files = []
        for i, chunk in enumerate(chunks):
            chunk_file = os.path.join(temp_dir, f"funcs_worker_{i}.json")
            worker_db = os.path.join(temp_dir, f"worker_{i}.db")
            with open(chunk_file, 'w') as f:
                json.dump(chunk, f)
            worker_files.append((chunk_file, worker_db, len(chunk)))
            
        # Step 3: Run Workers
        logger(f"[Step 3/4] Launching {len(worker_files)} workers")
        worker_start = time.time()
        
        analyzed_idb = None
        for ext in [".i64", ".idb"]:
            candidate = analysis_base + ext
            if os.path.exists(candidate):
                analyzed_idb = candidate
                break
        if not analyzed_idb:
            analyzed_idb = existing_idb

        if not analyzed_idb:
            logger("Warning: No analyzed IDB found from master. Workers will try to open binary directly.")
            
        worker_cmds = []
        worker_perf_paths = []
        for i, (chunk_file, worker_db, chunk_size) in enumerate(worker_files):
            worker_input = input_path
            
            if analyzed_idb:
                # Copy IDB for this worker to avoid contention
                ext = os.path.splitext(analyzed_idb)[1]
                worker_idb = os.path.join(temp_dir, f"worker_{i}{ext}")
                try:
                    if not os.path.exists(worker_idb):
                        shutil.copy2(analyzed_idb, worker_idb)
                    worker_input = worker_idb
                except Exception as e:
                    logger(f"Failed to copy IDB for worker {i}: {e}. Using original input.")

            cmd = f"python \"{ida_export_script}\" \"{worker_input}\" --output \"{worker_db}\" --parallel-worker \"{chunk_file}\""
            if fast:
                cmd += " --fast"
            perf_json = os.path.join(temp_dir, f"perf_worker_{i}.json")
            cmd += f" --perf-json \"{perf_json}\" --no-perf-report"
            worker_cmds.append(cmd)
            worker_perf_paths.append(perf_json)
            logger(f"Worker {i}: funcs={chunk_size} db={worker_db}")

        # Run workers
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for i, cmd in enumerate(worker_cmds):
                futures.append(executor.submit(run_command, cmd, True, f"[W{i}]", logger))
            results = [f.result() for f in futures]
            
        stats['worker_time'] = time.time() - worker_start
            
        if not all(r["ok"] for r in results):
            logger("Some workers failed.")
            
        # Step 4: Merge Results
        logger("[Step 4/4] Merging results")
        merge_start = time.time()
        
        worker_dbs_paths = [w_db for _, w_db, _ in worker_files]
        merge_databases(output_db, worker_dbs_paths, logger=logger)
        
        stats['merge_time'] = time.time() - merge_start
        stats['total_time'] = time.time() - stats['start_time']
        
        logger(f"Success! Full export saved to {output_db}")
        
        master_perf = _load_perf_json(master_perf_json)
        worker_perfs = []
        for p in worker_perf_paths:
            wp = _load_perf_json(p)
            if wp:
                worker_perfs.append(wp)
        print_full_performance_summary(stats, master_perf, worker_perfs)
        return True
        
    finally:
        try:
             shutil.rmtree(temp_dir) 
        except:
             pass

# =============================================================================
# Bulk/Directory Processing Logic
# =============================================================================

def process_directory(scan_dir, out_dir, target_binary, workers, logger=_default_logger):
    scan_dir = os.path.abspath(scan_dir)
    out_dir = os.path.abspath(out_dir)
    
    _safe_makedirs(out_dir)

    plan = []
    
    if target_binary:
        # Dependency-based scan
        target_path = os.path.abspath(target_binary)
        if not os.path.exists(target_path):
            raise FileNotFoundError(target_path)
        if not _is_within_dir(target_path, scan_dir):
            raise ValueError("target_binary must be within scan_dir")
            
        logger(f"Resolving dependencies for {target_path} in {scan_dir}...")
        resolved = resolve_recursive_dependencies(scan_dir, target_path)
        
        plan.append({"role": "main", "name": os.path.basename(target_path), "path": target_path})
        for r in resolved:
            if r.get("path"):
                plan.append({"role": "dep", "name": r["name"], "path": r["path"]})
            else:
                plan.append({"role": "dep_missing", "name": r["name"], "path": None})
    else:
        # Simple bulk scan (all files in directory) - Not implemented in original, 
        # but requested "support scanning directory".
        # For now, let's just error if target is missing for bulk mode to stay safe,
        # OR we can iterate all files.
        # Given the original script was "bulk_parallel_export", it implies doing many.
        # But the logic was strictly dependency based.
        # Let's stick to dependency based if target is provided. 
        # If not, maybe we should just scan all ELFs?
        # For now, let's require target for dependency mode, or maybe user meant 
        # "process this directory" -> "process all binaries in it".
        # Let's implement a simple "scan all" if no target is provided.
        logger(f"Scanning directory {scan_dir} for all files (no target specified)...")
        for root, dirs, files in os.walk(scan_dir):
            for f in files:
                # Heuristic to find binaries? Or just try everything?
                # Let's try to detect ELF or PE header?
                # For now, let's just add everything that looks like a file and isn't .db/.idb/.i64
                path = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()
                if ext in ['.db', '.idb', '.i64', '.json', '.py', '.c', '.h', '.txt', '.md']:
                    continue
                # Maybe check executable bit or magic?
                # Let's just try read_elf_identity as a filter
                if read_elf_identity(path):
                    plan.append({"role": "standalone", "name": f, "path": path})

    if not plan:
        logger("No files found to export.")
        return

    index = {
        "created_at": int(time.time()),
        "target": {"name": None, "db": None},
        "dependencies": [],
        "standalone": []
    }
    
    if target_binary:
         index["target"]["name"] = os.path.basename(target_binary)

    for item in plan:
        if not item.get("path"):
            if item["role"] == "dep_missing":
                index["dependencies"].append({"name": item["name"], "db": None, "idb": None})
            continue

        src_path = os.path.abspath(item["path"])
        name = os.path.basename(src_path)
        
        # Copy binary to output dir
        out_bin = _copy_to_out_dir(src_path, out_dir)
        logger(f"[BUNDLE] Copied {name} -> {out_bin}")

        db_name = f"{name}.{_sha256_prefix(src_path)}.db"
        out_db = os.path.join(out_dir, db_name)
        
        logger(f"[BUNDLE] Exporting {name} -> {out_db}")
        
        # Call single file process directly
        # We set save_idb to the binary path (so it saves .i64 next to the binary in out_dir)
        success = process_single_file(
            input_path=out_bin,
            output_db=out_db,
            workers=workers,
            save_idb=out_bin, # This will create .i64 next to the copied binary
            verbose=False,
            logger=logger
        )
        
        status = "ok" if success else "failed"
        out_idb = _detect_idb_path(out_bin) if status == "ok" else None

        entry = {
            "name": item["name"],
            "db": os.path.basename(out_db) if out_db and status == "ok" else None,
            "idb": os.path.basename(out_idb) if out_idb else None
        }

        if item["role"] == "main":
            index["target"]["db"] = entry["db"]
            index["target"]["idb"] = entry["idb"]
        elif item["role"] in ("dep", "dep_missing"):
            index["dependencies"].append(entry)
        else:
            index["standalone"].append(entry)

    index_path = os.path.join(out_dir, "export_index.json")
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    logger(f"[BUNDLE] Index saved to {index_path}")
    return index_path

# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Unified IDA Pro Export Script")
    
    # New arguments structure
    parser.add_argument("target", help="Path to input binary file")
    parser.add_argument("-o", "--output", required=True, help="Output path (DB file for single mode, Directory for bulk mode)")
    parser.add_argument("--scan-dir", help="Directory to scan for dependencies (enables Bulk Mode)")
    parser.add_argument("-j", "--workers", type=int, default=4, help="Number of parallel workers (default: 4)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()
    
    target_path = os.path.abspath(args.target)
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.")
        sys.exit(1)

    # Determine mode based on arguments
    if args.scan_dir:
        # Bulk Mode
        scan_dir = os.path.abspath(args.scan_dir)
        if not os.path.isdir(scan_dir):
            print(f"Error: Scan directory '{scan_dir}' does not exist or is not a directory.")
            sys.exit(1)
        
        if not _is_within_dir(target_path, scan_dir):
            print(f"Error: Target binary '{target_path}' must be within scan directory '{scan_dir}' for bulk mode.")
            sys.exit(1)

        print(f"Mode: Bulk (Target: {target_path}, Scan: {scan_dir})")
        try:
            process_directory(
                scan_dir=scan_dir,
                out_dir=args.output,
                target_binary=target_path,
                workers=args.workers
            )
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
            
    else:
        # Single Mode
        if os.path.isdir(target_path):
            print(f"Error: Target '{target_path}' is a directory. For directory scanning, use --scan-dir.")
            sys.exit(1)
            
        print(f"Mode: Single (Target: {target_path})")
        success = process_single_file(
            input_path=target_path,
            output_db=args.output,
            workers=args.workers,
            save_idb=None, # Default to None (temp dir) for single mode
            verbose=args.verbose
        )
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
