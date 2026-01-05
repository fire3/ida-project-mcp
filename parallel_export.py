import os
import sys
import argparse
import subprocess
import json
import shutil
import sqlite3
import time
import threading
from concurrent.futures import ThreadPoolExecutor

PRINT_LOCK = threading.Lock()

def _now_ts():
    return time.strftime("%H:%M:%S", time.localtime())

def _print_line(line):
    with PRINT_LOCK:
        print(line, flush=True)

def host_log(msg):
    _print_line(f"[HOST {_now_ts()}] {msg}")

def run_command(cmd, stream_output=False, prefix=None):
    if prefix:
        host_log(f"{prefix} Starting...")
    else:
        host_log("Starting command...")
        
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
                    _print_line(f"{prefix} {stripped}")
                else:
                    _print_line(stripped)
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
            host_log(f"{prefix} Failed (exit={returncode}, {duration:.2f}s).")
        else:
            host_log(f"Command failed (exit={returncode}, {duration:.2f}s).")
        if not stream_output:
            _print_line(result_stdout.rstrip())
        _print_line(result_stderr.rstrip())
        return {"ok": False, "duration": duration, "returncode": returncode, "stdout": result_stdout, "stderr": result_stderr}
        
    if prefix:
        host_log(f"{prefix} Done ({duration:.2f}s).")
    else:
        host_log(f"Done ({duration:.2f}s).")
    return {"ok": True, "duration": duration, "returncode": returncode, "stdout": result_stdout, "stderr": result_stderr}

def merge_databases(main_db, worker_dbs):
    host_log(f"Merging {len(worker_dbs)} worker databases into {main_db}...")
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
            host_log(f"Warning: Worker DB {worker_db} not found.")
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
            host_log(f"Error merging {worker_db}: {e}")
            
    conn.close()
    host_log(f"Merged {count} worker databases.")

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

    _print_line("")
    _print_line("=" * 72)
    _print_line(f"{'FINAL EXPORT PERFORMANCE SUMMARY':^72}")
    _print_line("=" * 72)
    _print_line(f"{'Total Time':<28}: {total_time:>10.2f}s")
    _print_line(f"{'Master (Step 1)':<28}: {master_time:>10.2f}s")
    _print_line(f"{'Workers (Step 3)':<28}: {worker_time:>10.2f}s")
    _print_line(f"{'Merge (Step 4)':<28}: {merge_time:>10.2f}s")
    _print_line("-" * 72)
    _print_line(f"{'Total Functions':<28}: {total_funcs:>10}")
    _print_line(f"{'Worker Threads':<28}: {workers:>10}")
    _print_line(f"{'Overall Speed':<28}: {overall_speed:>10.2f} funcs/sec")
    _print_line(f"{'Worker Speed':<28}: {worker_speed:>10.2f} funcs/sec")
    if attempted:
        _print_line(f"{'Pseudocode Attempted':<28}: {attempted:>10}")
        _print_line(f"{'Pseudocode Decompiled':<28}: {decompiled:>10}")
        _print_line(f"{'Pseudocode Failed':<28}: {failed:>10}")
        _print_line(f"{'Pseudocode Speed':<28}: {pseudo_speed:>10.2f} funcs/sec")

    if master_perf and master_perf.get("timer", {}).get("steps"):
        _print_line("-" * 72)
        _print_line("Master Step Breakdown:")
        for step in master_perf["timer"]["steps"]:
            name = step.get("name", "")
            dur = float(step.get("duration", 0.0))
            _print_line(f"  {name:<26} {dur:>10.2f}s")

    if worker_perfs:
        _print_line("-" * 72)
        _print_line("Worker Pseudocode Breakdown:")
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
            _print_line(
                f"  Worker {idx:<3} {pseudocode_dur:>7.2f}s  funcs={attempted_i:<5} ok={decompiled_i:<5} fail={failed_i:<5} thunk={thunks_i:<4} lib={library_i:<4} none={none_i:<4} nofunc={nofunc_i:<4} rate={rate_i:>7.2f}/s {range_str}".rstrip()
            )
            if failed_i and top_errors_i:
                for entry in top_errors_i[:3]:
                    err = str(entry.get("error", ""))
                    cnt = int(entry.get("count", 0))
                    _print_line(f"           {cnt}x {err}")

    _print_line("=" * 72)
    _print_line("")

def main():
    parser = argparse.ArgumentParser(description="Parallel IDA Pro Export")
    parser.add_argument("input_file", help="Path to input binary file")
    parser.add_argument("-j", "--workers", type=int, default=4, help="Number of parallel workers (default: 4)")
    parser.add_argument("-o", "--output", help="Path to output SQLite database")
    parser.add_argument("--fast", action="store_true", help="Enable fast analysis mode")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output for workers")
    
    args = parser.parse_args()
    
    input_path = os.path.abspath(args.input_file)
    if not os.path.exists(input_path):
        print(f"Error: Input file '{input_path}' not found.")
        sys.exit(1)
        
    if args.output:
        output_db = os.path.abspath(args.output)
    else:
        output_db = os.path.splitext(input_path)[0] + ".db"
        
    host_log(f"Input  : {input_path}")
    host_log(f"Output : {output_db}")
    host_log(f"Workers: {args.workers}")
    
    # Setup temporary directory
    temp_dir = os.path.join(os.path.dirname(output_db), "ida_parallel_temp")
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir)
    
    stats = {
        'start_time': time.time(),
        'workers': args.workers,
        'total_funcs': 0
    }
    
    try:
        # Step 1: Run Master (Export Metadata + Dump Functions)
        host_log("[Step 1/4] Running Master (Analysis & Metadata)")
        master_start = time.time()
        
        funcs_json = os.path.join(temp_dir, "funcs.json")
        master_perf_json = os.path.join(temp_dir, "perf_master.json")
        master_cmd = f"python ida-export-db.py \"{input_path}\" --output \"{output_db}\" --parallel-master --dump-funcs \"{funcs_json}\" --perf-json \"{master_perf_json}\" --no-perf-report"
        if args.fast:
            master_cmd += " --fast"
            
        result = run_command(master_cmd, stream_output=True, prefix="[MASTER]")
        if not result["ok"]:
            host_log("Master step failed. Aborting.")
            return
            
        stats['master_time'] = time.time() - master_start
            
        if not os.path.exists(funcs_json):
            print("Error: Function list was not generated.")
            return
            
        # Step 2: Split Work
        host_log("[Step 2/4] Splitting work")
        with open(funcs_json, 'r') as f:
            all_funcs = json.load(f)
            
        total_funcs = len(all_funcs)
        stats['total_funcs'] = total_funcs
        host_log(f"Total functions: {total_funcs}")
        
        if total_funcs == 0:
            print("No functions found. Nothing to parallelize.")
            return

        chunk_size = (total_funcs + args.workers - 1) // args.workers
        chunks = [all_funcs[i:i + chunk_size] for i in range(0, total_funcs, chunk_size)]
        
        worker_files = []
        for i, chunk in enumerate(chunks):
            chunk_file = os.path.join(temp_dir, f"funcs_worker_{i}.json")
            worker_db = os.path.join(temp_dir, f"worker_{i}.db")
            with open(chunk_file, 'w') as f:
                json.dump(chunk, f)
            worker_files.append((chunk_file, worker_db, len(chunk)))
            
        # Step 3: Run Workers
        host_log(f"[Step 3/4] Launching {len(worker_files)} workers")
        worker_start = time.time()
        
        # We need to be careful with IDB locking.
        # Strategy: Copy the `.i64` or `.idb` file (created by master) to temp dir for each worker.
        
        base_name = os.path.splitext(input_path)[0]
        idb_exts = [".i64", ".idb"]
        existing_idb = None
        for ext in idb_exts:
            if os.path.exists(base_name + ext):
                existing_idb = base_name + ext
                break
        
        if not existing_idb:
            host_log("Warning: No IDB file found. Workers will try to open binary directly.")
            
        worker_cmds = []
        worker_perf_paths = []
        for i, (chunk_file, worker_db, chunk_size) in enumerate(worker_files):
            worker_input = input_path
            
            if existing_idb:
                # Copy IDB for this worker
                ext = os.path.splitext(existing_idb)[1]
                worker_idb = os.path.join(temp_dir, f"worker_{i}{ext}")
                try:
                    if not os.path.exists(worker_idb):
                        shutil.copy2(existing_idb, worker_idb)
                    worker_input = worker_idb
                except Exception as e:
                    print(f"Failed to copy IDB for worker {i}: {e}. Using original input.")

            cmd = f"python ida-export-db.py \"{worker_input}\" --output \"{worker_db}\" --parallel-worker \"{chunk_file}\""
            if args.fast:
                cmd += " --fast"
            perf_json = os.path.join(temp_dir, f"perf_worker_{i}.json")
            cmd += f" --perf-json \"{perf_json}\" --no-perf-report"
            worker_cmds.append(cmd)
            worker_perf_paths.append(perf_json)
            host_log(f"Worker {i}: funcs={chunk_size} db={worker_db}")

        # Run workers
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = []
            for i, cmd in enumerate(worker_cmds):
                futures.append(executor.submit(run_command, cmd, True, f"[W{i}]"))
            results = [f.result() for f in futures]
            
        stats['worker_time'] = time.time() - worker_start
            
        if not all(r["ok"] for r in results):
            host_log("Some workers failed.")
            
        # Step 4: Merge Results
        host_log("[Step 4/4] Merging results")
        merge_start = time.time()
        
        worker_dbs = [w_db for _, w_db, _ in worker_files]
        merge_databases(output_db, worker_dbs)
        
        stats['merge_time'] = time.time() - merge_start
        stats['total_time'] = time.time() - stats['start_time']
        
        host_log(f"Success! Full export saved to {output_db}")
        
        master_perf = _load_perf_json(master_perf_json)
        worker_perfs = []
        for p in worker_perf_paths:
            wp = _load_perf_json(p)
            if wp:
                worker_perfs.append(wp)
        print_full_performance_summary(stats, master_perf, worker_perfs)
        
    finally:
        # Cleanup
        try:
             shutil.rmtree(temp_dir) 
             pass
        except:
             pass

if __name__ == "__main__":
    main()
