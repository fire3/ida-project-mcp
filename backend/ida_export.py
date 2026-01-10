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
from concurrent.futures import ThreadPoolExecutor

# =============================================================================
# Import Setup
# =============================================================================

# Ensure local imports work
current_dir = os.path.dirname(os.path.abspath(__file__))
lib_dir = os.path.join(current_dir, "ida-project-mcp")
if lib_dir not in sys.path:
    sys.path.insert(0, lib_dir)

try:
    from elf_service import ElfService
except ImportError:
    print("Error: Could not import ElfService from ida-project-mcp")
    sys.exit(1)

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

def _load_perf_json(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None

# =============================================================================
# Export Orchestrator
# =============================================================================

class ExportOrchestrator:
    def __init__(self, workers=4, verbose=False, show_perf_summary=False):
        self.workers = workers
        self.verbose = verbose
        self.show_perf_summary = show_perf_summary
        self.logger = _default_logger

    def run_command(self, cmd, stream_output=False, prefix=None):
        if prefix:
            self.logger(f"{prefix} Starting...")
        else:
            self.logger("Starting command...")
            
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
                self.logger(f"{prefix} Failed (exit={returncode}, {duration:.2f}s).")
            else:
                self.logger(f"Command failed (exit={returncode}, {duration:.2f}s).")
            if not stream_output:
                _plain_logger(result_stdout.rstrip())
            _plain_logger(result_stderr.rstrip())
            return {"ok": False, "duration": duration, "returncode": returncode, "stdout": result_stdout, "stderr": result_stderr}
            
        if prefix:
            self.logger(f"{prefix} Done ({duration:.2f}s).")
        else:
            self.logger(f"Done ({duration:.2f}s).")
        return {"ok": True, "duration": duration, "returncode": returncode, "stdout": result_stdout, "stderr": result_stderr}

    def merge_databases(self, main_db, worker_dbs):
        self.logger(f"Merging {len(worker_dbs)} worker databases into {main_db}...")
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
                self.logger(f"Warning: Worker DB {worker_db} not found.")
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
                self.logger(f"Error merging {worker_db}: {e}")
                
        conn.close()
        self.logger(f"Merged {count} worker databases.")

    def print_full_performance_summary(self, parallel_stats, master_perf, worker_perfs):
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

    def _run_master_analysis(self, master_input, output_db, temp_dir, save_idb=None):
        """
        Step 1: Run Master (Export Metadata + Dump Functions)
        """
        self.logger("[Step 1/4] Running Master (Analysis & Metadata)")
        master_start = time.time()
        
        funcs_json = os.path.join(temp_dir, "funcs.json")
        analysis_base = os.path.join(temp_dir, "analysis")
        if save_idb:
            analysis_base = os.path.abspath(save_idb)
            low = analysis_base.lower()
            if low.endswith(".i64") or low.endswith(".idb"):
                analysis_base = os.path.splitext(analysis_base)[0]
        
        master_perf_json = os.path.join(temp_dir, "perf_master.json")
        
        # NOTE: We assume ida-export-worker.py is in the same directory as this script
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        ida_export_script = os.path.join(current_script_dir, "ida-export-worker.py")
        
        master_cmd = f"python \"{ida_export_script}\" \"{master_input}\" --output \"{output_db}\" --parallel-master --dump-funcs \"{funcs_json}\" --save-idb \"{analysis_base}\" --perf-json \"{master_perf_json}\" --no-perf-report --fast"
            
        result = self.run_command(master_cmd, stream_output=True, prefix="[MASTER]")
        
        if not result["ok"]:
            self.logger("Master step failed. Aborting.")
            return None
            
        if not os.path.exists(funcs_json):
            self.logger("Error: Function list was not generated.")
            return None

        return {
            "duration": time.time() - master_start,
            "funcs_json": funcs_json,
            "analysis_base": analysis_base,
            "master_perf_json": master_perf_json
        }

    def _split_work(self, funcs_json, temp_dir):
        """
        Step 2: Split Work
        """
        self.logger("[Step 2/4] Splitting work")
        try:
            with open(funcs_json, 'r') as f:
                all_funcs = json.load(f)
        except Exception as e:
            self.logger(f"Error reading funcs.json: {e}")
            return None
            
        total_funcs = len(all_funcs)
        self.logger(f"Total functions: {total_funcs}")
        
        if total_funcs == 0:
            self.logger("No functions found. Nothing to parallelize.")
            return {"total_funcs": 0, "worker_files": []}

        # Balanced partitioning
        base_size = total_funcs // self.workers
        remainder = total_funcs % self.workers
        
        chunks = []
        start = 0
        for i in range(self.workers):
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
            
        return {"total_funcs": total_funcs, "worker_files": worker_files}

    def _run_workers(self, input_path, analysis_base, existing_idb, worker_files, temp_dir):
        """
        Step 3: Run Workers
        """
        self.logger(f"[Step 3/4] Launching {len(worker_files)} workers")
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
            self.logger("Warning: No analyzed IDB found from master. Workers will try to open binary directly.")
            
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        ida_export_script = os.path.join(current_script_dir, "ida-export-worker.py")
        
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
                    self.logger(f"Failed to copy IDB for worker {i}: {e}. Using original input.")

            cmd = f"python \"{ida_export_script}\" \"{worker_input}\" --output \"{worker_db}\" --parallel-worker \"{chunk_file}\""
            perf_json = os.path.join(temp_dir, f"perf_worker_{i}.json")
            cmd += f" --perf-json \"{perf_json}\" --no-perf-report"
            worker_cmds.append(cmd)
            worker_perf_paths.append(perf_json)
            self.logger(f"Worker {i}: funcs={chunk_size} db={worker_db}")

        # Run workers
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = []
            for i, cmd in enumerate(worker_cmds):
                futures.append(executor.submit(self.run_command, cmd, True, f"[W{i}]"))
            results = [f.result() for f in futures]
            
        duration = time.time() - worker_start
            
        if not all(r["ok"] for r in results):
            self.logger("Some workers failed.")
            
        return {
            "duration": duration,
            "results": results,
            "worker_perf_paths": worker_perf_paths
        }

    def process_single_file(self, input_path, output_db, save_idb=None):
        input_path = os.path.abspath(input_path)
        if not os.path.exists(input_path):
            self.logger(f"Error: Input file '{input_path}' not found.")
            return False

        if not output_db:
            output_db = os.path.splitext(input_path)[0] + ".db"
        
        output_db = os.path.abspath(output_db)
            
        if os.path.exists(output_db):
            self.logger(f"Target database already exists: {output_db}")
            self.logger("Skipping export.")
            return True
            
        self.logger(f"Input  : {input_path}")
        self.logger(f"Output : {output_db}")
        self.logger(f"Workers: {self.workers}")
        
        # Setup temporary directory
        temp_dir = os.path.join(os.path.dirname(output_db), f"ida_parallel_temp_{os.getpid()}_{int(time.time())}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)
        
        stats = {
            'start_time': time.time(),
            'workers': self.workers,
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
            # Step 1: Run Master
            master_res = self._run_master_analysis(existing_idb or input_path, output_db, temp_dir, save_idb)
            if not master_res:
                return False
            stats['master_time'] = master_res['duration']
            
            # Step 2: Split Work
            split_res = self._split_work(master_res['funcs_json'], temp_dir)
            if not split_res:
                return False
            stats['total_funcs'] = split_res['total_funcs']
            worker_files = split_res['worker_files']
            
            if not worker_files:
                # No functions to process, but metadata exported
                return True
                
            # Step 3: Run Workers
            worker_res = self._run_workers(
                input_path, 
                master_res['analysis_base'], 
                existing_idb, 
                worker_files, 
                temp_dir
            )
            stats['worker_time'] = worker_res['duration']
            
            # Step 4: Merge Results
            self.logger("[Step 4/4] Merging results")
            merge_start = time.time()
            
            worker_dbs_paths = [w_db for _, w_db, _ in worker_files]
            self.merge_databases(output_db, worker_dbs_paths)
            
            stats['merge_time'] = time.time() - merge_start
            stats['total_time'] = time.time() - stats['start_time']
            
            self.logger(f"Success! Full export saved to {output_db}")
            
            if self.show_perf_summary:
                master_perf = _load_perf_json(master_res['master_perf_json'])
                worker_perfs = []
                for p in worker_res['worker_perf_paths']:
                    wp = _load_perf_json(p)
                    if wp:
                        worker_perfs.append(wp)
                self.print_full_performance_summary(stats, master_perf, worker_perfs)
            return True
            
        finally:
            try:
                 shutil.rmtree(temp_dir) 
            except:
                 pass

    def process_directory(self, scan_dir, out_dir, target_binary):
        scan_dir = os.path.abspath(scan_dir)
        out_dir = os.path.abspath(out_dir)
        
        _safe_makedirs(out_dir)

        plan = []
        
        if not target_binary:
            self.logger("Error: target_binary is required for directory processing.")
            return

        # Dependency-based scan
        target_path = os.path.abspath(target_binary)
        if not os.path.exists(target_path):
            raise FileNotFoundError(target_path)
        if not _is_within_dir(target_path, scan_dir):
            raise ValueError("target_binary must be within scan_dir")
            
        self.logger(f"Resolving dependencies for {target_path} in {scan_dir}...")
        resolved = ElfService.resolve_recursive_dependencies(scan_dir, target_path)
        
        plan.append({"role": "main", "name": os.path.basename(target_path), "path": target_path})
        for r in resolved:
            if r.get("path"):
                plan.append({"role": "dep", "name": r["name"], "path": r["path"]})
            else:
                plan.append({"role": "dep_missing", "name": r["name"], "path": None})

        if not plan:
            self.logger("No files found to export.")
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
            self.logger(f"[BUNDLE] Copied {name} -> {out_bin}")

            db_name = f"{name}.{_sha256_prefix(src_path)}.db"
            out_db = os.path.join(out_dir, db_name)
            
            self.logger(f"[BUNDLE] Exporting {name} -> {out_db}")
            
            # Call single file process directly
            # We set save_idb to the binary path (so it saves .i64 next to the binary in out_dir)
            success = self.process_single_file(
                input_path=out_bin,
                output_db=out_db,
                save_idb=out_bin, # This will create .i64 next to the copied binary
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
        self.logger(f"[BUNDLE] Index saved to {index_path}")
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
    parser.add_argument("--perf-summary", action="store_true", help="Show performance summary")

    args = parser.parse_args()
    
    target_path = os.path.abspath(args.target)
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.")
        sys.exit(1)

    orchestrator = ExportOrchestrator(
        workers=args.workers,
        verbose=args.verbose,
        show_perf_summary=args.perf_summary
    )

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
            orchestrator.process_directory(
                scan_dir=scan_dir,
                out_dir=args.output,
                target_binary=target_path
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
        success = orchestrator.process_single_file(
            input_path=target_path,
            output_db=args.output,
            save_idb=None # Default to None (temp dir) for single mode
        )
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
