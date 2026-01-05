import os
import sys
import argparse
import subprocess
import json
import shutil
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

def run_command(cmd, verbose=False, stream_output=False):
    """
    Runs a shell command.
    verbose: If True, prints the command being run.
    stream_output: If True, prints stdout line-by-line in real-time.
    """
    if verbose:
        print(f"Running: {cmd}", flush=True)
        
    start_time = time.time()
    
    if stream_output:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        stdout_lines = []
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                print(line.rstrip(), flush=True)
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
        print(f"Error running command: {cmd}", flush=True)
        if not stream_output:
            print(f"STDOUT: {result_stdout}", flush=True)
        print(f"STDERR: {result_stderr}", flush=True)
        return False
        
    return True

def merge_databases(main_db, worker_dbs):
    print(f"Merging {len(worker_dbs)} worker databases into {main_db}...", flush=True)
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
            print(f"Warning: Worker DB {worker_db} not found.", flush=True)
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
            print(f"Error merging {worker_db}: {e}", flush=True)
            
    conn.close()
    print(f"Merged {count} worker databases.", flush=True)

def print_performance_summary(stats):
    print("\n" + "="*60)
    print(f"{'PARALLEL EXPORT PERFORMANCE SUMMARY':^60}")
    print("="*60)
    
    total_time = stats['total_time']
    master_time = stats['master_time']
    worker_time = stats['worker_time']
    merge_time = stats['merge_time']
    total_funcs = stats['total_funcs']
    workers = stats['workers']
    
    print(f"{'Total Time':<30} : {total_time:.2f}s")
    print(f"{'  - Analysis (Master)':<30} : {master_time:.2f}s")
    print(f"{'  - Export (Workers)':<30} : {worker_time:.2f}s")
    print(f"{'  - Merge':<30} : {merge_time:.2f}s")
    print("-" * 60)
    print(f"{'Total Functions':<30} : {total_funcs}")
    print(f"{'Worker Threads':<30} : {workers}")
    
    avg_speed = 0
    if total_time > 0:
        avg_speed = total_funcs / total_time
        
    worker_speed = 0
    if worker_time > 0:
        worker_speed = total_funcs / worker_time

    print(f"{'Overall Speed':<30} : {avg_speed:.2f} funcs/sec")
    print(f"{'Worker Export Speed':<30} : {worker_speed:.2f} funcs/sec")
    print("="*60 + "\n")

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
        
    print(f"Input: {input_path}")
    print(f"Output: {output_db}")
    print(f"Workers: {args.workers}")
    
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
        print("\n[Step 1/4] Running Master (Analysis & Metadata)...")
        master_start = time.time()
        
        funcs_json = os.path.join(temp_dir, "funcs.json")
        master_cmd = f"python ida-export-db.py \"{input_path}\" --output \"{output_db}\" --parallel-master --dump-funcs \"{funcs_json}\""
        if args.fast:
            master_cmd += " --fast"
            
        # We generally want to see master output to know analysis is progressing
        # But user wants less "useless" logs. 
        # If we hide it, user sees nothing during analysis.
        # Let's show it but rely on ida-export-db.py being cleaner.
        if not run_command(master_cmd, verbose=False, stream_output=True):
            print("Master step failed. Aborting.")
            return
            
        stats['master_time'] = time.time() - master_start
            
        if not os.path.exists(funcs_json):
            print("Error: Function list was not generated.")
            return
            
        # Step 2: Split Work
        print("\n[Step 2/4] Splitting work...")
        with open(funcs_json, 'r') as f:
            all_funcs = json.load(f)
            
        total_funcs = len(all_funcs)
        stats['total_funcs'] = total_funcs
        print(f"Total functions: {total_funcs}")
        
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
            worker_files.append((chunk_file, worker_db))
            
        # Step 3: Run Workers
        print(f"\n[Step 3/4] Launching {len(worker_files)} workers...")
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
            print("Warning: No IDB file found. Workers will try to open binary directly (might cause locking issues).")
            
        worker_cmds = []
        for i, (chunk_file, worker_db) in enumerate(worker_files):
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
            worker_cmds.append(cmd)

        # Run workers
        # For workers, we set verbose=True so we see the command, but stream_output=False
        # to avoid spamming stdout with interleaved logs.
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(run_command, cmd, False, False) for cmd in worker_cmds]
            results = [f.result() for f in futures]
            
        stats['worker_time'] = time.time() - worker_start
            
        if not all(results):
            print("Some workers failed.")
            
        # Step 4: Merge Results
        print("\n[Step 4/4] Merging results...")
        merge_start = time.time()
        
        worker_dbs = [w_db for _, w_db in worker_files]
        merge_databases(output_db, worker_dbs)
        
        stats['merge_time'] = time.time() - merge_start
        stats['total_time'] = time.time() - stats['start_time']
        
        print(f"\nSuccess! Full export saved to {output_db}")
        
        # Print Performance Summary
        print_performance_summary(stats)
        
    finally:
        # Cleanup
        print("Cleaning up temporary files...")
        try:
             # shutil.rmtree(temp_dir) 
             pass
        except:
             pass

if __name__ == "__main__":
    main()
