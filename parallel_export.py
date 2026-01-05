import os
import sys
import argparse
import subprocess
import json
import shutil
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

def run_command(cmd, verbose=False):
    if verbose:
        print(f"Running: {cmd}", flush=True)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if verbose and result.stdout:
        print(f"STDOUT: {result.stdout}", flush=True)
    if result.returncode != 0:
        print(f"Error running command: {cmd}", flush=True)
        print(f"STDOUT: {result.stdout}", flush=True)
        print(f"STDERR: {result.stderr}", flush=True)
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
    
    for worker_db in worker_dbs:
        if not os.path.exists(worker_db):
            print(f"Warning: Worker DB {worker_db} not found.", flush=True)
            continue
            
        print(f"Merging {worker_db}...", flush=True)
        try:
            # Attach worker DB
            cursor.execute(f"ATTACH DATABASE '{worker_db}' AS worker")
            
            # Copy pseudocode
            cursor.execute("INSERT OR REPLACE INTO pseudocode SELECT * FROM worker.pseudocode")
            
            conn.commit()
            cursor.execute("DETACH DATABASE worker")
            print("  Success", flush=True)
        except Exception as e:
            print(f"Error merging {worker_db}: {e}", flush=True)
            
    conn.close()
    print("Merge completed.", flush=True)

def main():
    parser = argparse.ArgumentParser(description="Parallel IDA Pro Export")
    parser.add_argument("input_file", help="Path to input binary file")
    parser.add_argument("-j", "--workers", type=int, default=4, help="Number of parallel workers (default: 4)")
    parser.add_argument("-o", "--output", help="Path to output SQLite database")
    parser.add_argument("--fast", action="store_true", help="Enable fast analysis mode")
    
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
    
    try:
        # Step 1: Run Master (Export Metadata + Dump Functions)
        print("\n[Step 1/4] Running Master (Analysis & Metadata)...")
        funcs_json = os.path.join(temp_dir, "funcs.json")
        master_cmd = f"python ida-export-db.py \"{input_path}\" --output \"{output_db}\" --parallel-master --dump-funcs \"{funcs_json}\""
        if args.fast:
            master_cmd += " --fast"
            
        if not run_command(master_cmd, verbose=True):
            print("Master step failed. Aborting.")
            return
            
        if not os.path.exists(funcs_json):
            print("Error: Function list was not generated.")
            return
            
        # Step 2: Split Work
        print("\n[Step 2/4] Splitting work...")
        with open(funcs_json, 'r') as f:
            all_funcs = json.load(f)
            
        total_funcs = len(all_funcs)
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
                    shutil.copy2(existing_idb, worker_idb)
                    worker_input = worker_idb
                    # print(f"Worker {i} using IDB copy: {worker_input}")
                except Exception as e:
                    print(f"Failed to copy IDB for worker {i}: {e}. Using original input.")

            cmd = f"python ida-export-db.py \"{worker_input}\" --output \"{worker_db}\" --parallel-worker \"{chunk_file}\""
            if args.fast:
                cmd += " --fast"
            worker_cmds.append(cmd)

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(run_command, cmd, True) for cmd in worker_cmds]
            results = [f.result() for f in futures]
            
        if not all(results):
            print("Some workers failed.")
            
        # Step 4: Merge Results
        print("\n[Step 4/4] Merging results...")
        worker_dbs = [w_db for _, w_db in worker_files]
        merge_databases(output_db, worker_dbs)
        
        print(f"\nSuccess! Full export saved to {output_db}")
        
    finally:
        # Cleanup
        print("Cleaning up temporary files...")
        # shutil.rmtree(temp_dir) # Keep for debugging if needed, or uncomment
        # For now, let's keep it safe and not delete immediately if user wants to inspect
        pass

if __name__ == "__main__":
    main()
