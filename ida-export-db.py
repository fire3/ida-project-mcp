import os
import sys
import argparse
import time

# Ensure local modules can be imported
script_dir = os.path.dirname(os.path.abspath(__file__))
idalib_dir = os.path.join(script_dir, "ida-project-mcp")
if idalib_dir not in sys.path:
    sys.path.insert(0, idalib_dir)

import ida_utils
from binary_database import BinaryDatabase
from ida_exporter import IDAExporter

# Try to import IDA modules
try:
    import idapro
except ImportError:
    idapro = None

try:
    import ida_auto
    import ida_pro
    import ida_ida
    import idc
    import ida_nalt
except ImportError:
    print("Error: This script must be run within IDA Pro.")
    sys.exit(1)

def main():
    # Parse arguments
    # Note: When running in IDA, sys.argv might contain IDA's arguments.
    # We need to filter or handle this. idc.ARGV might be better if available, 
    # but argparse can work if we are careful or use a separator.
    # For now, we assume standard usage or that the user passes args after a script separator if needed.
    
    parser = argparse.ArgumentParser(description="Export IDA Pro database to SQLite binary.db")
    # Make input_file optional because inside IDA we already have a file open
    parser.add_argument("input_file", nargs='?', help="Path to input binary file (optional if running in IDA)")
    parser.add_argument("-o", "--output", help="Path to output SQLite database (default: binary.db in same dir)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--fast", action="store_true", help="Enable fast analysis mode (disable some heavy analysis steps)")
    
    # In IDA, argv[0] is the executable or the script. 
    # If run via "File > Script file", sys.argv is usually just the script path (or empty in some versions).
    # If run via command line `idat -S...`, args are tricky.
    # We'll try to parse known args.
    args, unknown = parser.parse_known_args()

    # Initialize helpers
    logger = ida_utils.Logger(verbose=args.verbose)
    timer = ida_utils.PerformanceTimer()

    # Initialize IDA if needed
    opened_db = False
    if args.input_file and idapro:
        logger.log(f"Initializing IDA for {args.input_file}...")
        try:
            idapro.open_database(args.input_file, run_auto_analysis=False)
            opened_db = True
        except Exception as e:
            logger.log(f"Failed to open database: {e}")
            sys.exit(1)

    logger.log("Starting export script...")
    
    # Determine output path
    if args.output:
        db_path = os.path.abspath(args.output)
    else:
        # Default to input file name + .db
        # We can get the input file path from IDA
        # ida_ida.inf_get_input_file_path() doesn't exist in all versions or APIs.
        # ida_nalt.get_input_file_path() is the standard way.
        root_filename = ida_nalt.get_input_file_path()
        if not root_filename and args.input_file:
            root_filename = args.input_file
            
        if root_filename:
             db_path = os.path.splitext(root_filename)[0] + ".db"
        else:
             # Fallback or error if no input file is known
             logger.log("Error: No input file provided or detected. Please specify an input file or run within an active IDA session.")
             # We should probably exit or raise an error, but let's try to proceed carefully or exit.
             # If we are in IDA with no file open, we can't do much.
             sys.exit(1)

    logger.log(f"Output Database: {db_path}")

    # Handle Fast Analysis Setting
    if args.fast:
        logger.log("Fast analysis mode enabled. Disabling heavy analysis steps...")
        af = ida_ida.inf_get_af()
        # Disable AF_LVAR (0x20), AF_TRACE (0x2000), AF_FTAIL (0x10000)
        disable_mask = 0x20 | 0x2000 | 0x10000
        new_af = af & ~disable_mask
        ida_ida.inf_set_af(new_af)
        logger.log(f"Analysis flags updated: {hex(af)} -> {hex(new_af)}")

    # Auto Analysis
    logger.log("Waiting for auto-analysis...")
    monitor = ida_utils.AutoAnalysisMonitor(logger.log)
    monitor.hook()
    
    analysis_start = timer.start_step("AutoAnalysis")
    ida_auto.auto_wait()
    timer.end_step("AutoAnalysis")
    
    monitor.unhook()
    logger.log("Auto-analysis finished.")

    # Export Process
    try:
        db = BinaryDatabase(db_path, logger)
        db.connect()
        db.create_schema()
        
        exporter = IDAExporter(db, logger, timer, input_file=root_filename)
        exporter.export_all()
        
        db.close()
        logger.log("Export completed successfully.")
        
        # Print Performance Report
        report = timer.get_report()
        logger.log(report)
        
    except Exception as e:
        logger.log(f"Export failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Exit IDA if running in batch mode or if we opened the DB
        if ida_pro.qexit:
             # Check if we are in batch mode or if we launched IDA ourselves
             if opened_db or idc.batch(0) == 1:
                 logger.log("Exiting IDA...")
                 ida_pro.qexit(0)

if __name__ == "__main__":
    main()
