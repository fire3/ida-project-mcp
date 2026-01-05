import time
import sys
import math
from collections import Counter

# Try importing IDA modules, handle failure for non-IDA environments (e.g. testing)
try:
    import ida_kernwin
    import ida_idp
except ImportError:
    ida_kernwin = None
    ida_idp = None

class Logger:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.logs = []

    def log(self, msg, level=None):
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        if level:
            formatted_msg = f"[{timestamp}] [{level}] {msg}"
        else:
            formatted_msg = f"[{timestamp}] {msg}"
        self.logs.append(formatted_msg)
        
        if level:
            line = f"[IDA {timestamp}] [{level}] {msg}"
        else:
            line = f"[IDA {timestamp}] {msg}"

        print(line)
        sys.stdout.flush()
        
        # Always log to IDA output window if possible
        if ida_kernwin:
            try:
                ida_kernwin.msg(line + "\n")
            except:
                pass

class PerformanceTimer:
    def __init__(self):
        self.start_time = time.time()
        self.steps = []
        self.current_step_start = 0

    def start_step(self, name):
        self.current_step_start = time.time()
        return self.current_step_start

    def end_step(self, name):
        duration = time.time() - self.current_step_start
        self.steps.append((name, duration))
        return duration

    def get_report(self):
        total_time = time.time() - self.start_time
        report = ["\n" + "="*50]
        report.append("       PERFORMANCE SUMMARY       ")
        report.append("="*50)
        report.append(f"{'Step':<30} | {'Duration':<15}")
        report.append("-" * 48)
        
        for name, duration in self.steps:
            report.append(f"{name:<30} | {duration:.2f}s")
        
        report.append("-" * 48)
        report.append(f"{'Total Time':<30} | {total_time:.2f}s")
        report.append("="*50 + "\n")
        return "\n".join(report)

    def get_stats(self):
        total_time = time.time() - self.start_time
        return {
            "total_time": total_time,
            "steps": [{"name": name, "duration": duration} for name, duration in self.steps],
        }

class ProgressTracker:
    def __init__(self, total, log_func, prefix=""):
        self.total = total
        self.log_func = log_func
        self.prefix = prefix
        self.start_time = time.time()
        self.last_log_time = self.start_time
        self.count = 0
        
    def update(self, current_count=None, increment=1):
        if current_count is not None:
            self.count = current_count
        else:
            self.count += increment
            
        now = time.time()
        # Log every 2 seconds or if finished
        if now - self.last_log_time >= 2.0 or (self.total > 0 and self.count >= self.total):
            self.last_log_time = now
            self.report()
            
    def report(self):
        elapsed = time.time() - self.start_time
        if elapsed < 0.001: elapsed = 0.001
        
        # Calculate percentage
        percent = 0.0
        if self.total > 0:
            percent = (self.count / self.total) * 100.0
        if percent > 100.0: percent = 100.0
        
        # Calculate ETA
        eta_str = "??"
        if self.count > 0:
            rate = self.count / elapsed
            remaining = self.total - self.count
            if remaining < 0: remaining = 0
            eta_seconds = remaining / rate
            eta_str = f"{int(eta_seconds)}s"
            
        self.log_func(f"{self.prefix} Progress: {percent:.1f}% ({self.count}/{self.total}) - Elapsed: {int(elapsed)}s - ETA: {eta_str}")

class AutoAnalysisMonitor:
    def __init__(self, log_func):
        self.log = log_func
        self.count = 0
        self.last_time = time.time()
        self.start_time = time.time()
        self.hook_obj = None

    def hook(self):
        if ida_idp:
            # We need to define a class that inherits from IDB_Hooks dynamically or use the one if we can import it
            # Since we are in a util file, we can define the hook class here if ida_idp is available
            class _Hooks(ida_idp.IDB_Hooks):
                def __init__(self, monitor):
                    ida_idp.IDB_Hooks.__init__(self)
                    self.monitor = monitor
                def make_code(self, insn):
                    self.monitor.on_make_code(insn)
                    return 0
            
            self.hook_obj = _Hooks(self)
            self.hook_obj.hook()

    def unhook(self):
        if self.hook_obj:
            self.hook_obj.unhook()
            self.hook_obj = None

    def on_make_code(self, insn):
        self.count += 1
        if self.count % 1000 == 0:
            now = time.time()
            if now - self.last_time > 2.0:
                elapsed = now - self.start_time
                self.log(f"[Analysis] {self.count} instructions created. Elapsed: {int(elapsed)}s. Last EA: {hex(insn.ea)}")
                self.last_time = now

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
