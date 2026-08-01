import time
import logging
import hashlib
import json
import os
import argparse
import sys
import signal
import psutil
import threading
import select
from datetime import datetime
import collections
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# 1. Setup Forensic Logging
logging.basicConfig(
    filename='sentinelaudit.log',
    level=logging.WARNING,
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINE_FILE = os.path.join(BASE_DIR, "baseline.json")
WHITELIST_FILE = os.path.join(BASE_DIR, "whitelist.txt")
ANOMALIES_FILE = os.path.join(BASE_DIR, "anomalies.txt")

IGNORE_PATHS = ["/etc/shadow", "/etc/gshadow"]

PIPE_OUT = "/tmp/sentinel_pipe_out"
PIPE_IN = "/tmp/sentinel_pipe_in"

anomaly_queue = collections.deque()

def setup_pipes():
    for pipe in [PIPE_OUT, PIPE_IN]:
        if not os.path.exists(pipe):
            os.mkfifo(pipe)

def cleanup_pipes():
    for pipe in [PIPE_OUT, PIPE_IN]:
        if os.path.exists(pipe):
            try:
                os.remove(pipe)
            except Exception:
                pass

def read_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return set()
    with open(WHITELIST_FILE, "r") as f:
        return set([line.strip() for line in f if line.strip()])

def add_to_whitelist(name):
    wl = read_whitelist()
    if name not in wl:
        with open(WHITELIST_FILE, "a") as f:
            f.write(f"{name}\n")

def log_anomaly(name, pid, action):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entry = f"[{now}] {name} | PID: {pid} | {action}\n"
    with open(ANOMALIES_FILE, "a") as f:
        f.write(entry)

def compute_hash(file_path):
    """Computes SHA-256 hash of a file."""
    if file_path in IGNORE_PATHS:
        return None
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def load_baseline():
    """Loads baseline.json if it exists, else returns {}."""
    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_baseline(baseline_dict):
    """Writes the dictionary to baseline.json."""
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline_dict, f, indent=4)

def build_baseline(directory):
    """Recursively walks directory, computes hashes, and returns a dictionary."""
    baseline = {}
    for root, dirs, files in os.walk(directory):
        for name in files:
            file_path = os.path.join(root, name)
            if os.path.islink(file_path):
                continue
            file_hash = compute_hash(file_path)
            if file_hash:
                baseline[file_path] = file_hash
    return baseline

def ipc_worker():
    while True:
        if anomaly_queue:
            data = anomaly_queue.popleft()
            pid = data["pid"]
            name = data["name"]
            
            try:
                fd_out = os.open(PIPE_OUT, os.O_RDWR | os.O_NONBLOCK)
                with os.fdopen(fd_out, 'w') as pipe:
                    pipe.write(json.dumps(data) + "\n")
                    pipe.flush()
            except OSError:
                # If pipe fails, we just lose this event for the UI, but we shouldn't crash
                continue
            
            try:
                fd_in = os.open(PIPE_IN, os.O_RDWR | os.O_NONBLOCK)
                ready = select.select([fd_in], [], [], 60)
                if ready[0]:
                    with os.fdopen(fd_in, 'r') as pipe:
                        resp_str = pipe.readline().strip()
                        if resp_str:
                            resp = json.loads(resp_str)
                            decision = resp.get("decision")
                            if decision == "allow":
                                add_to_whitelist(name)
                                log_anomaly(name, pid, "Allowed by user")
                            elif decision == "kill":
                                try:
                                    psutil.Process(pid).kill()
                                except psutil.NoSuchProcess:
                                    pass
                                log_anomaly(name, pid, "Killed by user")
                            elif decision == "ignore":
                                pass
                else:
                    os.close(fd_in)
                    print(f"[!] UI response timed out for {name} (PID: {pid}). Skipping.")
                    logging.warning(f"UI TIMEOUT: {name} (PID: {pid}) skipped.")
            except Exception as e:
                print(f"[!] Error reading response: {e}")
        else:
            time.sleep(1)

def process_monitor():
    seen_pids = set(psutil.pids())
    
    while True:
        time.sleep(2)
        current_pids = set(psutil.pids())
        new_pids = current_pids - seen_pids
        
        whitelist = read_whitelist()
        
        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                cmd = proc.cmdline()
                
                if name in whitelist:
                    continue
                
                term = proc.terminal()
                if not term:
                    exts = ['.sh', '.py', '.rb', '.pl', '.js', '.php', '.lua']
                    cmd_str = " ".join(cmd)
                    if any(ext in cmd_str for ext in exts):
                        data = {
                            "pid": pid,
                            "name": name,
                            "path": proc.exe() if proc.exe() else name,
                            "user": proc.username(),
                            "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "command": cmd_str
                        }
                        anomaly_queue.append(data)
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        seen_pids = current_pids

class FIMHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.baseline = load_baseline()

    def check_integrity(self, file_path):
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return
            
        current_hash = compute_hash(file_path)
        if current_hash is None:
            return

        if file_path not in self.baseline:
            print(f"🚨 [CREATED] Rogue file detected: {file_path}")
            logging.warning(f"NEW_FILE_DETECTED: {file_path}")
        else:
            old_hash = self.baseline[file_path]
            if current_hash != old_hash:
                print(f"⚠️ [MODIFIED] Hash mismatch on: {file_path}")
                logging.warning(f"INTEGRITY VIOLATION: {file_path} (old: {old_hash[:8]}..., new: {current_hash[:8]}...)")

    def on_modified(self, event):
        if not event.is_directory:
            self.check_integrity(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.check_integrity(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"🗑️ [DELETED] Critical file removed: {event.src_path}")
            if event.src_path in self.baseline:
                logging.warning(f"FILE_DELETED: {event.src_path}")
            else:
                logging.warning(f"FILE_DELETED (Not in baseline): {event.src_path}")

    def on_moved(self, event):
        if not event.is_directory:
            print(f"🔄 [MOVED] File moved from {event.src_path} to {event.dest_path}")
            logging.warning(f"FILE_MOVED: {event.src_path} -> {event.dest_path}")
            self.check_integrity(event.dest_path)

observer = None

def signal_handler(sig, frame):
    print("\n[+] Shutting down Sentinel-FIM...")
    if observer:
        observer.stop()
        observer.join()
    cleanup_pipes()
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel-FIM: File Integrity Monitor")
    parser.add_argument('--init-baseline', action='store_true', help='Initialize baseline hashes for all files in targetdir')
    parser.add_argument('--update-baseline', action='store_true', help='Update baseline hashes for changed files in targetdir')
    parser.add_argument('--target', type=str, default='/etc', help='Target directory to monitor')
    args = parser.parse_args()

    targetdir = args.target

    # Setup Graceful Shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    setup_pipes()

    if args.init_baseline:
        print(f"[+] Building baseline for {targetdir}...")
        baseline_data = build_baseline(targetdir)
        save_baseline(baseline_data)
        print(f"[✓] Baseline saved to {BASELINE_FILE} ({len(baseline_data)} files)")
    elif args.update_baseline:
        print(f"[+] Updating baseline for {targetdir}...")
        baseline_data = load_baseline()
        updated_count = 0
        new_baseline_data = build_baseline(targetdir)
        for path, new_hash in new_baseline_data.items():
            if path not in baseline_data or baseline_data[path] != new_hash:
                baseline_data[path] = new_hash
                updated_count += 1
        save_baseline(baseline_data)
        print(f"[✓] Baseline updated in {BASELINE_FILE} ({updated_count} files modified/added, {len(baseline_data)} total)")
    else:
        # Start Process Monitor Thread
        pm_thread = threading.Thread(target=process_monitor, daemon=True)
        pm_thread.start()
        
        # Start IPC Worker Thread
        ipc_thread = threading.Thread(target=ipc_worker, daemon=True)
        ipc_thread.start()
        
        eventhandler = FIMHandler()
        observer = Observer()
        observer.schedule(eventhandler, targetdir, recursive=True)
        
        print(f"🛡️ Sentinel-FIM Engine Active.")
        print(f"👀 Monitoring critical directory: {targetdir}")
        print("Press Ctrl+C to stop...")
        observer.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            signal_handler(signal.SIGINT, None)