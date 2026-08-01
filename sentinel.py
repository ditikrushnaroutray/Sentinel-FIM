import time
import logging
import hashlib
import json
import os
import argparse
import sys
import signal
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# 1. Setup Forensic Logging
logging.basicConfig(
    filename='sentinelaudit.log',
    level=logging.WARNING,
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

BASELINE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.json")
IGNORE_PATHS = ["/etc/shadow", "/etc/gshadow"]

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