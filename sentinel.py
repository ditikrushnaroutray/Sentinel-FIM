import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# 1. Setup Forensic Logging
logging.basicConfig(
    filename='sentinelaudit.log',
    level=logging.WARNING,
    format='%(asctime)s - [SECURITY ALERT] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class FIMHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            print(f"⚠️ [MODIFIED] Unauthorized change to: {event.src_path}")
            logging.warning(f"Modified: {event.src_path}")

    def on_created(self, event):
        if not event.is_directory:
            print(f"🚨 [CREATED] Rogue file detected: {event.src_path}")
            logging.warning(f"Created: {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"🗑️ [DELETED] Critical file removed: {event.src_path}")
            logging.warning(f"Deleted: {event.src_path}")

if __name__ == "__main__":
    # 2. Target Directory mapped directly to the Linux brain
    targetdir = "/etc" 
    
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
        observer.stop()
        print("\n🛑 Sentinel offline.")
    
    observer.join()