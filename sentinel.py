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
import requests
import smtplib
from email.mime.text import MIMEText
from inotify_simple import INotify, flags

try:
    import tomllib
except ImportError:
    import tomli as tomllib

logging.basicConfig(
    filename='sentinelaudit.log',
    level=logging.WARNING,
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

PIPE_OUT = "/tmp/sentinel_pipe_out"
PIPE_IN = "/tmp/sentinel_pipe_in"

anomaly_queue = collections.deque()
alert_queue = collections.deque()
last_alert_time = {}
config = {}
shutdown_event = threading.Event()

DEFAULT_CONFIG = """monitored_dirs = ["/etc"]
ignored_dirs = ["/tmp/ignored", "/etc/shadow", "/etc/gshadow"]
ignore_extensions = [".log", ".tmp"]
whitelist_processes = ["bash", "python3", "node", "java"]
default_score = 5
min_score = 7

[alerts]
alert_min_score = 7
slack_webhook_url = ""
telegram_bot_token = ""
telegram_chat_id = ""
smtp_server = ""
smtp_port = 587
smtp_username = ""
smtp_password = ""
smtp_from = ""
smtp_to = ""

[threat_scores]
"/etc/passwd" = 10

[directory_scores]
"/tmp" = 8
"/var/log" = 2
"""

def load_config():
    global config
    if not os.path.exists('config.toml'):
        with open('config.toml', 'w') as f:
            f.write(DEFAULT_CONFIG)
            
    with open('config.toml', 'rb') as f:
        config = tomllib.load(f)
        
    config.setdefault('monitored_dirs', ["/etc"])
    config.setdefault('ignored_dirs', [])
    config.setdefault('ignore_extensions', [])
    config.setdefault('whitelist_processes', [])
    config.setdefault('default_score', 5)
    config.setdefault('min_score', 7)
    config.setdefault('threat_scores', {})
    config.setdefault('directory_scores', {})
    
    config.setdefault('alerts', {})
    alerts = config['alerts']
    alerts.setdefault('alert_min_score', config['min_score'])
    alerts.setdefault('slack_webhook_url', "")
    alerts.setdefault('telegram_bot_token', "")
    alerts.setdefault('telegram_chat_id', "")
    alerts.setdefault('smtp_server', "")
    alerts.setdefault('smtp_port', 587)
    alerts.setdefault('smtp_username', "")
    alerts.setdefault('smtp_password', "")
    alerts.setdefault('smtp_from', "")
    alerts.setdefault('smtp_to', "")

def calculate_score(path):
    _, ext = os.path.splitext(path)
    if ext in config['ignore_extensions']:
        return 0
        
    for d in config['ignored_dirs']:
        if path.startswith(d):
            return 0
            
    if path in config['threat_scores']:
        return config['threat_scores'][path]
        
    for d_path, score in config['directory_scores'].items():
        if path.startswith(d_path):
            return score
            
    return config['default_score']

def format_alert_message(data):
    action = data.get("action", "PROCESS_DETECTED").upper()
    if data["type"] == "process":
        return f"🚨 SENTINEL ALERT: {action}\nProcess: {data['name']}\nPID: {data['pid']}\nUser: {data.get('user', 'Unknown')}\nPath: {data['path']}\nScore: {data['score']}/10\nTime: {data['time']}\nCommand: {data.get('command', '')}"
    else:
        return f"🚨 SENTINEL ALERT: INTEGRITY_VIOLATION ({action})\nFile: {data['path']}\nScore: {data['score']}/10\nTime: {data['time']}"

def send_slack_alert(message, ident):
    url = config['alerts'].get('slack_webhook_url')
    if not url: return
    try:
        requests.post(url, json={"text": message}, timeout=5)
        logging.warning(f"ALERT SENT: [Slack] {ident}")
    except Exception as e:
        logging.warning(f"Slack alert failed: {e}")

def send_telegram_alert(message, ident):
    token = config['alerts'].get('telegram_bot_token')
    chat_id = config['alerts'].get('telegram_chat_id')
    if not token or not chat_id: return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        requests.post(url, json={"chat_id": chat_id, "text": message}, timeout=5)
        logging.warning(f"ALERT SENT: [Telegram] {ident}")
    except Exception as e:
        logging.warning(f"Telegram alert failed: {e}")

def send_email_alert(message, ident):
    alerts = config['alerts']
    server = alerts.get('smtp_server')
    if not server: return
    try:
        msg = MIMEText(message)
        msg['Subject'] = "🚨 Sentinel-FIM Security Alert"
        msg['From'] = alerts.get('smtp_from')
        msg['To'] = alerts.get('smtp_to')
        
        with smtplib.SMTP(server, alerts.get('smtp_port', 587)) as s:
            if alerts.get('smtp_port', 587) != 25:
                s.starttls()
            user = alerts.get('smtp_username')
            pwd = alerts.get('smtp_password')
            if user and pwd:
                s.login(user, pwd)
            s.send_message(msg)
        logging.warning(f"ALERT SENT: [Email] {ident}")
    except Exception as e:
        logging.warning(f"Email alert failed: {e}")

def alert_worker():
    while not shutdown_event.is_set():
        if alert_queue:
            data = alert_queue.popleft()
            message = format_alert_message(data)
            ident = data.get('path', data.get('name', 'Unknown'))
            send_slack_alert(message, ident)
            send_telegram_alert(message, ident)
            send_email_alert(message, ident)
        else:
            shutdown_event.wait(1)

def queue_alert_if_needed(data):
    if data['score'] < config['alerts']['alert_min_score']:
        return
        
    ident = data.get('path')
    now = time.time()
    
    if ident in last_alert_time:
        if now - last_alert_time[ident] < 60:
            return
            
    last_alert_time[ident] = now
    alert_queue.append(data)

def setup_pipes():
    for pipe in [PIPE_OUT, PIPE_IN]:
        if not os.path.exists(pipe):
            os.mkfifo(pipe)

def compute_hash(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def load_baseline():
    baseline_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'baseline.json')
    if os.path.exists(baseline_path):
        with open(baseline_path, 'r') as f:
            return json.load(f)
    return {}

def save_baseline(baseline_dict):
    baseline_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'baseline.json')
    with open(baseline_path, 'w') as f:
        json.dump(baseline_dict, f, indent=4)

def log_anomaly(identifier, action, decision, score=None):
    with open('anomalies.txt', 'a') as f:
        score_str = f"[Score: {score}] " if score is not None else ""
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {score_str}{identifier} | {action} | {decision}\n")

def check_integrity(file_path, action, baseline):
    score = calculate_score(file_path)
    if score < config['min_score']:
        return
        
    current_hash = compute_hash(file_path)
    if action != "deleted" and current_hash is None:
        return

    if action == "deleted":
        print(f"🗑️ [DELETED] File removed: {file_path}")
        logging.warning(f"FILE_DELETED: {file_path}")
        queue_file_anomaly(file_path, "deleted", score)
        return

    if file_path not in baseline:
        print(f"🚨 [CREATED] Rogue file detected: {file_path}")
        logging.warning(f"NEW_FILE_DETECTED: {file_path}")
        queue_file_anomaly(file_path, "created", score)
    else:
        old_hash = baseline[file_path]
        if current_hash != old_hash:
            print(f"⚠️ [MODIFIED] Hash mismatch on: {file_path}")
            logging.warning(f"INTEGRITY VIOLATION: {file_path} (old: {old_hash[:8]}..., new: {current_hash[:8]}...)")
            queue_file_anomaly(file_path, "modified", score)

def queue_file_anomaly(path, action, score):
    data = {
        "type": "file",
        "path": path,
        "action": action,
        "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "score": score
    }
    queue_alert_if_needed(data)
    anomaly_queue.append(data)

def inotify_monitor(targetdirs):
    inotify = INotify()
    watch_flags = flags.CREATE | flags.MODIFY | flags.DELETE | flags.MOVED_TO | flags.MOVED_FROM | flags.ISDIR
    wd_to_path = {}
    
    def add_watch_recursive(path):
        try:
            wd = inotify.add_watch(path, watch_flags)
            wd_to_path[wd] = path
            for entry in os.scandir(path):
                if entry.is_dir(follow_symlinks=False):
                    add_watch_recursive(entry.path)
        except OSError:
            pass

    for tdir in targetdirs:
        add_watch_recursive(tdir)
        
    while not shutdown_event.is_set():
        try:
            events = inotify.read(timeout=1000)
            baseline = load_baseline()
            for event in events:
                parent_path = wd_to_path.get(event.wd)
                if not parent_path:
                    continue
                file_path = os.path.join(parent_path, event.name)
                
                if event.mask & flags.ISDIR:
                    if (event.mask & flags.CREATE) or (event.mask & flags.MOVED_TO):
                        add_watch_recursive(file_path)
                    continue
                    
                if event.mask & flags.MODIFY:
                    check_integrity(file_path, "modified", baseline)
                elif (event.mask & flags.CREATE) or (event.mask & flags.MOVED_TO):
                    check_integrity(file_path, "created", baseline)
                elif (event.mask & flags.DELETE) or (event.mask & flags.MOVED_FROM):
                    check_integrity(file_path, "deleted", baseline)
                    
        except Exception as e:
            if not shutdown_event.is_set():
                shutdown_event.wait(1)

def process_monitor():
    seen_pids = set()
    for proc in psutil.process_iter(['pid', 'create_time']):
        if proc.info['pid'] < 100: continue
        seen_pids.add((proc.info['pid'], proc.info['create_time']))
        
    while not shutdown_event.is_set():
        shutdown_event.wait(3)
        current_pids = set()
        whitelist = config.get('whitelist_processes', [])
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'exe', 'terminal', 'create_time']):
                pid = proc.info['pid']
                if pid < 100:
                    continue
                    
                ctime = proc.info['create_time']
                ident = (pid, ctime)
                current_pids.add(ident)
                
                if ident not in seen_pids:
                    seen_pids.add(ident)
                    name = proc.info['name']
                    cmd = proc.info['cmdline'] or []
                    
                    if name in whitelist:
                        continue
                        
                    term = proc.info['terminal']
                    if not term:
                        exts = ['.sh', '.py', '.rb', '.pl', '.js', '.php', '.lua']
                        cmd_str = " ".join(cmd)
                        if any(ext in cmd_str for ext in exts):
                            script_path = proc.info['exe'] if proc.info['exe'] else name
                            score = calculate_score(script_path)
                            if score < config['min_score']:
                                continue
                                
                            data = {
                                "type": "process",
                                "pid": pid,
                                "name": name,
                                "path": script_path,
                                "user": proc.info['username'],
                                "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                "command": cmd_str,
                                "score": score
                            }
                            queue_alert_if_needed(data)
                            anomaly_queue.append(data)
                            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
        seen_pids = current_pids

def ipc_worker():
    while not shutdown_event.is_set():
        if anomaly_queue:
            data = anomaly_queue.popleft()
            try:
                with open(PIPE_OUT, "w") as pipe:
                    pipe.write(json.dumps(data) + "\n")
                    
                fd_in = os.open(PIPE_IN, os.O_RDWR | os.O_NONBLOCK)
                timeout = 60
                start_time = time.time()
                responded = False
                
                while not shutdown_event.is_set() and (time.time() - start_time) < timeout:
                    ready = select.select([fd_in], [], [], 1)
                    if ready[0]:
                        with os.fdopen(fd_in, 'r') as pipe:
                            resp_str = pipe.readline().strip()
                            if resp_str:
                                resp = json.loads(resp_str)
                                decision = resp.get("decision", "ignore")
                                
                                if data["type"] == "process":
                                    pid = data["pid"]
                                    if decision == "allow":
                                        config['whitelist_processes'].append(data["name"])
                                        log_anomaly(data["name"], "executed", "Allowed", data.get("score"))
                                    elif decision == "kill":
                                        try:
                                            p = psutil.Process(pid)
                                            p.terminate()
                                            log_anomaly(data["name"], "executed", "Killed", data.get("score"))
                                        except Exception as e:
                                            print(f"[!] Error killing PID {pid}: {e}")
                                    elif decision == "ignore":
                                        pass
                                        
                                elif data["type"] == "file":
                                    path = data["path"]
                                    action = data["action"]
                                    if decision == "allow":
                                        baseline = load_baseline()
                                        if action == "deleted":
                                            if path in baseline:
                                                del baseline[path]
                                        else:
                                            h = compute_hash(path)
                                            if h:
                                                baseline[path] = h
                                        save_baseline(baseline)
                                        log_anomaly(path, action, "Allowed/Baseline Updated", data.get("score"))
                                    elif decision == "delete":
                                        try:
                                            if os.path.exists(path):
                                                os.remove(path)
                                                log_anomaly(path, action, "Deleted by user", data.get("score"))
                                        except Exception as e:
                                            print(f"[!] Error deleting file: {e}")
                                    elif decision == "ignore":
                                        pass
                                responded = True
                                break
                                
                if not responded and not shutdown_event.is_set():
                    try:
                        os.close(fd_in)
                    except:
                        pass
                    ident = data.get('name') if data.get('type') == 'process' else data.get('path')
                    print(f"[!] UI response timed out for {ident}. Skipping.")
                    logging.warning(f"UI TIMEOUT: {ident} skipped.")
                    
            except Exception as e:
                print(f"[!] Error in IPC worker: {e}")
        else:
            shutdown_event.wait(1)

def signal_handler(sig, frame):
    print("\n[+] Shutting down Sentinel-FIM...")
    shutdown_event.set()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Sentinel-FIM")
    parser.add_argument('--target', type=str, default="/etc", help='Target directory to monitor')
    parser.add_argument('--init-baseline', action='store_true', help='Initialize baseline hashes for all files in targetdir')
    parser.add_argument('--update-baseline', action='store_true', help='Update baseline hashes for changed files')
    parser.add_argument('--profile', action='store_true', help='Run with cProfile for 60 seconds and output profiling data')
    args = parser.parse_args()

    load_config()
    targetdir = args.target
    
    if args.init_baseline or args.update_baseline:
        baseline = load_baseline() if args.update_baseline else {}
        for root, _, files in os.walk(targetdir):
            for file in files:
                path = os.path.join(root, file)
                h = compute_hash(path)
                if h:
                    baseline[path] = h
        save_baseline(baseline)
        print(f"[+] Baseline initialized/updated for {targetdir}")
        sys.exit(0)

    setup_pipes()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if not os.path.exists('anomalies.txt'):
        with open('anomalies.txt', 'w') as f:
            f.write("# Sentinel-FIM Anomalies History\n")

    def run_daemon():
        print("🛡️ Sentinel-FIM Engine Active.")
        print(f"👀 Monitoring: {targetdir}")
        
        proc_thread = threading.Thread(target=process_monitor, daemon=True)
        proc_thread.start()
        
        ipc_thread = threading.Thread(target=ipc_worker, daemon=True)
        ipc_thread.start()
        
        alert_thread = threading.Thread(target=alert_worker, daemon=True)
        alert_thread.start()
        
        file_thread = threading.Thread(target=inotify_monitor, args=([targetdir],), daemon=True)
        file_thread.start()
        
        while not shutdown_event.is_set():
            shutdown_event.wait(1)
            
    if args.profile:
        print("[+] Starting in Profiling Mode (60 seconds)...")
        import cProfile
        import pstats
        import io
        pr = cProfile.Profile()
        pr.enable()
        
        # Start threads but let main thread wait for 5s
        threading.Thread(target=run_daemon, daemon=True).start()
        shutdown_event.wait(5)
        shutdown_event.set()
        
        pr.disable()
        s = io.StringIO()
        sortby = 'cumulative'
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats(30)
        print("\n=== PROFILING RESULTS ===")
        print(s.getvalue())
    else:
        run_daemon()