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
import re
import ipaddress
import subprocess
from datetime import datetime
import collections
import requests
import smtplib
import shutil
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

[login_monitoring]
enabled = true
log_file = "/var/log/auth.log"
failed_threshold = 5
time_window = 300
whitelist_ips = ["127.0.0.1", "192.168.1.0/24"]

[cron_monitoring]
enabled = true
directories = [
    "/etc/crontab",
    "/etc/cron.d/",
    "/etc/cron.hourly/",
    "/etc/cron.daily/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/"
]

[remediation]
enabled = false
backup_dir = ".sentinel_backup"
max_backups = 5
directories = ["/etc", "/home"]
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
    
    config.setdefault('login_monitoring', {})
    login = config['login_monitoring']
    login.setdefault('enabled', True)
    login.setdefault('log_file', "/var/log/auth.log")
    login.setdefault('failed_threshold', 5)
    login.setdefault('time_window', 300)
    login.setdefault('whitelist_ips', ["127.0.0.1", "192.168.1.0/24"])

    config.setdefault('cron_monitoring', {})
    cron_cfg = config['cron_monitoring']
    cron_cfg.setdefault('enabled', True)
    cron_cfg.setdefault('directories', [
        "/etc/crontab",
        "/etc/cron.d/",
        "/etc/cron.hourly/",
        "/etc/cron.daily/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/"
    ])

    config.setdefault('remediation', {})
    remed = config['remediation']
    remed.setdefault('enabled', False)
    remed.setdefault('backup_dir', ".sentinel_backup")
    remed.setdefault('max_backups', 5)
    remed.setdefault('directories', ["/etc", "/home"])

def backup_file(src_path):
    remed = config.get('remediation', {})
    if not remed.get('enabled', False):
        return
    if not os.path.exists(src_path):
        return
        
    backup_dir = remed.get('backup_dir', '.sentinel_backup')
    max_backups = remed.get('max_backups', 5)
    
    dest_dir = os.path.join(backup_dir, src_path.lstrip('/'))
    os.makedirs(dest_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    dest_path = os.path.join(dest_dir, f"{timestamp}.backup")
    try:
        shutil.copy2(src_path, dest_path)
    except Exception as e:
        logging.warning(f"Backup failed for {src_path}: {e}")
        return
        
    backups = sorted([f for f in os.listdir(dest_dir) if f.endswith('.backup')])
    if len(backups) > max_backups:
        for old_bkp in backups[:-max_backups]:
            try:
                os.remove(os.path.join(dest_dir, old_bkp))
            except:
                pass

def perform_backups():
    remed = config.get('remediation', {})
    if not remed.get('enabled', False):
        return
        
    for d in remed.get('directories', []):
        if not os.path.exists(d): continue
        for root, _, files in os.walk(d):
            for file in files:
                backup_file(os.path.join(root, file))

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
    elif data["type"] == "login":
        return f"🚨 SENTINEL ALERT: {action}\nIP: {data['ip']}\nAttempts: {data['attempts']} failed logins in {data['window']}s\nService: {data['service']}\nUser: {data['user']}\nTime: {data['time']}"
    elif data["type"] == "cron":
        return f"🚨 SENTINEL ALERT: CRON_JOB_MODIFIED ({action})\nFile: {data['path']}\nScore: {data['score']}/10\nTime: {data['time']}"
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
            ident = data.get('path', data.get('name', data.get('ip', 'Unknown')))
            send_slack_alert(message, ident)
            send_telegram_alert(message, ident)
            send_email_alert(message, ident)
        else:
            shutdown_event.wait(1)

def queue_alert_if_needed(data):
    if data['score'] < config['alerts']['alert_min_score']:
        return
        
    ident = data.get('path', data.get('ip', 'Unknown'))
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
    except PermissionError:
        logging.warning(f"PERMISSION_DENIED: Cannot hash {file_path}")
        return None
    except FileNotFoundError:
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

def load_cron_baseline():
    baseline_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cron_baseline.json')
    if os.path.exists(baseline_path):
        with open(baseline_path, 'r') as f:
            return json.load(f)
    return {}

def save_cron_baseline(baseline_dict):
    baseline_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cron_baseline.json')
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
        backup_file(file_path)
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

def is_cron_file(path):
    if not config.get('cron_monitoring', {}).get('enabled', False):
        return False
    for d in config['cron_monitoring']['directories']:
        if path.startswith(d):
            return True
    return False

def check_cron_integrity(file_path, action, baseline):
    score = 10 # High severity for cron changes
    current_hash = compute_hash(file_path)
    if action != "deleted" and current_hash is None:
        return

    if action == "deleted":
        print(f"🗑️ [DELETED] Cron file removed: {file_path}")
        logging.warning(f"CRON_DELETED: {file_path}")
        if file_path in baseline:
            del baseline[file_path]
            save_cron_baseline(baseline)
        queue_cron_anomaly(file_path, "deleted", score)
        return

    if file_path not in baseline:
        print(f"🚨 [CREATED] Rogue cron detected: {file_path}")
        logging.warning(f"NEW_CRON_DETECTED: {file_path}")
        backup_file(file_path)
        queue_cron_anomaly(file_path, "created", score)
    else:
        old_hash = baseline[file_path]
        if current_hash != old_hash:
            print(f"⚠️ [MODIFIED] Cron hash mismatch: {file_path}")
            logging.warning(f"CRON_VIOLATION: {file_path} (old: {old_hash[:8]}..., new: {current_hash[:8]}...)")
            queue_cron_anomaly(file_path, "modified", score)

def queue_cron_anomaly(path, action, score):
    data = {
        "type": "cron",
        "path": path,
        "action": action,
        "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "score": score
    }
    queue_alert_if_needed(data)
    anomaly_queue.append(data)

def load_blocked_ips():
    blocked_ips_file = 'blocked_ips.txt'
    if os.path.exists(blocked_ips_file):
        with open(blocked_ips_file, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip:
                    try:
                        subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except subprocess.CalledProcessError:
                        try:
                            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                            print(f"[+] Re-applied iptables block for {ip}")
                        except Exception as e:
                            print(f"[!] Error re-applying block for {ip}: {e}")

def is_whitelisted_ip(ip_str):
    whitelist = config['login_monitoring']['whitelist_ips']
    try:
        ip = ipaddress.ip_address(ip_str)
        for w in whitelist:
            if '/' in w:
                if ip in ipaddress.ip_network(w, strict=False):
                    return True
            else:
                if ip == ipaddress.ip_address(w):
                    return True
    except Exception:
        pass
    return False

def auth_monitor():
    login_cfg = config.get('login_monitoring', {})
    if not login_cfg.get('enabled', False):
        return
        
    log_file = login_cfg.get('log_file', '/var/log/auth.log')
    if not os.path.exists(log_file):
        return
        
    failed_attempts = collections.defaultdict(list)
    fail_pattern = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+) port \d+ ssh2')
    accept_pattern = re.compile(r'Accepted password for (\S+) from (\S+) port \d+ ssh2')
    session_pattern = re.compile(r'session opened for user (\S+)')

    try:
        f = open(log_file, 'r')
        f.seek(0, os.SEEK_END)
        current_inode = os.fstat(f.fileno()).st_ino
    except Exception as e:
        print(f"[!] Error opening auth log: {e}")
        return

    while not shutdown_event.is_set():
        try:
            new_inode = os.stat(log_file).st_ino
            if current_inode != new_inode:
                f.close()
                f = open(log_file, 'r')
                current_inode = os.fstat(f.fileno()).st_ino
        except FileNotFoundError:
            pass

        line = f.readline()
        if not line:
            shutdown_event.wait(1)
            continue
            
        match = fail_pattern.search(line)
        if match:
            user, ip = match.groups()
            if is_whitelisted_ip(ip): continue
            
            now = time.time()
            failed_attempts[ip].append(now)
            
            window = login_cfg.get('time_window', 300)
            failed_attempts[ip] = [ts for ts in failed_attempts[ip] if now - ts <= window]
            
            threshold = login_cfg.get('failed_threshold', 5)
            if len(failed_attempts[ip]) >= threshold:
                data = {
                    "type": "login",
                    "ip": ip,
                    "user": user,
                    "service": "ssh",
                    "attempts": len(failed_attempts[ip]),
                    "window": window,
                    "score": 10,
                    "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "action": "BRUTE_FORCE_DETECTED",
                    "path": f"Auth log: {log_file}"
                }
                queue_alert_if_needed(data)
                anomaly_queue.append(data)
                failed_attempts[ip] = []
            continue

        match = accept_pattern.search(line)
        if match:
            user, ip = match.groups()
            log_anomaly(ip, "login_success", f"Successful login for {user}", None)
            continue
            
        match = session_pattern.search(line)
        if match:
            user = match.group(1)
            log_anomaly("localhost", "session_opened", f"Session opened for {user}", None)


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
            cron_baseline = load_cron_baseline() if config.get('cron_monitoring', {}).get('enabled', False) else {}
            
            for event in events:
                parent_path = wd_to_path.get(event.wd)
                if not parent_path:
                    continue
                file_path = os.path.join(parent_path, event.name) if event.name else parent_path
                
                if event.mask & flags.ISDIR:
                    if (event.mask & flags.CREATE) or (event.mask & flags.MOVED_TO):
                        add_watch_recursive(file_path)
                    continue
                    
                is_cron = is_cron_file(file_path)
                check_func = check_cron_integrity if is_cron else check_integrity
                baseline_to_use = cron_baseline if is_cron else baseline
                
                if event.mask & flags.MODIFY:
                    check_func(file_path, "modified", baseline_to_use)
                elif (event.mask & flags.CREATE) or (event.mask & flags.MOVED_TO):
                    check_func(file_path, "created", baseline_to_use)
                elif (event.mask & flags.DELETE) or (event.mask & flags.MOVED_FROM):
                    check_func(file_path, "deleted", baseline_to_use)
                    
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
                                        
                                elif data["type"] == "login":
                                    ip = data["ip"]
                                    if decision == "allow":
                                        config['login_monitoring']['whitelist_ips'].append(ip)
                                        log_anomaly(ip, "brute_force", "Allowed by user", data.get("score"))
                                    elif decision == "block":
                                        try:
                                            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                                            log_anomaly(ip, "brute_force", "Blocked via iptables", data.get("score"))
                                            with open('blocked_ips.txt', 'a') as bf:
                                                bf.write(f"{ip}\n")
                                        except Exception as e:
                                            print(f"[!] Error blocking IP: {e}")
                                    elif decision == "ignore":
                                        pass

                                elif data["type"] == "cron":
                                    path = data["path"]
                                    action = data["action"]
                                    if decision == "allow":
                                        baseline = load_cron_baseline()
                                        if action == "deleted":
                                            if path in baseline:
                                                del baseline[path]
                                        else:
                                            h = compute_hash(path)
                                            if h:
                                                baseline[path] = h
                                            backup_file(path)
                                        save_cron_baseline(baseline)
                                        log_anomaly(path, action, "Allowed/Baseline Updated", data.get("score"))
                                    elif decision == "delete":
                                        try:
                                            if os.path.exists(path):
                                                os.remove(path)
                                                log_anomaly(path, action, "Deleted by user", data.get("score"))
                                        except Exception as e:
                                            print(f"[!] Error deleting cron file: {e}")
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
                                            backup_file(path)
                                        save_baseline(baseline)
                                        log_anomaly(path, action, "Allowed/Baseline Updated", data.get("score"))
                                    elif decision == "delete":
                                        try:
                                            if os.path.exists(path):
                                                os.remove(path)
                                                log_anomaly(path, action, "Deleted by user", data.get("score"))
                                        except Exception as e:
                                            print(f"[!] Error deleting file: {e}")
                                    elif decision == "revert":
                                        try:
                                            remed = config.get('remediation', {})
                                            backup_dir = remed.get('backup_dir', '.sentinel_backup')
                                            dest_dir = os.path.join(backup_dir, path.lstrip('/'))
                                            if os.path.exists(dest_dir):
                                                backups = sorted([f for f in os.listdir(dest_dir) if f.endswith('.backup')])
                                                if backups:
                                                    latest = os.path.join(dest_dir, backups[-1])
                                                    shutil.copy2(latest, path)
                                                    baseline = load_baseline()
                                                    h = compute_hash(path)
                                                    if h:
                                                        baseline[path] = h
                                                    save_baseline(baseline)
                                                    log_anomaly(path, action, "REVERTED", data.get("score"))
                                                    print(f"[+] Successfully reverted {path} from backup.")
                                                else:
                                                    print(f"[-] No backups found for {path} to revert.")
                                            else:
                                                print(f"[-] Backup directory for {path} does not exist.")
                                        except Exception as e:
                                            print(f"[!] Error reverting file {path}: {e}")
                                    elif decision == "ignore":
                                        pass
                                responded = True
                                break
                                
                if not responded and not shutdown_event.is_set():
                    try:
                        os.close(fd_in)
                    except:
                        pass
                    ident = data.get('name') if data.get('type') == 'process' else data.get('path', data.get('ip'))
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
    parser.add_argument('--init_baseline', action='store_true', help='Initialize baseline hashes for all files in targetdir')
    parser.add_argument('--update_baseline', action='store_true', help='Update baseline hashes for changed files')
    parser.add_argument('--init-cron-baseline', action='store_true', help='Initialize baseline hashes for cron directories')
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

    if config.get('cron_monitoring', {}).get('enabled', False):
        cron_baseline_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cron_baseline.json')
        if not os.path.exists(cron_baseline_path) or args.init_cron_baseline:
            cron_dirs = config['cron_monitoring']['directories']
            c_baseline = {}
            for d in cron_dirs:
                if os.path.isfile(d):
                    h = compute_hash(d)
                    if h: c_baseline[d] = h
                elif os.path.isdir(d):
                    for root, _, files in os.walk(d):
                        for file in files:
                            path = os.path.join(root, file)
                            h = compute_hash(path)
                            if h: c_baseline[path] = h
            save_cron_baseline(c_baseline)
            print("[+] Cron baseline initialized.")
            if args.init_cron_baseline:
                sys.exit(0)

    if config.get('remediation', {}).get('enabled', False):
        print("[+] Initializing Auto-Remediation backups...")
        perform_backups()
        print("[+] Backups initialized.")

    setup_pipes()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if not os.path.exists('anomalies.txt'):
        with open('anomalies.txt', 'w') as f:
            f.write("# Sentinel-FIM Anomalies History\n")

    load_blocked_ips()

    def run_daemon():
        print("🛡️ Sentinel-FIM Engine Active.")
        print(f"👀 Monitoring: {targetdir}")
        
        watch_dirs = [targetdir]
        if config.get('cron_monitoring', {}).get('enabled', False):
            for d in config['cron_monitoring']['directories']:
                if os.path.exists(d):
                    watch_dirs.append(d)
                    
        proc_thread = threading.Thread(target=process_monitor, daemon=True)
        proc_thread.start()
        
        ipc_thread = threading.Thread(target=ipc_worker, daemon=True)
        ipc_thread.start()
        
        alert_thread = threading.Thread(target=alert_worker, daemon=True)
        alert_thread.start()
        
        file_thread = threading.Thread(target=inotify_monitor, args=(watch_dirs,), daemon=True)
        file_thread.start()
        
        auth_thread = threading.Thread(target=auth_monitor, daemon=True)
        auth_thread.start()
        
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