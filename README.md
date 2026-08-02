# 🛡️ Sentinel-FIM: Advanced Security & File Integrity Monitor

Sentinel-FIM is an ultra-lightweight, high-performance security agent for Linux systems. Designed for zero-overhead execution, it hooks directly into the Linux kernel to detect unauthorized file modifications, rogue file creations, and suspicious process executions in real time. 

When high-threat anomalies are detected, Sentinel-FIM funnels them through a local interactive UI for immediate forensic decisions and dispatches asynchronous alerts to your remote endpoints (Slack, Telegram, Email).

---

## 🚀 Core Capabilities

### 1. Raw Kernel File Integrity Monitoring
Sentinel-FIM abandons heavy Python abstraction layers and utilizes `inotify-simple` for absolute minimal-overhead directory surveillance. It natively hooks into Linux `inotify` kernel syscalls to recursively monitor directories (like `/etc` or `/var/www`) for `CREATE`, `MODIFY`, and `DELETE` events with near-zero latency.

### 2. Batched Process Surveillance
Instead of sequentially querying OS processes, the engine efficiently iterates through the OS process table using batched `psutil` C-level passes. It natively filters out system PIDs (`< 100`) and tracks state using `(pid, create_time)` tuples to prevent spoofing from recycled PIDs.

### 3. Dynamic Threat Scoring Engine
Say goodbye to alert fatigue. A centralized `config.toml` engine automatically scores anomalies based on deterministic criteria (directory targets, file extensions, explicit identifiers). Low-threat events are silently discarded, while critical threats immediately trigger alerts.

### 4. Interactive Zero-Trust UI Architecture
The root FIM daemon safely interfaces with a non-privileged User Agent UI via a dual FIFO pipe architecture. When an anomaly is caught, an interactive ASCII terminal popup prompts the user to make on-the-fly forensic decisions:
- **[a] Allow**: Whitelist a process or silently update `baseline.json` with a new SHA-256 hash.
- **[k]/[d] Kill/Delete**: Instantly terminate a rogue process or cleanly delete a malicious file.
- **[i] Ignore**: Discard the event.

### 5. Asynchronous Global Alerting & Anti-Spam
High-scoring threats are instantly dispatched to Slack Webhooks, Telegram Bots, and SMTP Email addresses. An intelligent background `alert_worker` thread ensures network timeouts never stall core kernel polling loops, while a built-in 60-second cooldown cache prevents alert flooding from rapid attack scripts.

---

## 🛠️ Technical Stack
- **Language:** Python 3.11+
- **Architecture:** Multi-threaded Event loop, FIFO Interprocess Communication (IPC)
- **Dependencies:** `inotify-simple` (Kernel hooks), `psutil` (Process batching), `requests` (Webhooks), `tomllib` (Configuration)
- **Environment:** Linux (Debian, Arch, RHEL, Alpine)

---

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ditikrushnaroutray/Sentinel-FIM.git
   cd Sentinel-FIM
   ```

2. **Initialize a Python Virtual Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Start the User Agent UI (Background):**
   This script handles the interactive popups and must run as your local GUI user.
   ```bash
   nohup python3 popup.py --daemon &
   ```

4. **Launch the Core Sentinel Daemon (Root):**
   The daemon must run with elevated privileges to hook `inotify` and terminate processes.
   ```bash
   sudo nohup python3 sentinel.py --target /etc &
   ```

---

## 📜 Configuration (`config.toml`)

Upon first launch, Sentinel-FIM automatically generates a `config.toml` file in the project root. You can modify this to fit your exact operational environment.

### Ignoring Noise
```toml
monitored_dirs = ["/etc", "/var/www/html"]
ignored_dirs = ["/etc/shadow", "/etc/gshadow", "/tmp/ignored"]
ignore_extensions = [".log", ".tmp", ".swp"]
whitelist_processes = ["bash", "python3", "node", "java"]
```

### Threat Scoring & Thresholds
If an anomaly's calculated score is below `min_score`, it is completely ignored.
```toml
default_score = 5
min_score = 7

[threat_scores]
# Exact file path matching
"/etc/passwd" = 10

[directory_scores]
# Directory-wide score fallback
"/tmp" = 8
"/var/log" = 2
```

### Remote Alerting
Configure remote Webhooks or SMTP servers. The engine natively handles TLS and graceful timeouts.
```toml
[alerts]
alert_min_score = 7
slack_webhook_url = "https://hooks.slack.com/services/..."
telegram_bot_token = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
telegram_chat_id = "-100123456789"

smtp_server = "smtp.gmail.com"
smtp_port = 587
smtp_username = "security@yourdomain.com"
smtp_password = "app-password"
smtp_from = "sentinel@yourdomain.com"
smtp_to = "admin@yourdomain.com"
```

---

## 📊 Performance Profiling

Sentinel-FIM is optimized for heavily congested enterprise servers. You can run a 60-second execution benchmark against your current OS load by passing the `--profile` flag:
```bash
sudo python3 sentinel.py --target /etc --profile
```
The daemon will execute natively, monitor all hooks, and safely exit after 60 seconds, printing a comprehensive `cProfile` benchmark to standard output.