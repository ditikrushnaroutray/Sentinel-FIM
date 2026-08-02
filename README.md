# 🛡️ Sentinel-FIM: Intelligent Security & File Integrity Monitor

A high-performance, real-time security agent designed for zero-overhead execution on Linux systems. Sentinel-FIM interfaces directly with kernel `inotify` syscalls to natively detect unauthorized modifications, rogue file creations, and suspicious process executions, funneling high-threat anomalies directly to real-time notification endpoints and an interactive local UI.

## 🚀 Core Features
- **Raw Kernel Monitoring:** Utilizes `inotify-simple` for absolute minimal-overhead recursive directory surveillance.
- **Batched Process Scraping:** Efficiently iterates through the OS process table using batched `psutil` C-level passes.
- **Rule-Based Threat Scoring:** A dynamic `config.toml` engine automatically ignores low-threat anomalies (e.g. log files, temporary directories) based on deterministic thresholds, entirely eliminating alert fatigue.
- **Decoupled User Interface:** dual FIFO pipe architecture allows the root FIM daemon to safely interface with an ASCII-based non-privileged User Agent UI for on-the-fly interactive forensic decisions (Allow/Kill/Delete).
- **Asynchronous Global Alerting:** Integrated multi-channel remote alerts (Slack Webhooks, Telegram API, SMTP Email) decoupled by a background worker thread to ensure network timeouts never stall core kernel polling loops.
- **Anti-Spam Throttling:** Automatically filters and deduplicates high-velocity attacks through a unified 60-second cooldown memory cache per anomalous identifier.

## 🛠️ Technical Stack
- **Language:** Python 3.11+
- **Architecture:** Threading Events, FIFO Interprocess Communication (IPC)
- **Libraries:** `inotify-simple`, `psutil`, `requests`, `tomllib`
- **Environment:** Linux (Debian, Arch, Enterprise Servers)

## 📂 Project Structure
- `sentinel.py`: The root-level core surveillance daemon.
- `popup.py`: The User Agent daemon triggering localized terminal popup workflows.
- `config.toml`: The unified security configuration layer (auto-generated on launch).
- `baseline.json`: Automatically updated SHA-256 state tracking for tracked files.

## ⚙️ Installation & Usage
1. **Clone and setup the environment:**
   ```bash
   git clone https://github.com/ditikrushnaroutray/Sentinel-FIM.git
   cd Sentinel-FIM
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Start the User Agent UI (Background):**
   ```bash
   nohup python3 popup.py --daemon &
   ```
3. **Launch the core Sentinel Daemon:**
   ```bash
   sudo nohup python3 sentinel.py --target /etc &
   ```
4. **Performance Benchmark (Optional):**
   ```bash
   sudo python3 sentinel.py --target /etc --profile
   ```