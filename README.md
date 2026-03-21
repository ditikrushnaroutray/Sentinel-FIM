# 🛡️ Sentinel-FIM: File Integrity Monitor

A high-performance, real-time security agent for Linux systems. Sentinel-FIM hooks directly into the OS kernel events to detect unauthorized modifications, rogue file creations, and data tampering in critical system directories like `/etc`.

## 🚀 Core Features
- **Kernel-Level Monitoring:** Uses the Python `watchdog` API to monitor file system events in real-time.
- **Forensic Logging:** Generates persistent, timestamped audit logs for security incident response.
- **Stealth Execution:** Integrated Bash daemon scripts to run the engine as a background system process.
- **Automated Assessment:** Custom reporting tool for rapid threat analysis and dashboard summaries.

## 🛠️ Technical Stack
- **Language:** Python 3.x
- **Automation:** Linux Bash Scripting
- **Libraries:** `watchdog`, `logging`
- **Environment:** Linux Mint / Debian-based systems

## 📂 Project Structure
- `sentinel.py`: The core Python monitoring engine.
- `startsentinel.sh`: Bash script to launch the agent in background mode.
- `getreport.sh`: Bash script to generate a color-coded security dashboard.
- `sentinelaudit.log`: The forensic audit trail (auto-generated).

## ⚙️ Installation & Usage
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/ditikrushnaroutray/Sentinel-FIM.git](https://github.com/ditikrushnaroutray/Sentinel-FIM.git)
   cd Sentinel-FIM
   