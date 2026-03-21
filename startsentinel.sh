#!/bin/bash

echo "[*] Booting Sentinel-FIM into Stealth Mode..."

# Run the Python engine in the background using sudo to access /etc
sudo nohup python3 sentinel.py > /dev/null 2>&1 &

echo "[+] Sentinel-FIM is now monitoring /etc 24/7."
echo "[+] To view live security alerts, run: tail -f sentinelaudit.log"
