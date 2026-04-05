#!/bin/bash

# Color variables for terminal output
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}      SENTINEL-FIM SECURITY REPORT      ${NC}"
echo -e "${CYAN}========================================${NC}"

# Check if the log file exists yet
if [ ! -f "sentinelaudit.log" ]; then
    echo -e "${YELLOW}[!] No audit log found. System is clean.${NC}"
    echo -e "${CYAN}========================================${NC}"
    exit 0
fi

# Parse the log file and count the exact number of threats
modified=$(grep -c "Modified" sentinelaudit.log)
created=$(grep -c "Created" sentinelaudit.log)
deleted=$(grep -c "Deleted" sentinelaudit.log)

# Print the final dashboard
echo -e "${YELLOW}[⚠️] System Modifications: $modified${NC}"
echo -e "${RED}[🚨] Rogue Files Created:  $created${NC}"
echo -e "${RED}[🗑️] Critical Files Wiped: $deleted${NC}"
echo -e "${CYAN}========================================${NC}"
echo "Run 'cat sentinelaudit.log' for full forensic details."
