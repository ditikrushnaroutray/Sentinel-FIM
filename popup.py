import os
import sys
import json
import subprocess
import argparse
import time

PIPE_OUT = "/tmp/sentinel_pipe_out"
PIPE_IN = "/tmp/sentinel_pipe_in"

def spawn_terminal_ui(json_str):
    try:
        subprocess.Popen([
            'gnome-terminal', '--', 'python3', os.path.abspath(__file__), '--ui', json_str
        ])
    except FileNotFoundError:
        # Fallback to xterm
        try:
            subprocess.Popen([
                'xterm', '-e', 'python3', os.path.abspath(__file__), '--ui', json_str
            ])
        except FileNotFoundError:
            print("No suitable terminal emulator found.")

def run_listener():
    print("Sentinel-FIM User Agent started. Listening for anomalies...")
    while True:
        if not os.path.exists(PIPE_OUT):
            time.sleep(1)
            continue
        try:
            with open(PIPE_OUT, "r") as pipe:
                for line in pipe:
                    line = line.strip()
                    if line:
                        try:
                            # Verify it's valid JSON
                            json.loads(line)
                            spawn_terminal_ui(line)
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            time.sleep(1)

def show_ui(json_str):
    try:
        data = json.loads(json_str)
    except Exception as e:
        print("Error parsing data:", e)
        time.sleep(2)
        sys.exit(1)
        
    print("╔══════════════════════════════════════════════════════════╗")
    
    event_type = data.get("type", "process")
    score = data.get("score", "?")
    
    if event_type == "process":
        print("║   🔴 SENTINEL: Suspicious Process Detected              ║")
        print("║                                                         ║")
        print(f"║   Process:   {data.get('name', 'Unknown')}".ljust(59) + "║")
        print(f"║   PID:       {data.get('pid', 'Unknown')}".ljust(59) + "║")
        print(f"║   Path:      {data.get('path', 'Unknown')}".ljust(59) + "║")
        print(f"║   User:      {data.get('user', 'Unknown')}".ljust(59) + "║")
        print(f"║   Threat:    {score}/10".ljust(59) + "║")
        print(f"║   Time:      {data.get('time', 'Unknown')}".ljust(59) + "║")
        print("║                                                         ║")
        print("║   [a] Allow  [k] Kill  [i] Ignore once                 ║")
    else:
        print("║   ⚠️ SENTINEL: File Integrity Violation                 ║")
        print("║                                                         ║")
        print(f"║   File:      {data.get('path', 'Unknown')}".ljust(59) + "║")
        print(f"║   Action:    {str(data.get('action', 'Unknown')).upper()}".ljust(59) + "║")
        print(f"║   Threat:    {score}/10".ljust(59) + "║")
        print(f"║   Time:      {data.get('time', 'Unknown')}".ljust(59) + "║")
        print("║                                                         ║")
        action = data.get('action', 'Unknown')
        if action == "modified":
            print("║   [a] Update Baseline                                  ║")
            print("║   [d] Delete File                                      ║")
        elif action == "created":
            print("║   [a] Allow (add to baseline)                          ║")
            print("║   [d] Delete File                                      ║")
        else:
            print("║   [a] Accept Deletion (update baseline)                ║")
        print("║   [i] Ignore once                                      ║")
        
    print("╚══════════════════════════════════════════════════════════╝")
    
    while True:
        if event_type == "process":
            choice = input("Decision [a/k/i]: ").strip().lower()
            if choice in ['a', 'k', 'i']:
                decision = "allow" if choice == 'a' else "kill" if choice == 'k' else "ignore"
                resp = {"decision": decision}
                try:
                    with open(PIPE_IN, "w") as pipe:
                        pipe.write(json.dumps(resp) + "\n")
                        pipe.flush()
                except Exception as e:
                    print("Failed to send decision:", e)
                    time.sleep(2)
                break
            else:
                print("Invalid choice.")
        else:
            action = data.get('action')
            valid_choices = ['a', 'd', 'i'] if action in ['modified', 'created'] else ['a', 'i']
            choice = input(f"Decision [{' / '.join(valid_choices)}]: ").strip().lower()
            
            if choice in valid_choices:
                if choice == 'd':
                    confirm = input("⚠️ Delete this file? (y/n): ").strip().lower()
                    if confirm != 'y':
                        continue
                decision = "allow" if choice == 'a' else "delete" if choice == 'd' else "ignore"
                resp = {"decision": decision}
                try:
                    with open(PIPE_IN, "w") as pipe:
                        pipe.write(json.dumps(resp) + "\n")
                        pipe.flush()
                except Exception as e:
                    print("Failed to send decision:", e)
                    time.sleep(2)
                break
            else:
                print("Invalid choice.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--ui', type=str, help='Run in UI mode with JSON data')
    parser.add_argument('--daemon', action='store_true', help='Run as a background daemon')
    args = parser.parse_args()

    if args.daemon:
        print("Starting Sentinel-FIM User Agent in daemon mode...")
        try:
            if os.fork() > 0:
                sys.exit(0)
        except OSError as e:
            print(f"fork failed: {e}", file=sys.stderr)
            sys.exit(1)
            
        os.chdir("/")
        os.setsid()
        os.umask(0)
        
        try:
            if os.fork() > 0:
                sys.exit(0)
        except OSError as e:
            print(f"fork failed: {e}", file=sys.stderr)
            sys.exit(1)
            
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
        
        run_listener()
    elif args.ui:
        show_ui(args.ui)
    else:
        run_listener()
