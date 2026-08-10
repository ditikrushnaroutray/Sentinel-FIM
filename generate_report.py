import sys
import os
import re
import argparse
from datetime import datetime

CSS = """
body { background-color: #0a0e17; color: #e8edf5; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 40px; }
h1, h2, h3 { color: #4f8cf7; }
.header { text-align: center; margin-bottom: 40px; }
.summary-container { display: flex; justify-content: space-around; flex-wrap: wrap; gap: 20px; margin-bottom: 40px; }
.card { background-color: #131b2e; padding: 25px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); text-align: center; flex: 1; min-width: 150px; }
.card h2 { margin: 0; font-size: 2.5em; }
.card p { margin: 10px 0 0 0; color: #a1b2d3; font-weight: 500; letter-spacing: 0.5px; }
.card.high h2 { color: #ff4c4c; }
.card.medium h2 { color: #ffaa00; }
.card.low h2 { color: #f4d03f; }
table { width: 100%; border-collapse: collapse; background-color: #131b2e; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
th, td { padding: 18px 20px; text-align: left; border-bottom: 1px solid #1f2a40; }
th { background-color: #1a2436; color: #4f8cf7; text-transform: uppercase; font-size: 0.85em; letter-spacing: 1.2px; }
tr:hover { background-color: #1a2436; transition: background-color 0.2s ease; }
.row-high { border-left: 5px solid #ff4c4c; }
.row-medium { border-left: 5px solid #ffaa00; }
.row-low { border-left: 5px solid #f4d03f; }
.row-unknown { border-left: 5px solid #888; }
.footer { text-align: center; margin-top: 50px; color: #6b7a99; font-size: 0.9em; border-top: 1px solid #1f2a40; padding-top: 20px; }
.empty-state { text-align: center; padding: 60px; background-color: #131b2e; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
.empty-state h2 { color: #4f8cf7; margin-bottom: 10px; }
"""

def parse_anomalies(file_path):
    anomalies = []
    # Match: [2025-08-10 14:30:22] INTEGRITY_VIOLATION: /etc/passwd (old: a1b2c3, new: d4e5f6) | Score: 10 | Action: Killed by user
    pattern = re.compile(r"^\[(.*?)\]\s+(.*?):\s+(.*?)\s+\|\s+Score:\s+(\d+)\s+\|\s+(.*?)$")
    
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            match = pattern.match(line)
            if not match:
                print(f"[!] Warning: Skipping malformed line {line_num}: {line}", file=sys.stderr)
                continue
                
            timestamp, event_type, path, score_str, action_decision = match.groups()
            score = int(score_str) if score_str else 0
            
            anomalies.append({
                'timestamp': timestamp,
                'score': score,
                'path': path.strip(),
                'action': event_type.strip(),
                'decision': action_decision.strip()
            })
            
    return anomalies

def generate_html(anomalies, output_file):
    total = len(anomalies)
    high = sum(1 for a in anomalies if a['score'] >= 7)
    medium = sum(1 for a in anomalies if 4 <= a['score'] <= 6)
    low = sum(1 for a in anomalies if 1 <= a['score'] <= 3)
    pending = sum(1 for a in anomalies if 'Pending' in a['decision'] or 'Unknown' in a['decision'])
    
    gen_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel-FIM Security Report</title>
    <style>{CSS}</style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Sentinel-FIM Security Report</h1>
        <p>Generated on: {gen_time}</p>
    </div>
"""
    
    if total == 0:
        html += """
    <div class="empty-state">
        <h2>✅ No anomalies detected</h2>
        <p>Your system is currently secure. No high-threat events have bypassed the automated filtering engine.</p>
    </div>
"""
    else:
        html += f"""
    <div class="summary-container">
        <div class="card">
            <h2>{total}</h2>
            <p>Total Events</p>
        </div>
        <div class="card high">
            <h2>{high}</h2>
            <p>High Severity (≥7)</p>
        </div>
        <div class="card medium">
            <h2>{medium}</h2>
            <p>Medium Severity (4-6)</p>
        </div>
        <div class="card low">
            <h2>{low}</h2>
            <p>Low Severity (1-3)</p>
        </div>
        <div class="card">
            <h2>{pending}</h2>
            <p>Pending Actions</p>
        </div>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Path / Identifier</th>
                <th>Threat Score</th>
                <th>Action Taken</th>
            </tr>
        </thead>
        <tbody>
"""
        # Sort anomalies by timestamp descending (newest first)
        anomalies.sort(key=lambda x: x['timestamp'], reverse=True)
        
        for a in anomalies:
            score = a['score']
            if score >= 7:
                row_class = 'row-high'
            elif 4 <= score <= 6:
                row_class = 'row-medium'
            elif 1 <= score <= 3:
                row_class = 'row-low'
            else:
                row_class = 'row-unknown'
                
            html += f"""
            <tr class="{row_class}">
                <td>{a['timestamp']}</td>
                <td>{a['action']}</td>
                <td>{a['path']}</td>
                <td>{score}/10</td>
                <td>{a['decision']}</td>
            </tr>"""
            
        html += """
        </tbody>
    </table>
"""

    html += f"""
    <div class="footer">
        Sentinel-FIM • Phase 8 Reporting Engine • {gen_time}
    </div>
</body>
</html>
"""
    
    with open(output_file, 'w') as f:
        f.write(html)
        
    print(f"[+] Report successfully generated: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Sentinel-FIM HTML Report Generator")
    parser.add_argument('--output', type=str, help="Output HTML file path")
    args = parser.parse_args()
    
    log_file = "anomalies.txt"
    if not os.path.exists(log_file):
        print(f"[!] Error: {log_file} does not exist. No events to report.", file=sys.stderr)
        sys.exit(1)
        
    anomalies = parse_anomalies(log_file)
    
    output_file = args.output
    if not output_file:
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        output_file = f"report_{timestamp}.html"
        
    generate_html(anomalies, output_file)

if __name__ == "__main__":
    main()
