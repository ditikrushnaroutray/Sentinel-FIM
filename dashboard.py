import os
import re
from datetime import datetime
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static
from textual.containers import Grid
from textual.reactive import reactive
from rich.text import Text

CSS = """
Screen {
    background: #0a0e17;
}

#stats-container {
    height: 10;
    margin: 1 2;
    layout: grid;
    grid-size: 5;
    grid-gutter: 2;
}

.stat-card {
    background: #131b2e;
    padding: 1;
    border: solid #1f2a40;
    content-align: center middle;
    height: 100%;
}

.stat-title {
    color: #a1b2d3;
    text-align: center;
}

.stat-value {
    color: #e8edf5;
    text-align: center;
    text-style: bold;
}

.val-high { color: #ff4c4c; }
.val-medium { color: #ffaa00; }
.val-low { color: #f4d03f; }

DataTable {
    background: #131b2e;
    border: solid #1f2a40;
    margin: 0 2 1 2;
    height: 1fr;
}
"""

class StatCard(Static):
    def __init__(self, title: str, value: str, value_class: str = "", id: str = None):
        super().__init__(id=id, classes="stat-card")
        self.title_text = title
        self.value_text = value
        self.value_class = value_class

    def compose(self) -> ComposeResult:
        yield Static(self.title_text, classes="stat-title")
        yield Static(self.value_text, classes=f"stat-value {self.value_class}", id=f"{self.id}-val")

class SentinelDashboard(App):
    CSS = CSS
    TITLE = "🛡️ Sentinel-FIM Dashboard"
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("f", "cycle_filter", "Filter: All"),
        ("t", "toggle_refresh", "Auto-Refresh: ON"),
    ]
    
    anomalies = reactive([])
    filter_mode = reactive("All")
    auto_refresh = reactive(True)
    
    def parse_anomalies(self):
        anomalies_list = []
        pattern = re.compile(r"^\[(.*?)\]\s+(.*?):\s+(.*?)\s+\|\s+Score:\s+(\d+)\s+\|\s+(.*?)$")
        file_path = 'anomalies.txt'
        
        try:
            if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                return anomalies_list
                
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    match = pattern.match(line)
                    if match:
                        timestamp, event_type, path, score_str, action_decision = match.groups()
                        score = int(score_str) if score_str else 0
                        anomalies_list.append({
                            'timestamp': timestamp,
                            'score': score,
                            'path': path.strip(),
                            'action': event_type.strip(),
                            'decision': action_decision.strip()
                        })
            anomalies_list.sort(key=lambda x: x['timestamp'], reverse=True)
        except (PermissionError, OSError) as e:
            self.notify(f"Error reading log file: {e}", title="Read Error", severity="warning")
            
        return anomalies_list

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Grid(id="stats-container"):
            yield StatCard("Total Events", "0", id="stat-total")
            yield StatCard("High Severity (≥7)", "0", "val-high", id="stat-high")
            yield StatCard("Medium Severity (4-6)", "0", "val-medium", id="stat-medium")
            yield StatCard("Low Severity (1-3)", "0", "val-low", id="stat-low")
            yield StatCard("Pending Actions", "0", id="stat-pending")
            
        yield DataTable(id="anomalies-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Timestamp", "Event Type", "Path / Identifier", "Threat Score", "Action Taken")
        table.cursor_type = "row"
        table.zebra_stripes = True
        
        self.update_data()
        self.set_interval(2, self.update_data_if_auto)

    def update_data_if_auto(self):
        if self.auto_refresh:
            self.update_data()

    def action_refresh(self) -> None:
        self.update_data()
        
    def action_toggle_refresh(self) -> None:
        self.auto_refresh = not self.auto_refresh
        state = "ON" if self.auto_refresh else "OFF"
        self.notify(f"Auto-Refresh: {state}")

    def action_cycle_filter(self) -> None:
        modes = ["All", "High", "Medium", "Low"]
        idx = modes.index(self.filter_mode)
        self.filter_mode = modes[(idx + 1) % len(modes)]
        self.notify(f"Filter Mode: {self.filter_mode}")
        self.populate_table()

    def update_data(self):
        self.anomalies = self.parse_anomalies()
        self.update_stats()
        self.populate_table()
        
    def update_stats(self):
        total = len(self.anomalies)
        high = sum(1 for a in self.anomalies if a['score'] >= 7)
        medium = sum(1 for a in self.anomalies if 4 <= a['score'] <= 6)
        low = sum(1 for a in self.anomalies if 1 <= a['score'] <= 3)
        pending = sum(1 for a in self.anomalies if 'Pending' in a['decision'] or 'Unknown' in a['decision'])
        
        self.query_one("#stat-total-val", Static).update(str(total))
        self.query_one("#stat-high-val", Static).update(str(high))
        self.query_one("#stat-medium-val", Static).update(str(medium))
        self.query_one("#stat-low-val", Static).update(str(low))
        self.query_one("#stat-pending-val", Static).update(str(pending))

    def populate_table(self):
        table = self.query_one(DataTable)
        table.clear()
        
        if not self.anomalies:
            table.add_row(Text("No anomalies detected. Waiting for events...", style="#4f8cf7"), "", "", "", "")
            return
            
        for a in self.anomalies:
            score = a['score']
            if self.filter_mode == "High" and score < 7:
                continue
            if self.filter_mode == "Medium" and not (4 <= score <= 6):
                continue
            if self.filter_mode == "Low" and not (1 <= score <= 3):
                continue
                
            color = "#ff4c4c" if score >= 7 else "#ffaa00" if score >= 4 else "#f4d03f"
            
            ts = Text(a['timestamp'], style=color)
            action = Text(a['action'], style=color)
            path = Text(a['path'], style=color)
            score_text = Text(f"{score}/10", style=color)
            dec = Text(a['decision'], style=color)
            
            table.add_row(ts, action, path, score_text, dec)

if __name__ == "__main__":
    app = SentinelDashboard()
    app.run()
