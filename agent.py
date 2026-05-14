import psutil, time, pandas as pd, datetime, os, csv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

LOG_FILE = "live_telemetry.csv"
MONITOR_PATH = os.path.expanduser("~") 

class MonitorAgent(FileSystemEventHandler):
    def __init__(self): self.file_change_count = 0
    def on_modified(self, event):
        if not event.is_directory: self.file_change_count += 1

def start_agent():
    print(f"🚀 EDR AGENT ACTIVE: Monitoring {MONITOR_PATH}")
    event_handler = MonitorAgent(); observer = Observer()
    observer.schedule(event_handler, MONITOR_PATH, recursive=True); observer.start()
    net_start = psutil.net_io_counters()

    cols = ["user_id", "timestamp", "department", "role", "login_count", 
            "file_access", "avg_file_access_30d", "usb_usage", "emails_sent", 
            "email_subject", "network_traffic_mb"]
    
    # Force a fresh file with a header immediately
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()

    try:
        while True:
            net_now = psutil.net_io_counters()
            mb_sent = round((net_now.bytes_sent - net_start.bytes_sent) / (1024 * 1024), 2)
            
            suspicious_apps = ["cmd.exe", "powershell.exe", "wireshark.exe"]
            current_procs = [p.name().lower() for p in psutil.process_iter(['name'])]
            
            status = "Normal Activity"
            for app in suspicious_apps:
                if any(app in p for p in current_procs): status = f"SUSPICIOUS: {app.upper()}"

            new_data = {
                "user_id": "LOCAL_USER", "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "department": "Engineering", "role": "System Operator", "login_count": 1,
                "file_access": event_handler.file_change_count, "avg_file_access_30d": 5, 
                "usb_usage": 0, "emails_sent": 0, "email_subject": status, "network_traffic_mb": mb_sent
            }

            # Append the data row
            pd.DataFrame([new_data]).to_csv(LOG_FILE, mode='a', header=False, index=False, quoting=csv.QUOTE_NONNUMERIC)
            event_handler.file_change_count = 0; time.sleep(4)

    except KeyboardInterrupt: observer.stop()
    observer.join()

if __name__ == "__main__": start_agent()