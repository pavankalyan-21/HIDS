import os
import hashlib
import time
import json
import psutil
import subprocess
import logging
from plyer import notification
import platform

MONITORED_PATHS = ["/etc/passwd", "/etc/shadow", "/etc/hosts"]
HASH_STORE = "file_hashes.json"
CHECK_INTERVAL = 10
SUSPICIOUS_IPS = ["192.168.1.100", "10.0.0.200"]
MAX_NETWORK_THRESHOLD = 1000000

if platform.system() == 'Windows':
    MONITORED_PATHS = [os.path.join("C:", "Windows", "System32", "drivers", "etc", "hosts")]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("hids.log"), logging.StreamHandler()],
)

def calculate_hash(file_path):
    hash_func = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        logging.warning(f"File not found: {file_path}")
        return None
    except PermissionError:
        logging.warning(f"Permission denied: {file_path}")
        return None

def load_hashes():
    if os.path.exists(HASH_STORE):
        with open(HASH_STORE, "r") as f:
            return json.load(f)
    return {}

def save_hashes(hashes):
    try:
        with open(HASH_STORE, "w") as f:
            json.dump(hashes, f, indent=4)
    except IOError as e:
        logging.error(f"Failed to save hashes: {e}")

def show_alert(message):
    try:
        if platform.system() == 'Windows':
            notification.notify(
                title="Security Alert!",
                message=message,
                timeout=15,
                app_icon=None
            )
        elif platform.system() == 'Darwin':
            notification.notify(
                title="Security Alert!",
                message=message,
                timeout=15,
                app_icon=None
            )
        else:
            subprocess.run([
                "notify-send",
                "-u", "critical",
                "-t", "15000",
                "-i", "dialog-warning",
                "Security Alert!",
                message
            ], check=True)
    except Exception as e:
        logging.error(f"Failed to send notification: {e}")

def monitor_files():
    stored_hashes = load_hashes()
    current_hashes = {}

    for path in MONITORED_PATHS:
        file_hash = calculate_hash(path)
        current_hashes[path] = file_hash

        if path in stored_hashes:
            if stored_hashes[path] != file_hash:
                if file_hash is None:
                    alert_message = f"WARNING: File deleted: {path}"
                else:
                    alert_message = f"ALERT: File modified: {path}"
                logging.warning(alert_message)
                show_alert(alert_message)
        elif file_hash is not None:
            alert_message = f"New file added to monitoring: {path}"
            logging.info(alert_message)
            show_alert(alert_message)

    save_hashes(current_hashes)

def monitor_network():
    if not hasattr(monitor_network, "previous_bytes"):
        monitor_network.previous_bytes = psutil.net_io_counters()

    net_io = psutil.net_io_counters()
    bytes_sent = net_io.bytes_sent - monitor_network.previous_bytes.bytes_sent
    bytes_recv = net_io.bytes_recv - monitor_network.previous_bytes.bytes_recv
    monitor_network.previous_bytes = net_io

    if bytes_sent > MAX_NETWORK_THRESHOLD or bytes_recv > MAX_NETWORK_THRESHOLD:
        alert_message = "WARNING: High network traffic detected! Possible flood."
        logging.warning(alert_message)
        show_alert(alert_message)

    suspicious_activity = False
    for conn in psutil.net_connections(kind="inet"):
        if conn.raddr and conn.raddr.ip in SUSPICIOUS_IPS:
            suspicious_activity = True
            alert_message = f"ALERT: Suspicious connection detected to {conn.raddr.ip}"
            logging.warning(alert_message)
            show_alert(alert_message)

    if not suspicious_activity:
        logging.info("No suspicious network activity detected.")

if __name__ == "__main__":
    logging.info("Starting HIDS monitoring system...")
    try:
        while True:
            monitor_files()
            monitor_network()
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        logging.info("HIDS monitoring stopped by user.")
