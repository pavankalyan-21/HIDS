# Host Intrusion Detection System (HIDS)

This script monitors changes in critical system files and network activity, providing real-time alerts for suspicious activity. It aims to detect modifications in sensitive files and abnormal network traffic, helping to identify potential security threats.

## Features

- **File Integrity Monitoring**: Monitors critical system files for any changes, additions, or deletions. 
- **Network Activity Monitoring**: Detects suspicious network connections and abnormal traffic patterns.
- **Cross-platform Support**: Compatible with Windows, macOS, and Linux.

## Requirements

- Python 3.x
- Required Python libraries: `psutil`, `plyer`

## Setup

1. Clone this repository or download the script to your machine.

2. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Adjust the `MONITORED_PATHS` and `SUSPICIOUS_IPS` in the script to fit your specific needs.
   
    - `MONITORED_PATHS`: List of file paths to monitor. Defaults are for Linux-based systems (`/etc/passwd`, `/etc/shadow`, `/etc/hosts`). For Windows, the `hosts` file in `C:\Windows\System32\drivers\etc` is monitored.
    - `SUSPICIOUS_IPS`: List of IPs to monitor for suspicious network activity.

4. Run the script:

    ```bash
    python hids_monitor.py
    ```

5. The script will start monitoring files and network activity, logging alerts, and sending notifications for suspicious events.

## Examples

Here are some example files to help you understand the HIDS functionality:

- [file_hashes.json](examples/file_hashes.json): Contains example hashes for monitored files.
- [hids.log](examples/hids.log): A sample log file showing HIDS alerts and monitoring activity.

To view these files, navigate to the `examples/` directory in the repository or click the links above.

## Alerts

- **File Monitoring**:
    - Alerts when a monitored file is modified, deleted, or a new file is added to the list.
- **Network Monitoring**:
    - Alerts when abnormal network traffic is detected or if a suspicious connection is found.

## Customization

- You can modify the `CHECK_INTERVAL` to change the monitoring frequency (in seconds).
- You can adjust the `MAX_NETWORK_THRESHOLD` to set the threshold for network traffic before an alert is triggered.

## Troubleshooting

- If you encounter any issues with notifications, ensure that the necessary notification systems are installed on your OS. For example:
  - Linux: `libnotify-bin` package should be installed for `notify-send` to work.
  - Windows/macOS: The `plyer` library handles notifications.

