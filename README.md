# Network Scanner

This Python script is a network scanner that identifies active devices within a specified IP range. It is useful for network administration, penetration testing, and educational purposes.

## Features

- Scans the local network or a specified IP range.
- Displays active devices' IP and MAC addresses in real-time.
- Continuously scans the network at a defined interval.

## Prerequisites

- Python 3.x
- `scapy` library
- `netifaces` library

## Setup

1. **Clone the repository:**

    ```bash
    git clone https://github.com/yourusername/network-scanner.git
    cd network-scanner
    ```

2. **Create and activate the virtual environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install required dependencies:**

    ```bash
    pip install scapy netifaces
    ```

## Usage

To scan the network, run the script with root privileges:

1. Ensure you are in the virtual environment:

    ```bash
    source venv/bin/activate
    ```

2. **Run the script with sudo:**

    ```bash
    sudo python3 network_scanner.py -r [IP Range]
    ```

   If no IP range is specified, the script will automatically use the local machine's IP range.

## Example

```bash
sudo python3 network_scanner.py -r 192.168.1.0/24
```
