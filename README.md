# NetScope

NetScope is an advanced multi-threaded IP port scanner that scans random public IP addresses for open ports. It features comprehensive service version detection similar to nmap -sV, analyzing response behavior, timing patterns, and TCP characteristics to identify services like Apache, OpenSSH, nginx, and more.

## Features

- Multi-threaded scanning for high performance
- Random IP address scanning (excludes private IP ranges)
- **Advanced service version detection (-sV)**:
  - TCP handshake analysis (window size, timing)
  - Response behavior fingerprinting
  - Protocol-specific banner grabbing
  - Confidence scoring system
- **IoT device discovery (-iot)**:
  - Focused scanning of common IoT ports (23, 80, 443, 554, 1900, etc.)
  - Device type identification (cameras, routers, DVRs, smart TVs, etc.)
  - Vendor recognition (Hikvision, Dahua, TP-Link, Synology, etc.)
  - Fire-and-forget SYN packet approach for efficiency
- Service detection for 20+ protocols (HTTP, SSH, FTP, SMTP, MySQL, PostgreSQL, etc.)
- Multiple output formats: TXT, JSON, CSV with IoT device information
- Real-time results display with device type identification
- Graceful shutdown with Ctrl+C

## Prerequisites

- GCC compiler
- POSIX threads (pthread) library
- Linux/Unix-like operating system

## Installation

1. Clone or download the source code
2. Navigate to the project directory
3. Build the application:

```bash
make
```

This will create the `netscope` executable.

## Usage

### Basic Usage

```bash
./netscope
```

This starts scanning with default settings:
- 100 threads
- Port 80
- TXT output format

### Command Line Options

```bash
./netscope [threads] [--ports port1,port2,...] [--out format] [-ss|--syn] [-iot]
```

- `threads`: Number of scanning threads (1-500, default: 100)
- `--ports port1,port2,...`: Comma-separated list of ports to scan (default: 80)
- `--out format`: Output format (txt, json, csv)
- `-ss` or `--syn`: Use TCP SYN scanning (half-open scanning) for stealthier and more accurate port detection
- `-iot`: IoT device scanning mode - focuses on common IoT ports and identifies device types

### Examples

Scan port 443 with 50 threads:
```bash
./netscope 50 --ports 443
```

Scan multiple ports (21, 22, 80, 443, 3306) with service detection:
```bash
./netscope --ports 21,22,80,443,3306
```

Scan common web ports with JSON output:
```bash
./netscope --ports 80,443,8080,8443 --out json
```

Scan port 22 with 200 threads and CSV output:
```bash
./netscope 200 --ports 22 --out csv
```

Comprehensive service scan (web, database, SSH):
```bash
./netscope 150 --ports 22,80,443,3306,5432 --out json
```

Use TCP SYN scanning for stealthier detection:
```bash
./netscope -ss --ports 22,80,443
```

IoT device discovery:
```bash
./netscope -iot --out json
```

## Output

### Console Output

During scanning, results are displayed in real-time with service detection:
```
Found: 192.168.1.1:80 (25ms, Apache/2.4.41) [Apache 2.4.x 95%]
Found: 10.0.0.1:22 (15ms, SSH-2.0-OpenSSH_8.2p1) [OpenSSH 8.x 98%]
Found: 172.16.0.1:3306 (8ms) [MySQL 8.x 90%]
```

### File Output

Results are saved to two locations:

1. **ip.txt**: Simple list of IP addresses (appends to existing file)
2. **./out/scan_results.{format}**: Detailed results in selected format

### Output Formats

#### TXT Format (scan_results.txt)
```
IP Address	Port	Status	Latency (ms)	Banner	TCP Window	Response Time (ms)	Response Pattern	Detected Service	Version	Confidence	IoT Vendor	IoT Device Model
192.168.1.1	80	open	25	Apache/2.4.41	64240	18	Apache	Apache	2.4.x	95	Router	Network Router
10.0.0.1	22	open	15	SSH-2.0-OpenSSH_8.2p1	64240	12	SSH-2.0-OpenSSH	OpenSSH	8.x	98	Unknown	IoT Device
172.16.0.1	554	open	12	RTSP/1.0 200 OK	16384	8	RTSP	Unknown		0	IP Camera	Network Camera
```

#### JSON Format (scan_results.json)
```json
[
  {
    "ip": "192.168.1.1",
    "port": 80,
    "status": "open",
    "latency_ms": 25,
    "banner": "Apache/2.4.41",
    "tcp_window_size": 64240,
    "response_time_ms": 18,
    "response_pattern": "Apache",
    "detected_service": "Apache",
    "detected_version": "2.4.x",
    "confidence_level": 95,
    "iot_vendor": "Router",
    "iot_device_model": "Network Router"
  }
]
```

#### CSV Format (scan_results.csv)
```csv
ip,port,status,latency_ms,banner,tcp_window_size,response_time_ms,response_pattern,detected_service,detected_version,confidence_level,iot_vendor,iot_device_model
192.168.1.1,80,open,25,"Apache/2.4.41",64240,18,"Apache","Apache","2.4.x",95,"Router","Network Router"
10.0.0.1,22,open,15,"SSH-2.0-OpenSSH_8.2p1",64240,12,"SSH-2.0-OpenSSH","OpenSSH","8.x",98,"Unknown","IoT Device"
172.16.0.1,554,open,12,"RTSP/1.0 200 OK",16384,8,"RTSP","Unknown","",0,"IP Camera","Network Camera"
```

## Stopping the Scanner

Press `Ctrl+C` to stop scanning. The application will display the total number of hosts found and save results before exiting.

## Service Version Detection (-sV)

NetScope includes comprehensive service version detection similar to `nmap -sV`. It analyzes multiple characteristics to identify running services:

### Detection Methods

- **TCP Analysis**: Window size and connection timing patterns
- **Banner Analysis**: Protocol-specific banner grabbing and parsing
- **Response Behavior**: How services respond to probes and handshakes
- **Timing Analysis**: Response time patterns unique to different services

### Supported Services

- **Web Servers**: Apache (2.2.x, 2.4.x), nginx (1.x), Microsoft-IIS (10.0)
- **SSH Servers**: OpenSSH (7.x, 8.x)
- **FTP Servers**: vsftpd (3.x)
- **Mail Servers**: SMTP, POP3, IMAP services
- **Databases**: MySQL (8.x), PostgreSQL (13.x)
- **DNS Servers**: BIND version detection

### Confidence Levels

Results include confidence percentages (0-100%) indicating how certain the detection is:
- **90-100%**: High confidence (banner match + timing patterns)
- **70-89%**: Medium confidence (partial banner match + TCP characteristics)
- **30-69%**: Low confidence (TCP characteristics only)
- **0-29%**: Unknown service

### Example Output

```
Found: 192.168.1.1:80 (25ms, Apache/2.4.41) [Apache 2.4.x 95%]
Found: 10.0.0.1:22 (15ms, SSH-2.0-OpenSSH_8.2p1) [OpenSSH 8.x 98%]
Found: 172.16.0.1:3306 (8ms) [MySQL 8.x 90%]
```

## Technical Details

- Maximum 500 concurrent threads
- Maximum 10,000 scan results
- 100ms connection timeout
- Automatic exclusion of private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 0.0.0.0)
- **Three scanning methods**:
  - **TCP Connect Scan** (default): Full TCP connection for reliable banner grabbing
  - **TCP SYN Scan** (-sS): Half-open scanning using raw sockets for stealthier detection
  - **IoT Device Scan** (-iot): Optimized scanning for Internet of Things devices
- **Service version detection for 20+ protocols**:
  - TCP handshake analysis (window size, response timing)
  - Protocol-specific banner grabbing (HTTP, SSH, FTP, SMTP, POP3, IMAP, MySQL, PostgreSQL, DNS)
  - Fingerprint matching with confidence scoring
- Supported services: Apache, nginx, OpenSSH, vsftpd, MySQL, PostgreSQL, Microsoft-IIS, and more
- **IoT Device Types**: IP Cameras (Hikvision, Dahua, Foscam), DVR/NVR systems, Routers (TP-Link, D-Link), Smart TVs (Samsung, LG), Smart bulbs (Philips Hue), Thermostats (Nest), Network printers (HP), NAS devices (Synology, QNAP), and more

## TCP SYN Scanning (-sS)

TCP SYN scanning provides stealthier port detection by using raw sockets to send SYN packets without completing the full TCP handshake. This method is more accurate for determining port states and less likely to be logged by target systems.

### Features

- **Half-open scanning**: Sends SYN packets and analyzes responses without completing connections
- **Accurate port state detection**:
  - **open**: SYN-ACK response received
  - **closed**: RST response received
  - **filtered**: No response or ICMP unreachable
- **Stealth mode**: Less detectable than full connection scans
- **Raw socket implementation**: Direct packet crafting and analysis

### Usage

```bash
# Use SYN scanning instead of connect scanning
./netscope -ss --ports 22,80,443

# Combine with service detection
./netscope -ss --ports 21,22,80,443,3306 --out json
```

### How it works

1. **Packet Crafting**: Creates TCP SYN packets with proper IP and TCP headers
2. **Checksum Calculation**: Computes correct TCP and IP checksums
3. **Response Analysis**: Monitors for SYN-ACK (open), RST (closed), or no response (filtered)
4. **Banner Grabbing**: For open ports, follows up with regular connection to grab banners
5. **Service Detection**: Applies fingerprinting analysis to identify services

### Requirements

- **Root privileges**: Required for raw socket operations
- **Linux/Unix**: Raw socket support needed

Run with sudo for SYN scanning:
```bash
sudo ./netscope -ss --ports 22,80,443
```

## IoT Device Scanning (-iot)

NetScope includes specialized IoT device discovery that focuses on identifying Internet of Things devices in your network. This mode uses optimized scanning techniques specifically designed for IoT devices.

### Features

- **IoT-Specific Port Scanning**: Focuses on ports commonly used by IoT devices (23, 80, 443, 554, 1900, 2323, 37777, etc.)
- **Device Type Identification**: Recognizes cameras, routers, DVRs, smart TVs, thermostats, printers, NAS devices, and more
- **Vendor Recognition**: Identifies manufacturers like Hikvision, Dahua, TP-Link, Synology, Samsung, etc.
- **Fire-and-Forget SYN Packets**: Sends SYN packets without waiting for responses for maximum efficiency
- **Smart Banner Analysis**: Analyzes device responses to determine device types and capabilities

### Supported IoT Device Types

- **IP Cameras**: Hikvision, Dahua, Foscam network cameras
- **Video Recorders**: DVR and NVR systems from various manufacturers
- **Routers**: TP-Link, D-Link, and other network routers
- **Smart TVs**: Samsung, LG smart televisions
- **Smart Home**: Philips Hue lights, Nest thermostats
- **Network Storage**: Synology, QNAP NAS devices
- **Printers**: HP network printers
- **Other Devices**: Smart doorbells, IP phones, embedded web servers

### Usage Examples

```bash
# Basic IoT device discovery
./netscope -iot

# IoT scanning with JSON output for analysis
./netscope -iot --out json

# IoT scanning with service detection
./netscope -iot --out csv
```

### How it Works

1. **Port Selection**: Scans only ports commonly used by IoT devices
2. **SYN Packet Flood**: Sends SYN packets to all target ports simultaneously
3. **Connection Attempts**: Tries to connect to responsive ports
4. **Banner Analysis**: Extracts and analyzes device banners
5. **Device Classification**: Matches banners against known IoT device fingerprints
6. **Result Reporting**: Reports device types, vendors, and capabilities

### Example Output

```
IoT Found: 192.168.1.100:80 (45ms) [IP Camera - Network Camera] [Apache 2.4.x 85%]
IoT Found: 10.0.0.50:554 (23ms) [IP Camera - Network Camera]
IoT Found: 172.16.0.25:80 (67ms) [Router - Network Router] [nginx 1.x 92%]
IoT Found: 192.168.1.200:37777 (12ms) [DVR - Digital Video Recorder]
```

### Requirements

- **Root privileges**: Required for raw socket operations (same as SYN scanning)
- **Fast Network**: IoT scanning can generate significant network traffic

Run IoT scanning with sudo:
```bash
sudo ./netscope -iot --out json
```

## Build Targets

- `make`: Build the application
- `make clean`: Remove build artifacts
- `make install`: Install to /usr/local/bin (requires root)
- `make uninstall`: Remove from /usr/local/bin (requires root)

## Project Structure

```
netscope/
├── src/           # Source files
│   ├── main.c         # Main application logic
│   ├── args.c         # Command line argument parsing
│   ├── scanner.c      # Connect scanning implementation
│   ├── syn_scan.c     # TCP SYN scanning implementation (-sS)
│   ├── iot_scan.c     # IoT device scanning implementation (-iot)
│   ├── banner.c       # Enhanced service banner detection
│   ├── output.c       # Result export functions
│   ├── signal.c       # Signal handling
│   ├── utils.c        # Utility functions
│   └── service_detect.c # Service version detection (-sV)
├── include/       # Header files
│   ├── common.h       # Common definitions and structures
│   ├── args.h         # Argument parsing
│   ├── scanner.h      # Connect scanner interface
│   ├── syn_scan.h     # SYN scanner interface
│   ├── iot_scan.h     # IoT scanner interface
│   ├── banner.h       # Banner detection
│   ├── output.h       # Output interface
│   ├── signal.h       # Signal handling
│   └── service_detect.h # Service detection interface
├── out/           # Output directory
├── Makefile       # Build configuration
└── README.md      # This file
```
