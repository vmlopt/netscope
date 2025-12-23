# NetScope

NetScope is a multi-threaded IP port scanner that scans random public IP addresses for open ports. It can detect service banners and export results in multiple formats.

## Features

- Multi-threaded scanning for high performance
- Random IP address scanning (excludes private IP ranges)
- Service banner detection for HTTP services
- Multiple output formats: TXT, JSON, CSV
- Real-time results display with latency information
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
./netscope [threads] [--ports port1,port2,...] [--out format]
```

- `threads`: Number of scanning threads (1-500, default: 100)
- `--ports port1,port2,...`: Comma-separated list of ports to scan (default: 80)
- `--out format`: Output format (txt, json, csv)

### Examples

Scan port 443 with 50 threads:
```bash
./netscope 50 --ports 443
```

Scan multiple ports (21, 22, 80, 443, 3306):
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

## Output

### Console Output

During scanning, results are displayed in real-time:
```
Found: 192.168.1.1 (port 80, 45ms, nginx/1.18.0)
Found: 10.0.0.1 (port 80, 23ms)
```

### File Output

Results are saved to two locations:

1. **ip.txt**: Simple list of IP addresses (appends to existing file)
2. **./out/scan_results.{format}**: Detailed results in selected format

### Output Formats

#### TXT Format (scan_results.txt)
```
IP Address	Port	Status	Latency (ms)	Banner
192.168.1.1	80	open	45	nginx/1.18.0
10.0.0.1	80	open	23
```

#### JSON Format (scan_results.json)
```json
[
  {
    "ip": "192.168.1.1",
    "port": 80,
    "status": "open",
    "latency_ms": 45,
    "banner": "nginx/1.18.0"
  }
]
```

#### CSV Format (scan_results.csv)
```csv
ip,port,status,latency_ms,banner
192.168.1.1,80,open,45,"nginx/1.18.0"
10.0.0.1,80,open,23,""
```

## Stopping the Scanner

Press `Ctrl+C` to stop scanning. The application will display the total number of hosts found and save results before exiting.

## Technical Details

- Maximum 500 concurrent threads
- Maximum 10,000 scan results
- 100ms connection timeout
- Automatic exclusion of private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 0.0.0.0)
- HTTP banner detection for ports 80 and 443

## Build Targets

- `make`: Build the application
- `make clean`: Remove build artifacts
- `make install`: Install to /usr/local/bin (requires root)
- `make uninstall`: Remove from /usr/local/bin (requires root)

## Project Structure

```
netscope/
├── src/           # Source files
│   ├── main.c     # Main application logic
│   ├── args.c     # Command line argument parsing
│   ├── scanner.c  # Scanning thread implementation
│   ├── banner.c   # Service banner detection
│   ├── output.c   # Result export functions
│   ├── signal.c   # Signal handling
│   └── utils.c    # Utility functions
├── include/       # Header files
│   ├── common.h   # Common definitions
│   ├── args.h     # Argument parsing
│   ├── scanner.h  # Scanner interface
│   ├── banner.h   # Banner detection
│   ├── output.h   # Output interface
│   └── signal.h   # Signal handling
├── out/           # Output directory
├── Makefile       # Build configuration
└── README.md      # This file
```
