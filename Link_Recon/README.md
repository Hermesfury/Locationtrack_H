# 🔐 Link Recon v2.0.0 - Industry Standard Edition

Advanced Link Information Gathering & Reconnaissance Tool

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Plugin Architecture](#plugin-architecture)
- [Dashboard](#dashboard)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Overview

Link Recon is a sophisticated information gathering tool designed for security research and authorized penetration testing. It creates a local web server that collects comprehensive target information when visitors access the served page.

### What It Does

When a target visits the served page, Link Recon collects:

1. **Browser Fingerprint**
   - User-Agent string
   - Screen resolution
   - Browser language
   - Timezone
   - WebGL support status
   - Local Storage availability

2. **Geolocation Data**
   - Public IP address
   - City, Region, Country
   - Geographic coordinates
   - Google Maps link

3. **Network Information**
   - Local IP addresses (via WebRTC)
   - Network type (WiFi, 4G, etc.)
   - Connection latency (RTT)
   - LAN scan results

4. **System Probes**
   - Sensitive file detection
   - Operating system details
   - Platform information

5. **Visual Capture**
   - Screenshot of the target page

---

## Features

### 🔍 Advanced Data Collection

- **Multi-API Geolocation**: Falls back to multiple geolocation services
- **HTML5 GPS Support**: Precise GPS coordinates with accuracy data
- **Async LAN Scanning**: Parallel scanning of common gateway IPs
- **WebRTC IP Detection**: Discovers local IP addresses through WebRTC
- **File System Probing**: Checks for common sensitive files

### 💾 Multiple Export Formats

- **JSON**: Structured data export
- **CSV**: Spreadsheet-compatible format
- **SQLite**: Queryable database
- **HTML**: Visual reports with embedded screenshots
- **KML**: Google Earth compatible maps

### 🛡️ Security Features

- **Rate Limiting**: Configurable requests per minute
- **HTTPS Support**: Self-signed certificate generation
- **Authentication**: Optional access tokens
- **Input Validation**: Comprehensive error handling

### 🎨 User Interface

- **Real-time Dashboard**: Live statistics and analytics
- **Structured Logging**: Detailed logs with rotation
- **Progress Indicators**: Visual feedback during operation

### 🔌 Extensible Architecture

- **Plugin System**: Add custom collectors and processors
- **Configuration Files**: JSON/YAML configuration support
- **REST API**: External integration capabilities

---

## Requirements

- Python 3.8+
- No external dependencies (uses standard library only)

### Recommended: Virtual Environment

Using a virtual environment ensures the tool works consistently across any PC:

```bash
# Windows - Run the setup script
setup_venv.bat

# Or manually:
python -m venv venv
venv\Scripts\activate
python infogather.py
```

### Optional Dependencies

For enhanced features:
- `openssl` - For HTTPS certificate generation

---

## Installation

### Quick Start (No Venv)

```bash
# Navigate to the Link_Recon directory
cd Link_Recon

# Run directly (works on any PC with Python)
python infogather.py
```

### Recommended: With Virtual Environment

```bash
# Windows - Double-click or run:
setup_venv.bat

# Or manually:
cd Link_Recon
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python infogather.py
```

### Using the Run Script

```bash
# Windows - Quick run with venv:
run.bat

# With custom port:
run.bat --port 8080
```

---

## ⚠️ Understanding File Probes

The `file_probes` configuration (robots.txt, .env, .git/config, .ssh/id_rsa) are **browser-based JavaScript probes** that check what files exist on the visitor's browser. These are NOT system commands on your server - they are probes sent to the visitor's browser.

---

## 📍 Precise Location Tracking

For pinpoint location accuracy, the tool uses multiple methods:

### 1. IP Geolocation (Default - ~city level)
- Uses ipinfo.io, ipapi.co, ip-api.com
- Accuracy: ~city level
- Works on all devices

### 2. HTML5 GPS Geolocation (Optional - ~meter level)

The tool uses the browser's HTML5 Geolocation API to request precise GPS coordinates:

**GPS Configuration:**

```json
{
  "enable_gps": true,
  "gps_timeout": 10,
  "gps_accuracy_threshold": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `enable_gps` | boolean | Enable GPS geolocation requests |
| `gps_timeout` | float | Timeout for GPS request (seconds) |
| `gps_accuracy_threshold` | int | Only use GPS if accuracy < X meters |

**How It Works:**

1. Browser requests location permission from visitor
2. If granted, GPS coordinates are sent to server
3. Coordinates are saved with accuracy information
4. KML files prioritize GPS over IP geolocation

**Notes:**
- Mobile devices with GPS: ~meter accuracy
- Desktop with WiFi: ~10-50 meter accuracy
- Desktop without WiFi: ~city block accuracy
- Visitors can deny permission

### 3. WebRTC IP Leak Detection
- Discovers local network IPs
- Helps identify precise network location

---

## Usage

### Basic Usage

```bash
# Run with default settings
python infogather.py

# Specify custom port
python infogather.py --port 8080

# Enable HTTPS
python infogather.py --https

# Load configuration from file
python infogather.py --config my_config.json

# Custom output directory
python infogather.py --output /path/to/reports
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--host` | Host to bind to | `0.0.0.0` |
| `--port` | Port to listen on | `5000` |
| `--https` | Enable HTTPS | `false` |
| `--cert` | SSL certificate file | `cert.pem` |
| `--key` | SSL key file | `key.pem` |
| `--config` | Configuration file path | `null` |
| `--output` | Output directory | `reports` |
| `--no-dashboard` | Disable dashboard | `false` |

---

## Configuration

### Configuration File

Create a `link_recon_config.json` file:

```json
{
  "host": "0.0.0.0",
  "port": 5000,
  "use_https": false,
  "rate_limit": 10,
  "lan_scan_timeout": 1.0,
  "lan_scan_range": [
    "192.168.1.1",
    "10.0.0.1",
    "192.168.0.1"
  ],
  "file_probes": [
    "/robots.txt",
    "/.env",
    "/.git/config"
  ],
  "output_dir": "reports",
  "export_json": true,
  "export_csv": true,
  "export_sqlite": true,
  "enable_dashboard": true
}
```

### Configuration Options

#### Server Settings

| Parameter | Type | Description |
|-----------|------|-------------|
| `host` | string | IP address to bind to |
| `port` | integer | Port number |
| `use_https` | boolean | Enable HTTPS |
| `rate_limit` | integer | Requests per minute |

#### Scanning Settings

| Parameter | Type | Description |
|-----------|------|-------------|
| `lan_scan_timeout` | float | Timeout for LAN scans (seconds) |
| `lan_scan_range` | array | IPs to scan |
| `file_probes` | array | Files to check for |

#### GPS Settings

| Parameter | Type | Description |
|-----------|------|-------------|
| `enable_gps` | boolean | Enable HTML5 GPS geolocation |
| `gps_timeout` | float | GPS request timeout (seconds) |
| `gps_accuracy_threshold` | int | Min accuracy threshold (meters) |

#### Output Settings

| Parameter | Type | Description |
|-----------|------|-------------|
| `output_dir` | string | Output directory path |
| `export_json` | boolean | Export as JSON |
| `export_csv` | boolean | Export as CSV |
| `export_sqlite` | boolean | Export to SQLite |
| `enable_dashboard` | boolean | Enable dashboard |

---

## Output Formats

### Directory Structure

```
reports/
├── recon_data.db          # SQLite database
├── report_abc123.json     # JSON export
├── report_abc123.csv      # CSV export
├── report_abc123.html     # HTML report
├── report_abc123.png      # Screenshot
└── link_recon.log        # Application log
```

### JSON Export

```json
{
  "report_id": "abc123...",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "ipInfo": {
      "ip": "192.168.1.100",
      "city": "Lagos",
      "country": "NG",
      "loc": "6.45,3.40"
    },
    "gpsData": {
      "gps_lat": 6.5244,
      "gps_lon": 3.3792,
      "gps_accuracy": 10,
      "gps_altitude": 15
    },
    "userAgent": "...",
    "platform": "Linux x86_64",
    "lanScan": {...},
    "fileHints": {...}
  }
}
```

### SQLite Database

Tables available:

- `reports`: Main reconnaissance data
- `sessions`: Session tracking
- `geolocation`: Cached IP geolocation

### HTML Report

Visual reports with:
- Geolocation map link
- Device information cards
- Network details
- Screenshot gallery
- Color-coded status indicators

---

## Plugin Architecture

### Creating a Plugin

```python
from infogather import PluginBase

class CustomPlugin(PluginBase):
    def __init__(self):
        super().__init__("MyPlugin", "1.0.0")
    
    def collect(self, data: dict) -> dict:
        # Add custom data collection
        data['custom_field'] = 'custom_value'
        return data
    
    def process(self, raw_data: dict) -> dict:
        # Add custom processing
        raw_data['processed'] = True
        return raw_data

# Load the plugin
plugin_manager.load_plugin(CustomPlugin)
```

### Plugin Lifecycle

1. **initialize(config)**: Called when plugin is loaded
2. **collect(data)**: Called during data collection phase
3. **process(raw_data)**: Called during data processing phase
4. **teardown()**: Called when plugin is unloaded

---

## Dashboard

Access the real-time dashboard at:

```
http://localhost:5000/dashboard
```

### Dashboard Features

- **Live Statistics**
  - Total reports count
  - Unique IP addresses
  - Top countries
  - Top platforms

- **Auto-refresh**
  - Updates every 30 seconds
  - Manual refresh available

---

## Security Considerations

### ⚠️ Legal Notice

This tool is provided for **educational purposes only**. Unauthorized use of this tool against systems you do not own or have explicit permission to test is **illegal**.

### Best Practices

1. **Always obtain written authorization** before conducting reconnaissance
2. **Document all activities** and scope
3. **Use rate limiting** to avoid overwhelming targets
4. **Enable HTTPS** for production use
5. **Secure your data** - reports may contain sensitive information
6. **Follow responsible disclosure** practices

### Recommended Deployment

```bash
# Run with HTTPS and authentication
python infogather.py --https --config secure_config.json

# Configure rate limiting
# "rate_limit": 5  # requests per minute
```

---

## Troubleshooting

### Common Issues

#### Port Already in Use

```bash
# Find process using port 5000
netstat -ano | findstr :5000

# Kill the process (Windows)
taskkill /PID <PID> /F

# Or use a different port
python infogather.py --port 8080
```

#### HTTPS Certificate Issues

```bash
# Regenerate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

#### Database Errors

```bash
# Delete and recreate database
rm reports/recon_data.db
python infogather.py
```

### Logging

Check the log file for detailed error information:

```bash
tail -f link_recon.log
```

---

## API Reference

### REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main reconnaissance page |
| `/log` | POST | Submit collected data |
| `/dashboard` | GET | Dashboard page |
| `/stats` | GET | Statistics JSON |

### Report Database

```python
# Access statistics
db = ReportDatabase()
stats = db.get_statistics()

# stats contains:
# {
#   'total_reports': 10,
#   'unique_ips': 5,
#   'top_cities': {...},
#   'top_countries': {...},
#   'top_platforms': {...}
# }
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Submit a pull request

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0.0 | 2024 | Industry standard rewrite |
| 1.0.0 | 2023 | Initial release |

---

## License

For educational purposes only. See [LICENSE](LICENSE) for details.

---

## Disclaimer

The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before conducting security testing.

---

**🔐 Link Recon v2.0.0** | Made with ❤️ for Security Research
