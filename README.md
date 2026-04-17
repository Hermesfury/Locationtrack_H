# Locationtrack_H

**Link Recon** is an advanced reconnaissance tool for gathering comprehensive information about targets through web-based tracking. It creates a local server that collects browser fingerprints, geolocation data, network details, and system information when visitors access the served page.

## Features

- **Precise Location Tracking**: IP geolocation + HTML5 GPS coordinates
- **Browser Fingerprinting**: User agent, screen resolution, timezone, WebGL
- **Network Intelligence**: Local IP discovery via WebRTC, LAN scanning
- **System Probing**: Checks for sensitive file existence
- **Visual Capture**: Automatic screenshots
- **Multiple Export Formats**: JSON, CSV, SQLite, KML, HTML reports
- **Real-time Dashboard**: Live statistics at `/dashboard`
- **Security Features**: Rate limiting, HTTPS support, authentication

## Quick Start

```bash
# Navigate to Link_Recon directory
cd Link_Recon

# Setup virtual environment (recommended)
setup_venv.bat

# Run the tool
python infogather.py

# Access dashboard at http://localhost:5000/dashboard
```

## Usage

```bash
# Basic usage
python infogather.py

# Custom port and HTTPS
python infogather.py --port 8080 --https

# Load custom config
python infogather.py --config my_config.json
```

## Location Tracking

### Current Capabilities
- **IP Geolocation**: City-level accuracy using multiple APIs (ipinfo.io, ipapi.co)
- **HTML5 GPS**: Precise coordinates (meter-level) when user grants permission
- **Google Maps Integration**: Automatic map links generated for all coordinates

### Enhanced Tracking
For active targets, the tool already provides:
- Real-time Google Maps links in reports
- KML files for Google Earth visualization
- Coordinate export for external mapping tools

To achieve pinpoint location for online users:
1. **IP Geolocation**: Already implemented with fallback APIs
2. **GPS Permission**: Prompts user for precise location
3. **WiFi Positioning**: Inferred from IP and network data
4. **Social Engineering**: Combine with OSINT tools for cross-referencing

**Note**: Legal and ethical use only. Always obtain proper authorization.

## Requirements

- Python 3.8+
- No external dependencies (uses standard library only)

## Security Notice

This tool is for **educational and authorized security research purposes only**. Unauthorized use is illegal. Always obtain written permission before conducting reconnaissance.

## License

Educational purposes only.
