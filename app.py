
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from pymongo import MongoClient
import certifi
from scapy.all import sniff, IP
import threading
from datetime import datetime
import requests

app = Flask(__name__)
socketio = SocketIO(app)

# MongoDB connection
try:
    client = MongoClient(
        "mongodb+srv://ansuhka1528_db_user:Annu1528@cloudshieldids.gwpko52.mongodb.net/?retryWrites=true&w=majority&appName=CloudShieldIDS",
        tlsCAFile=certifi.where()
    )
    db = client.cloudshield
    collection = db.traffic_logs
    sample_data = {
        "traffic": {"value": "1,248", "change": "+12%"},
        "safe_connections": {"value": "1,134", "change": "+8%"},
        "threats": {"value": "14", "change": "+3%"}
    }
    if collection.count_documents({}) == 0:
        collection.insert_one(sample_data)
        print("✅ Sample data inserted!")
    else:
        print("ℹ️ Collection already has data, skipping insert.")
except Exception as e:
    print("❌ MongoDB connection failed:", e)
    collection = None

# Thread control
monitoring_thread = None
stop_sniffing = False

def monitor_packets():
    def process_packet(packet):
        global stop_sniffing
        if stop_sniffing:
            return False
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            log = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "IP Packet",
                "source": src,
                "target": dst,
                "severity": "Low"
            }
            collection.insert_one(log)
            socketio.emit('new_log', log)

    sniff(prn=process_packet, store=False)

@app.route('/start-monitoring')
def start_monitoring():
    global monitoring_thread, stop_sniffing
    stop_sniffing = False
    if collection is not None:
        monitoring_thread = threading.Thread(target=monitor_packets)
        monitoring_thread.start()
        return "✅ Monitoring started!"
    else:
        return "❌ Cannot start monitoring. No DB connection."

@app.route('/stop-monitoring')
def stop_monitoring():
    global stop_sniffing
    stop_sniffing = True
    return "🛑 Monitoring stopped!"

@app.route('/check-url')
def check_url():
    url_to_check = request.args.get('url')
    if not url_to_check:
        return jsonify({"error": "Missing URL parameter"}), 400

    API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
    SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    payload = {
        "client": {
            "clientId": "cloudshield",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url_to_check}
            ]
        }
    }

    response = requests.post(SAFE_BROWSING_URL, json=payload)
    result = response.json()

    if "matches" in result:
        return jsonify({"safe": False, "details": result["matches"]})
    else:
        return jsonify({"safe": True, "message": "URL is safe."})

@app.route('/')
def dashboard():
    if collection is not None:
        logs = list(collection.find().sort('_id', -1).limit(50))

        traffic_count = len(logs)
        safe_count = sum(1 for log in logs if log['severity'] == 'Low')
        threat_count = sum(1 for log in logs if log['severity'] != 'Low')

        traffic = {"value": str(traffic_count), "change": "+0%"}
        safe_connections = {"value": str(safe_count), "change": "+0%"}
        threats = {"value": str(threat_count), "change": "+0%"}

        return render_template(
            "index.html",
            traffic=traffic,
            safe_connections=safe_connections,
            threats=threats,
            traffic_logs=logs
        )
    else:
        return "❌ Database connection failed."


    
@app.route('/add-threat', methods=['POST'])
def add_threat():
    if collection is None:
        return jsonify({"status": "error", "message": "Database not connected."})

    ip = request.form.get('ip')
    threat_type = request.form.get('type')
    target = request.form.get('target')
    severity = request.form.get('severity')

    log = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": threat_type,
        "source": ip,
        "target": target,
        "severity": severity
    }

    collection.insert_one(log)
    socketio.emit('new_log', log)
    return jsonify({"status": "success", "message": "Threat added successfully!"})




if __name__ == '__main__':
    print("🚀 Starting Flask server...")
    print("✅ Flask app is running. Visit http://127.0.0.1:5001 in your browser.")
    app.debug = True


    socketio.run(app, port=5001)


