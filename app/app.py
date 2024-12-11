from flask import Flask, render_template
import requests

app = Flask(__name__)

RYU_API_URL = "http://127.0.0.1:8080"  # Adjust if different

@app.route('/')
def index():
    # Fetch stats from Ryu's REST API
    try:
        flow_stats = requests.get(f"{RYU_API_URL}/stats/flow").json()
        port_stats = requests.get(f"{RYU_API_URL}/stats/port").json()
        scan_stats = requests.get(f"{RYU_API_URL}/stats/scans").json()
        dos_stats = requests.get(f"{RYU_API_URL}/stats/dos").json()
    except Exception as e:
        flow_stats = {}
        port_stats = {}
        scan_stats = {"count":0, "events":[]}
        dos_stats = {"count":0, "events":[]}

    return render_template('index.html',
                           flow_stats=flow_stats,
                           port_stats=port_stats,
                           scan_stats=scan_stats,
                           dos_stats=dos_stats)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
