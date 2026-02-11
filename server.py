from flask import Flask, render_template, jsonify
import gex_fetcher
import os
from threading import Thread
import time

app = Flask(__name__)

# Store latest GEX data
gex_data = {}

def fetch_gex_loop():
    """Background thread to fetch GEX data periodically"""
    global gex_data
    while True:
        try:
            gex_data = gex_fetcher.fetch_gex_data()
            print("GEX data updated")
        except Exception as e:
            print(f"Error fetching GEX: {e}")
        time.sleep(300)  # Update every 5 minutes

@app.route('/')
def index():
    return render_template('gex_heatmap.html')

@app.route('/api/gex')
def get_gex():
    return jsonify(gex_data)

if __name__ == '__main__':
    # Start background fetcher
    fetcher_thread = Thread(target=fetch_gex_loop, daemon=True)
    fetcher_thread.start()
    
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
