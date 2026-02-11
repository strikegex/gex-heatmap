"""
GEX Heatmap Server — Flask + Schwab auto-fetch
"""
import os, json, threading, time, base64
from datetime import datetime
from flask import Flask, render_template, jsonify, Response

app = Flask(__name__)

# ─── State ───
gex_data = {}
last_fetch = None
fetch_lock = threading.Lock()

# ─── Config ───
APP_KEY = os.environ.get("SCHWAB_APP_KEY", "")
FETCH_INTERVAL = int(os.environ.get("FETCH_INTERVAL", "300"))  # 5 min
SYMBOLS = os.environ.get("SYMBOLS", "SPX,SPY,QQQ,IWM").split(",")

def fetch_loop():
    """Background fetcher - SAFE version with dummy data if Schwab fails"""
    global gex_data, last_fetch
    
    # Dummy data for testing (no Schwab needed)
    dummy_data = {
        "SPX": {"spot": 5500, "king_strike": 5500, "total_gex": 125000000, "timestamp": "test"},
        "SPY": {"spot": 550, "king_strike": 550, "total_gex": 25000000, "timestamp": "test"}
    }
    
    while True:
        try:
            # Try Schwab (will work once you add keys)
            if APP_KEY:
                try:
                    import gex_fetcher as gf
                    # Your Schwab code here
                    gex_data = dummy_data  # Replace with real data later
                except Exception as e:
                    print(f"Schwab fetch failed: {e}")
                    gex_data = dummy_data
            
            else:
                gex_data = dummy_data
            
            with fetch_lock:
                last_fetch = datetime.now().isoformat()
            
            print(f"✅ Data updated @ {datetime.now().strftime('%H:%M:%S')}")
            
        except Exception as e:
            print(f"⚠️ Fetch error: {e}")
        
        time.sleep(FETCH_INTERVAL)

@app.route("/")
def index():
    """Serve heatmap - FIXED"""
    return render_template("gex_heatmap.html")

@app.route("/api/gex")
def api_gex():
    with fetch_lock:
        return jsonify(gex_data)

@app.route("/api/status")
def api_status():
    return jsonify({
        "status": "ok",
        "last_fetch": last_fetch,
        "symbols": SYMBOLS,
        "interval": FETCH_INTERVAL,
        "schwab_key": bool(APP_KEY)
    })

if __name__ == "__main__":
    # Start fetcher if Schwab keys exist
    if APP_KEY:
        t = threading.Thread(target=fetch_loop, daemon=True)
        t.start()
        print(f"🔄 Auto-fetch started: {', '.join(SYMBOLS)}")
    
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
