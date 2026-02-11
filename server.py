"""
Flask server: serves gex_heatmap.html and runs gex_fetcher on a schedule.
"""
import os, json, threading, time
from datetime import datetime, date, timedelta
from flask import Flask, send_file, jsonify, Response

app = Flask(__name__)

# ─── Global data store ───
gex_data = {}
last_fetch = None
fetch_lock = threading.Lock()

# ─── Schwab credentials from environment ───
APP_KEY = os.environ.get("SCHWAB_APP_KEY", "")
APP_SECRET = os.environ.get("SCHWAB_APP_SECRET", "")
CALLBACK_URL = os.environ.get("SCHWAB_CALLBACK_URL", "https://127.0.0.1:8182/")
TOKEN_PATH = os.environ.get("SCHWAB_TOKEN_PATH", "schwab_token.json")
FETCH_INTERVAL = int(os.environ.get("FETCH_INTERVAL", "60"))  # seconds
SYMBOLS = os.environ.get("SYMBOLS", "SPX,SPY,QQQ,IWM").split(",")


def get_client():
    """Create Schwab client (reuse token)."""
    from schwab import auth
    return auth.easy_client(
        api_key=APP_KEY, app_secret=APP_SECRET,
        callback_url=CALLBACK_URL, token_path=TOKEN_PATH
    )


def fetch_loop():
    """Background thread: fetch GEX data every FETCH_INTERVAL seconds."""
    global gex_data, last_fetch
    # Import the fetcher module
    import gex_fetcher as gf

    # Wait for market hours (optional, uncomment to restrict)
    # from datetime import time as dt_time
    # while True:
    #     now = datetime.now()
    #     if dt_time(9,30) <= now.time() <= dt_time(16,15):
    #         break
    #     time.sleep(60)

    client = None
    history = gf.load_history()

    while True:
        try:
            if client is None:
                client = get_client()
                print("✅ Schwab client ready")

            data = {}
            for sym in SYMBOLS:
                data[sym] = gf.fetch_gex(client, sym, history)

            gf.save_history(history)

            with fetch_lock:
                gex_data = data
                last_fetch = datetime.now().isoformat()

            # Also save to disk as backup
            with open("gex_data.json", "w") as f:
                json.dump(data, f)

            print(f"✅ Fetched {len(SYMBOLS)} symbols @ {datetime.now().strftime('%H:%M:%S')}")

        except Exception as e:
            print(f"⚠️ Fetch error: {e}")
            client = None  # Force re-auth on next attempt

        time.sleep(FETCH_INTERVAL)


@app.route("/")
def index():
    """Serve the heatmap HTML."""
    return send_file("gex_heatmap.html")


@app.route("/api/gex")
def api_gex():
    """Return current GEX data as JSON (for the heatmap to auto-fetch)."""
    with fetch_lock:
        return jsonify(gex_data)


@app.route("/api/status")
def api_status():
    """Health check."""
    return jsonify({
        "status": "ok",
        "last_fetch": last_fetch,
        "symbols": SYMBOLS,
        "interval": FETCH_INTERVAL,
    })


# ─── Stream endpoint: Server-Sent Events for real-time updates ───
@app.route("/api/stream")
def stream():
    """SSE stream — pushes new data to the frontend whenever it changes."""
    def generate():
        last_ts = None
        while True:
            with fetch_lock:
                current_ts = last_fetch
                data = gex_data.copy()
            if current_ts != last_ts and data:
                last_ts = current_ts
                yield f"data: {json.dumps(data)}\n\n"
            time.sleep(5)
    return Response(generate(), mimetype='text/event-stream')


if __name__ == "__main__":
    # Start fetch loop in background thread
    if APP_KEY:
        t = threading.Thread(target=fetch_loop, daemon=True)
        t.start()
        print(f"🔴 Fetch loop started: {', '.join(SYMBOLS)} every {FETCH_INTERVAL}s")
    else:
        print("⚠️ No SCHWAB_APP_KEY — serving static mode only")

    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
    from flask import Flask, render_template, jsonify

@app.route('/')
def index():
    return render_template('gex_heatmap.html')

