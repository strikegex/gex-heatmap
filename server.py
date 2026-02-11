"""
GEX Heatmap Server — Flask + Schwab auto-fetch
Serves gex_heatmap.html and fetches fresh data every 5 minutes.

Deploy to Railway with env vars:
  SCHWAB_APP_KEY, SCHWAB_APP_SECRET, SCHWAB_TOKEN_B64
"""
import os, json, threading, time, base64
from datetime import datetime
from flask import Flask, send_file, jsonify

app = Flask(__name__)

# ─── State ───
gex_data = {}
last_fetch = None
fetch_lock = threading.Lock()

# ─── Config from env ───
APP_KEY = os.environ.get("SCHWAB_APP_KEY", "")
APP_SECRET = os.environ.get("SCHWAB_APP_SECRET", "")
CALLBACK_URL = os.environ.get("SCHWAB_CALLBACK_URL", "https://127.0.0.1:8182/")
TOKEN_PATH = os.environ.get("SCHWAB_TOKEN_PATH", "schwab_token.json")
FETCH_INTERVAL = int(os.environ.get("FETCH_INTERVAL", "300"))  # 5 min default
SYMBOLS = os.environ.get("SYMBOLS", "SPX,SPY,QQQ,IWM").split(",")

# ─── Decode token from env if needed ───
TOKEN_B64 = os.environ.get("SCHWAB_TOKEN_B64", "")
if TOKEN_B64 and not os.path.exists(TOKEN_PATH):
    try:
        with open(TOKEN_PATH, "wb") as f:
            f.write(base64.b64decode(TOKEN_B64))
        print("✅ Token decoded from SCHWAB_TOKEN_B64")
    except Exception as e:
        print(f"⚠️ Token decode failed: {e}")


def fetch_loop():
    """Background: fetch GEX from Schwab every FETCH_INTERVAL seconds."""
    global gex_data, last_fetch
    import gex_fetcher as gf

    client = None
    history = gf.load_history()

    while True:
        try:
            if client is None:
                from schwab import auth
                client = auth.easy_client(
                    api_key=APP_KEY, app_secret=APP_SECRET,
                    callback_url=CALLBACK_URL, token_path=TOKEN_PATH
                )
                print("✅ Schwab client ready")

            data = {}
            for sym in SYMBOLS:
                try:
                    data[sym] = gf.fetch_gex(client, sym, history)
                except Exception as e:
                    print(f"  ⚠️ {sym}: {e}")

            if data:
                gf.save_history(history)
                with fetch_lock:
                    gex_data = data
                    last_fetch = datetime.now().isoformat()
                with open("gex_data.json", "w") as f:
                    json.dump(data, f)
                print(f"  ✅ {len(data)} symbols @ {datetime.now().strftime('%H:%M:%S')}")

        except Exception as e:
            print(f"  ⚠️ Fetch error: {e}")
            client = None

        time.sleep(FETCH_INTERVAL)


@app.route("/")
def index():
    return send_file("gex_heatmap.html")


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
    })


if __name__ == "__main__":
    if APP_KEY:
        t = threading.Thread(target=fetch_loop, daemon=True)
        t.start()
        print(f"🔴 Auto-fetch: {','.join(SYMBOLS)} every {FETCH_INTERVAL}s")
    else:
        print("⚠️ No SCHWAB_APP_KEY — static mode only")

    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
