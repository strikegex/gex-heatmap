"""
GEX Heatmap Server — Flask + Schwab auto-fetch
Serves gex_heatmap.html and fetches fresh data every 5 minutes.

Deploy to Railway with env vars:
  SCHWAB_APP_KEY, SCHWAB_APP_SECRET, SCHWAB_TOKEN_B64
"""
import os, json, threading, time, base64
from datetime import datetime
from flask import Flask, send_from_directory, jsonify

app = Flask(__name__)

# ─── State ───
gex_data = {}
last_fetch = None
fetch_lock = threading.Lock()

# ─── Load existing data from disk if available (survives restarts) ───
if os.path.exists("gex_data.json"):
    try:
        with open("gex_data.json") as f:
            gex_data = json.load(f)
        last_fetch = gex_data.get(list(gex_data.keys())[0], {}).get("timestamp") if gex_data else None
        print(f"✅ Loaded cached gex_data.json ({len(gex_data)} symbols)")
    except:
        pass

# ─── Config from env ───
APP_KEY = os.environ.get("SCHWAB_APP_KEY", "")
APP_SECRET = os.environ.get("SCHWAB_APP_SECRET", "")
CALLBACK_URL = os.environ.get("SCHWAB_CALLBACK_URL", "https://127.0.0.1:8182/")
TOKEN_PATH = os.environ.get("SCHWAB_TOKEN_PATH", "schwab_token.json")
FETCH_INTERVAL = int(os.environ.get("FETCH_INTERVAL", "300"))  # 5 min default
SYMBOLS = os.environ.get("SYMBOLS", "SPX,SPY,QQQ,IWM").split(",")

# ─── Decode token from env EVERY startup (Railway filesystem is ephemeral) ───
TOKEN_B64 = os.environ.get("SCHWAB_TOKEN_B64", "")
if TOKEN_B64:
    try:
        token_bytes = base64.b64decode(TOKEN_B64)
        with open(TOKEN_PATH, "wb") as f:
            f.write(token_bytes)
        print(f"✅ Token decoded from SCHWAB_TOKEN_B64 ({len(token_bytes)} bytes)")
    except Exception as e:
        print(f"❌ Token decode failed: {e}")
else:
    print("⚠️ SCHWAB_TOKEN_B64 not set — token must already exist on disk")

if os.path.exists(TOKEN_PATH):
    print(f"✅ Token file exists: {TOKEN_PATH}")
else:
    print(f"❌ No token file at {TOKEN_PATH} — fetcher will not work!")
    print(f"   To fix: run locally, authenticate, then:")
    print(f"   cat schwab_token.json | base64 | tr -d '\\n'")
    print(f"   Paste result as SCHWAB_TOKEN_B64 env var in Railway")


def is_market_hours():
    """Check if US market is open (9:30am-4:00pm ET, weekdays). DST-aware."""
    try:
        from zoneinfo import ZoneInfo
        et = datetime.now(ZoneInfo("America/New_York"))
    except ImportError:
        from datetime import timezone, timedelta
        et = datetime.now(timezone(timedelta(hours=-5)))
    if et.weekday() >= 5:  # Weekend
        return False
    t = et.hour * 60 + et.minute
    return 565 <= t < 965  # 9:25am-4:05pm ET (5min buffer both sides)


def fetch_loop():
    """Background: fetch GEX from Schwab every FETCH_INTERVAL seconds."""
    global gex_data, last_fetch
    import gex_fetcher as gf

    client = None
    history = gf.load_history()

    while True:
        try:
            if not is_market_hours():
                print(f"  💤 Market closed — skipping fetch ({datetime.now().strftime('%H:%M:%S')} UTC)")
                time.sleep(FETCH_INTERVAL)
                continue

            if client is None:
                from schwab import auth
                if not os.path.exists(TOKEN_PATH):
                    print("❌ No token file — cannot authenticate. Set SCHWAB_TOKEN_B64 env var.")
                    time.sleep(60)
                    continue
                # Use client_from_token_file — NEVER opens a browser
                client = auth.client_from_token_file(
                    token_path=TOKEN_PATH,
                    api_key=APP_KEY,
                    app_secret=APP_SECRET,
                )
                print("✅ Schwab client ready (from token file)")

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
    return send_from_directory("templates", "gex_heatmap.html")


@app.route("/live")
def gex_live():
    return send_from_directory("templates", "gex_live.html")


# ─── User database (in production, use a real DB) ───
USERS = {
    "admin": "strikegex",
}
# Load additional users from env: USERS=user1:pass1,user2:pass2
extra_users = os.environ.get("GEX_USERS", "")
if extra_users:
    for pair in extra_users.split(","):
        if ":" in pair:
            u, p = pair.split(":", 1)
            USERS[u.strip()] = p.strip()
    print(f"✅ Loaded {len(USERS)} users ({', '.join(USERS.keys())})")


@app.route("/api/login", methods=["POST"])
def api_login():
    from flask import request
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if username in USERS and USERS[username] == password:
        return jsonify({"ok": True, "user": username})
    return jsonify({"ok": False, "error": "Invalid username or password"}), 401


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


# ─── Start fetch loop (works with both gunicorn and python server.py) ───
_fetch_started = False
def start_fetch():
    global _fetch_started
    if _fetch_started:
        return
    _fetch_started = True
    if APP_KEY:
        t = threading.Thread(target=fetch_loop, daemon=True)
        t.start()
        print(f"🔴 Auto-fetch: {','.join(SYMBOLS)} every {FETCH_INTERVAL}s")
    else:
        print("⚠️ No SCHWAB_APP_KEY — static mode only (set env vars)")

# Start immediately when module is imported (gunicorn does this)
start_fetch()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
