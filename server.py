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
gex_all_data = {}   # multi-expiry data for GEX Live view
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
if os.path.exists("gex_all_data.json"):
    try:
        with open("gex_all_data.json") as f:
            gex_all_data = json.load(f)
        print(f"✅ Loaded cached gex_all_data.json ({len(gex_all_data)} symbols)")
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
    global gex_data, gex_all_data, last_fetch
    import gex_fetcher as gf

    client = None
    history = gf.load_history()
    first_run = True  # attempt one fetch regardless of market hours on startup

    while True:
        try:
            if not is_market_hours() and not first_run:
                print(f"  💤 Market closed — skipping fetch ({datetime.now().strftime('%H:%M:%S')} UTC)")
                time.sleep(FETCH_INTERVAL)
                continue
            first_run = False

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
            all_data = {}
            for sym in SYMBOLS:
                try:
                    data[sym] = gf.fetch_gex(client, sym, history)
                except Exception as e:
                    print(f"  ⚠️ {sym} 0DTE: {e}")
                try:
                    all_data[sym] = gf.fetch_gex_all_expirations(client, sym)
                except Exception as e:
                    print(f"  ⚠️ {sym} ALL-EXP: {e}")

            if data:
                gf.save_history(history)
                with fetch_lock:
                    gex_data = data
                    if all_data:
                        gex_all_data = all_data
                    last_fetch = datetime.now().isoformat()
                with open("gex_data.json", "w") as f:
                    json.dump(data, f)
                if all_data:
                    with open("gex_all_data.json", "w") as f:
                        json.dump(all_data, f)
                print(f"  ✅ {len(data)} symbols @ {datetime.now().strftime('%H:%M:%S')}")

        except Exception as e:
            print(f"  ⚠️ Fetch error: {e}")
            client = None

        time.sleep(FETCH_INTERVAL)


@app.route("/")
def index():
    return send_from_directory("templates", "landing.html")

@app.route("/app")
def app_page():
    return send_from_directory("templates", "gex_heatmap.html")

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("templates", filename)


# ─── User database (in production, use a real DB) ───
# ─── Admin credentials (internal access) ───
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "strikegex")

# ─── Whop config ───
WHOP_API_KEY      = os.environ.get("WHOP_API_KEY", "")        # Bearer token from Whop dashboard
WHOP_WEBHOOK_SECRET = os.environ.get("WHOP_WEBHOOK_SECRET", "")  # Webhook signing secret
WHOP_PRODUCT_ID   = os.environ.get("WHOP_PRODUCT_ID", "")     # Your product/pass ID

# ─── Member store: {email: {whop_user_id, membership_id, tier, valid, expires_at}} ───
MEMBERS_FILE = os.path.join(os.path.dirname(__file__), "whop_members.json")
members_lock = threading.Lock()

def load_members():
    if os.path.exists(MEMBERS_FILE):
        try:
            with open(MEMBERS_FILE) as f:
                return json.load(f)
        except:
            pass
    return {}

def save_members(members):
    with open(MEMBERS_FILE, "w") as f:
        json.dump(members, f, indent=2)

members_db = load_members()
print(f"✅ Loaded {len(members_db)} Whop members")


def verify_whop_webhook(request_body: bytes, headers: dict) -> bool:
    """Verify webhook signature - handles Whop HMAC-SHA256.
    Header: X-Whop-Signature (hex digest, optionally prefixed sha256=)
    Secret: WHOP_WEBHOOK_SECRET env var (strip whsec_ prefix if present)
    """
    import hmac as hmac_mod, hashlib
    if not WHOP_WEBHOOK_SECRET:
        print("WARNING: WHOP_WEBHOOK_SECRET not set - skipping sig check")
        return True
    sig = (headers.get("x-whop-signature") or
           headers.get("X-Whop-Signature", "")).strip()
    if not sig:
        print("WARNING: No X-Whop-Signature header")
        return False
    secret = WHOP_WEBHOOK_SECRET
    if secret.startswith("whsec_"):
        secret = secret[6:]
    expected = hmac_mod.new(secret.encode(), request_body, hashlib.sha256).hexdigest()
    check_sig = sig[7:] if sig.startswith("sha256=") else sig
    return hmac_mod.compare_digest(expected, check_sig)


def get_whop_member_tier(email: str) -> str:
    """Return 'approved' if email has active Whop membership, else 'free'."""
    with members_lock:
        m = members_db.get(email.lower())
    if m and m.get("valid"):
        return "approved"
    # Optionally re-verify live via Whop API
    return "free"


@app.route("/api/login", methods=["POST"])
def api_login():
    from flask import request
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    # Admin login
    if username == ADMIN_USER and password == ADMIN_PASS:
        return jsonify({"ok": True, "user": username, "tier": "approved"})

    # Whop member login — username is their email, password is their license key
    email = username.lower()
    with members_lock:
        member = members_db.get(email)

    if member:
        # Verify license key matches
        if password == member.get("license_key", "") or member.get("valid"):
            tier = "approved" if member.get("valid") else "free"
            return jsonify({"ok": True, "user": email, "tier": tier,
                            "membership": member.get("membership_id", "")})
        return jsonify({"ok": False, "error": "Invalid license key"}), 401

    return jsonify({"ok": False, "error": "Account not found. Purchase a membership at whop.com/strikegex"}), 401


@app.route("/api/whop/webhook", methods=["POST"])
def whop_webhook():
    """Receive Whop membership webhooks to auto-provision/deprovision users."""
    from flask import request
    raw_body = request.get_data()
    headers = dict(request.headers)

    if not verify_whop_webhook(raw_body, headers):
        print("⚠️  Whop webhook signature invalid")
        return jsonify({"error": "Invalid signature"}), 401

    try:
        payload = json.loads(raw_body)
    except:
        return jsonify({"error": "Bad JSON"}), 400

    action = payload.get("action", "").lower()
    data   = payload.get("data", {})

    # ── Normalize event name ──────────────────────────────────
    # New API format:  "membership_activated" / "membership_deactivated"
    # Old API v2 format: "membership.went_valid" / "membership.went_invalid"
    # payment events:  "payment_succeeded" / "payment_failed"
    ACTIVATE_EVENTS   = {"membership_activated",   "membership.went_valid"}
    DEACTIVATE_EVENTS = {"membership_deactivated", "membership.went_invalid",
                         "payment_failed"}

    # ── Extract email ─────────────────────────────────────────
    email = (data.get("email") or "").lower()
    user  = data.get("user") or {}
    if not email:
        email = (user.get("email") or "").lower()
    # New API may nest email under membership.user.email
    if not email and isinstance(data.get("membership"), dict):
        mem_user = data["membership"].get("user") or {}
        email = (mem_user.get("email") or "").lower()

    membership_id = data.get("id", "")
    license_key   = data.get("license_key", "")
    expires_at    = (data.get("expires_at") or data.get("renewal_period_end")
                     or data.get("expiration_date"))
    plan          = data.get("plan") or {}
    plan_name     = plan.get("name") if isinstance(plan, dict) else str(plan)

    print(f"📨 Whop webhook: action={action!r} email={email!r} membership={membership_id!r}")

    if not email:
        print(f"⚠️  Whop webhook {action} — no email in payload, ignoring")
        return jsonify({"ok": True}), 200

    with members_lock:
        if action in ACTIVATE_EVENTS:
            members_db[email] = {
                "whop_user_id":   user.get("id", ""),
                "username":       user.get("username", ""),
                "membership_id":  membership_id,
                "license_key":    license_key,
                "plan":           plan_name,
                "valid":          True,
                "tier":           "approved",
                "activated_at":   datetime.now().isoformat(),
                "expires_at":     expires_at,
            }
            save_members(members_db)
            print(f"✅ Whop member activated: {email} ({plan_name})")

        elif action in DEACTIVATE_EVENTS:
            if email in members_db:
                members_db[email]["valid"] = False
                members_db[email]["tier"]  = "free"
                members_db[email]["deactivated_at"] = datetime.now().isoformat()
                save_members(members_db)
                print(f"🚫 Whop member deactivated: {email}")
            else:
                print(f"⚠️  Deactivate event for unknown member: {email}")

        elif action == "payment_succeeded":
            # Ensure member stays active on renewal
            if email in members_db:
                members_db[email]["valid"] = True
                members_db[email]["tier"]  = "approved"
                members_db[email]["last_payment"] = datetime.now().isoformat()
                save_members(members_db)
                print(f"💳 Payment confirmed, access maintained: {email}")
        else:
            print(f"ℹ️  Unhandled Whop event: {action}")

    return jsonify({"ok": True}), 200


@app.route("/api/whop/members", methods=["GET"])
def whop_members_list():
    """Admin endpoint — list all members."""
    from flask import request
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {ADMIN_PASS}":
        return jsonify({"error": "Unauthorized"}), 401
    with members_lock:
        return jsonify({"members": members_db, "count": len(members_db)})


@app.route("/api/gex")
def api_gex():
    with fetch_lock:
        return jsonify(gex_data)


@app.route("/api/gex-all")
def api_gex_all():
    with fetch_lock:
        return jsonify(gex_all_data)


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
