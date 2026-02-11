# GEX Heatmap — Deployment Guide

## GitHub + Railway: Step-by-Step

This guide covers deploying the GEX Heatmap as a live web app with automated data fetching via Schwab API.

---

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  Schwab API  │────▶│  gex_fetcher │────▶│  gex_data.json│
│  (0DTE chain)│     │  (Python)    │     │  (auto-saved) │
└─────────────┘     └──────────────┘     └──────┬───────┘
                                                │
                                    ┌───────────▼───────────┐
                                    │   gex_heatmap.html    │
                                    │   (static frontend)   │
                                    │   served via Flask     │
                                    └───────────────────────┘
```

---

## Step 1: Create GitHub Repository

### 1a. Initialize the repo

```bash
mkdir gex-heatmap
cd gex-heatmap
git init
```

### 1b. Create the file structure

```
gex-heatmap/
├── gex_fetcher.py          # Backend: fetches data from Schwab API
├── gex_heatmap.html        # Frontend: interactive heatmap
├── server.py               # Flask server to serve frontend + auto-fetch
├── requirements.txt        # Python dependencies
├── Procfile                # Railway process file
├── railway.toml            # Railway config
├── .gitignore
└── README.md
```

### 1c. Create `server.py` — Flask app that serves the heatmap and runs the fetcher

```python
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
```

### 1d. Create `requirements.txt`

```
flask>=3.0
schwab-py>=1.0
httpx>=0.25
gunicorn>=21.0
```

### 1e. Create `Procfile` (for Railway)

```
web: gunicorn server:app --bind 0.0.0.0:$PORT --workers 2 --threads 4
```

### 1f. Create `railway.toml`

```toml
[build]
builder = "nixpacks"

[deploy]
startCommand = "gunicorn server:app --bind 0.0.0.0:$PORT --workers 2 --threads 4"
restartPolicyType = "ON_FAILURE"
restartPolicyMaxRetries = 3
```

### 1g. Create `.gitignore`

```
schwab_token.json
gex_data.json
gex_history_intraday.json
__pycache__/
*.pyc
.env
venv/
```

### 1h. Update `gex_heatmap.html` — Add auto-fetch from API

You need to add one small block to the heatmap HTML so it can fetch data from the Flask server instead of requiring a file upload. Add this right before the closing `</script>` tag:

```javascript
// ═══ AUTO-FETCH FROM SERVER (for deployed mode) ═══
function startServerFetch() {
  // Try SSE stream first
  if (window.EventSource) {
    const es = new EventSource('/api/stream');
    es.onmessage = function(e) {
      try {
        const newD = JSON.parse(e.data);
        if (Object.keys(newD).length > 0) {
          D = newD;
          document.getElementById('sb').classList.remove('vis');
          document.getElementById('sd').className = 'status-dot live';
          rerender();
        }
      } catch(err) { console.error('SSE parse error', err); }
    };
    es.onerror = function() {
      console.log('SSE disconnected, falling back to polling');
      es.close();
      startPolling();
    };
    document.getElementById('st').textContent = 'Live (SSE)';
  } else {
    startPolling();
  }
}

function startPolling() {
  setInterval(async () => {
    try {
      const resp = await fetch('/api/gex');
      const newD = await resp.json();
      if (Object.keys(newD).length > 0) {
        D = newD;
        document.getElementById('sd').className = 'status-dot live';
        rerender();
      }
    } catch(e) { console.log('Poll error:', e); }
  }, 30000);
  document.getElementById('st').textContent = 'Live (polling 30s)';
}

// Auto-start server fetch if we're served from a server (not file://)
if (window.location.protocol !== 'file:') {
  setTimeout(startServerFetch, 1000);
}
```

### 1i. Push to GitHub

```bash
git add -A
git commit -m "Initial GEX heatmap deployment"
git remote add origin https://github.com/YOUR_USERNAME/gex-heatmap.git
git push -u origin main
```

---

## Step 2: Schwab OAuth Token Setup

The Schwab API requires an OAuth token. This is the trickiest part because you need to do the initial OAuth flow **locally** first, then upload the token to Railway.

### 2a. Local token generation (one-time)

```bash
cd gex-heatmap
python3 -m venv venv
source venv/bin/activate
pip install schwab-py httpx

# Set your credentials
export SCHWAB_APP_KEY="your_app_key"
export SCHWAB_APP_SECRET="your_app_secret"

# Run the fetcher once — it will open a browser for OAuth
python gex_fetcher.py
```

This creates `schwab_token.json` in your directory. This file contains your access + refresh tokens.

### 2b. Token refresh

The Schwab token auto-refreshes via `schwab-py`'s `easy_client`. As long as the server runs at least once every 7 days, the refresh token stays valid. If it expires, you need to redo the OAuth flow locally and re-upload the token.

---

## Step 3: Deploy to Railway

### 3a. Create Railway account

1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub
3. Click **"New Project"** → **"Deploy from GitHub Repo"**
4. Select your `gex-heatmap` repository
5. Railway will auto-detect Python and build

### 3b. Set environment variables

In Railway dashboard → your project → **Variables** tab:

| Variable | Value |
|----------|-------|
| `SCHWAB_APP_KEY` | Your Schwab developer app key |
| `SCHWAB_APP_SECRET` | Your Schwab developer app secret |
| `SCHWAB_CALLBACK_URL` | `https://127.0.0.1:8182/` |
| `FETCH_INTERVAL` | `60` (seconds between fetches) |
| `SYMBOLS` | `SPX,SPY,QQQ,IWM` |
| `PORT` | `8080` (Railway sets this automatically) |

### 3c. Upload the Schwab token

Railway doesn't have file uploads, so you need to base64-encode your token and set it as an env var, then decode it on startup.

**Option A: Token as env var (recommended)**

Add to `server.py` at the top, before the Flask app:

```python
import base64

# Decode token from environment if present
TOKEN_B64 = os.environ.get("SCHWAB_TOKEN_B64", "")
if TOKEN_B64 and not os.path.exists(TOKEN_PATH):
    token_data = base64.b64decode(TOKEN_B64)
    with open(TOKEN_PATH, "wb") as f:
        f.write(token_data)
    print("✅ Token decoded from SCHWAB_TOKEN_B64")
```

Then locally:

```bash
# Encode your token
cat schwab_token.json | base64 | tr -d '\n'
```

Copy the output and set it as `SCHWAB_TOKEN_B64` in Railway's environment variables.

**Option B: Railway volume (persistent storage)**

```bash
# In Railway dashboard → Settings → Add Volume
# Mount path: /app/data
# Then set TOKEN_PATH=/app/data/schwab_token.json
```

### 3d. Deploy

Railway auto-deploys when you push to GitHub. Check the deployment logs:

```
Railway Dashboard → Deployments → View Logs
```

You should see:
```
✅ Authenticated with Schwab
🔴 Fetch loop started: SPX, SPY, QQQ, IWM every 60s
```

### 3e. Access your heatmap

Railway provides a public URL like: `https://gex-heatmap-production.up.railway.app`

Click **Settings** → **Networking** → **Generate Domain** to get your URL.

---

## Step 4: Verify Everything Works

### 4a. Check the health endpoint

```
https://your-app.up.railway.app/api/status
```

Should return:
```json
{
  "status": "ok",
  "last_fetch": "2026-02-11T10:30:45.123",
  "symbols": ["SPX", "SPY", "QQQ", "IWM"],
  "interval": 60
}
```

### 4b. Check the data endpoint

```
https://your-app.up.railway.app/api/gex
```

Should return the full GEX JSON data.

### 4c. Open the heatmap

```
https://your-app.up.railway.app/
```

The heatmap should auto-connect via SSE and show live data.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `❌ Auth failed` | Token expired. Re-do OAuth locally, re-encode, re-upload `SCHWAB_TOKEN_B64` |
| `400 Bad Request` on $SPX | Market is closed. Schwab returns 400 for index options outside market hours |
| No data showing | Check `/api/status` — if `last_fetch` is null, the fetcher hasn't run yet |
| SSE disconnects | Normal — the heatmap falls back to polling every 30s automatically |
| Token expires every 7 days | Schwab refresh tokens last 7 days. As long as the server is running, `schwab-py` auto-refreshes. If server was down >7 days, re-do OAuth |

---

## Optional: Custom Domain

1. Railway Settings → Networking → Custom Domain
2. Add your domain (e.g., `gex.yourdomain.com`)
3. Add CNAME record at your DNS provider pointing to Railway's domain
4. SSL is automatic via Railway

---

## Local Development

Run locally without Railway:

```bash
cd gex-heatmap
source venv/bin/activate
export SCHWAB_APP_KEY="your_key"
export SCHWAB_APP_SECRET="your_secret"

# Option 1: Just the fetcher (saves gex_data.json, open HTML in browser)
python gex_fetcher.py --live --interval 60

# Option 2: Full server (auto-fetch + web UI)
python server.py
# Then open http://localhost:8080
```

---

## Cost

- **Railway**: Free tier gives 500 hours/month. $5/month for Hobby plan (always-on).
- **Schwab API**: Free with a Schwab developer account.
- **GitHub**: Free.
