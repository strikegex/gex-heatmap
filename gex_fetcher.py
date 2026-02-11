"""
GEX Heatmap Data Fetcher — Schwab API (0DTE focused)
=====================================================
Fetches 0DTE+1DTE chain, calculates GEX, tracks king node history
and volume surges across refreshes.

Usage:
  python gex_fetcher.py                         # SPX + SPY + QQQ + IWM
  python gex_fetcher.py --live --interval 60    # Continuous with history tracking
  python gex_fetcher.py --symbol SPX SPY QQQ IWM
"""

import json, time, argparse, os, sys
from datetime import datetime, date, timedelta

APP_KEY = os.environ.get("SCHWAB_APP_KEY", "YOUR_APP_KEY_HERE")
APP_SECRET = os.environ.get("SCHWAB_APP_SECRET", "YOUR_APP_SECRET_HERE")
CALLBACK_URL = os.environ.get("SCHWAB_CALLBACK_URL", "https://127.0.0.1:8182/")
TOKEN_PATH = os.environ.get("SCHWAB_TOKEN_PATH", "schwab_token.json")
CONTRACT_MULTIPLIER = 100

DTE_WEIGHTS = {0: 10.0, 1: 2.0}
DTE_DEFAULT_WEIGHT = 0.0

HISTORY_FILE = "gex_history_intraday.json"


def load_history():
    try:
        with open(HISTORY_FILE) as f:
            h = json.load(f)
        if h.get("date") != str(date.today()):
            return {"date": str(date.today()), "snapshots": {}}
        return h
    except:
        return {"date": str(date.today()), "snapshots": {}}


def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def record_snapshot(history, symbol, spot, king_strike, king_gex, strikes_data):
    ts = datetime.now().isoformat()
    if symbol not in history["snapshots"]:
        history["snapshots"][symbol] = []
    vol_map = {}
    for s in strikes_data:
        vol_map[str(s["strike"])] = {
            "cv": s.get("call_volume", 0),
            "pv": s.get("put_volume", 0),
            "tv": s.get("call_volume", 0) + s.get("put_volume", 0),
        }
    history["snapshots"][symbol].append({
        "t": ts, "spot": spot, "king": king_strike, "vol": vol_map,
    })
    if len(history["snapshots"][symbol]) > 120:
        history["snapshots"][symbol] = history["snapshots"][symbol][-120:]


def get_king_history(history, symbol):
    snaps = history.get("snapshots", {}).get(symbol, [])
    if not snaps: return []
    timeline = []
    prev = None
    for snap in snaps:
        k = snap["king"]
        if k != prev:
            timeline.append({"strike": k, "timestamp": snap["t"], "spot": snap["spot"]})
            prev = k
    return timeline


def detect_volume_surges(history, symbol, current_strikes):
    snaps = history.get("snapshots", {}).get(symbol, [])
    if len(snaps) < 2: return []
    prev = snaps[-1]["vol"]
    surges = []
    for s in current_strikes:
        sk = str(s["strike"])
        curr = s.get("call_volume", 0) + s.get("put_volume", 0)
        pv = prev.get(sk, {}).get("tv", 0)
        if pv > 50 and curr > pv * 1.5:
            surges.append({
                "strike": s["strike"],
                "prev_vol": pv, "curr_vol": curr,
                "delta": curr - pv,
                "pct": round(((curr / pv) - 1) * 100, 1) if pv else 0,
                "call_vol": s.get("call_volume", 0),
                "put_vol": s.get("put_volume", 0),
            })
    surges.sort(key=lambda x: -x["delta"])
    return surges[:8]


def get_schwab_client():
    try:
        from schwab import auth
    except ImportError:
        print("❌ pip install schwab-py httpx --break-system-packages"); sys.exit(1)
    if APP_KEY == "YOUR_APP_KEY_HERE":
        print("❌ Set SCHWAB_APP_KEY and SCHWAB_APP_SECRET"); sys.exit(1)
    try:
        c = auth.easy_client(api_key=APP_KEY, app_secret=APP_SECRET,
                             callback_url=CALLBACK_URL, token_path=TOKEN_PATH)
        print("✅ Authenticated with Schwab"); return c
    except Exception as e:
        print(f"❌ Auth failed: {e}"); sys.exit(1)


def get_spot_price(client, symbol):
    sym = f"${symbol}" if symbol in ("SPX","NDX","RUT","DJX","VIX") else symbol
    resp = client.get_quote(sym); resp.raise_for_status()
    q = resp.json().get(sym, {}).get("quote", {})
    return float(q.get("lastPrice", q.get("closePrice", 0)))


def get_option_chain(client, symbol, expiry=None, num_strikes=60):
    sym = f"${symbol}" if symbol in ("SPX","NDX","RUT","DJX","VIX") else symbol
    kw = {"include_underlying_quote": True, "strike_count": num_strikes * 2}
    if expiry:
        d = date.fromisoformat(expiry)
        kw["from_date"] = d; kw["to_date"] = d + timedelta(days=1)
    else:
        kw["from_date"] = date.today()
        kw["to_date"] = date.today() + timedelta(days=1)
    resp = client.get_option_chain(sym, **kw); resp.raise_for_status()
    return resp.json()


def calculate_gex(chain, spot):
    today = date.today()
    strikes = {}

    def ensure(strike):
        if strike not in strikes:
            strikes[strike] = dict(
                strike=strike, net_gex=0, call_gex=0, put_gex=0,
                total_gamma=0, call_oi=0, put_oi=0,
                call_volume=0, put_volume=0,
                call_iv=0, put_iv=0, call_delta=0, put_delta=0,
                call_bid=0, call_ask=0, put_bid=0, put_ask=0,
            )

    def get_dte_weight(exp_key):
        try:
            parts = exp_key.split(":")
            dte = int(parts[1]) if len(parts) >= 2 else (date.fromisoformat(parts[0]) - today).days
            return DTE_WEIGHTS.get(dte, DTE_DEFAULT_WEIGHT), dte
        except:
            return DTE_DEFAULT_WEIGHT, 99

    for exp_key, smap in chain.get("callExpDateMap", {}).items():
        weight, dte = get_dte_weight(exp_key)
        for sk, contracts in smap.items():
            strike = float(sk)
            for c in contracts:
                oi = int(c.get("openInterest", 0))
                gamma = float(c.get("gamma", 0) or 0)
                vol = int(c.get("totalVolume", 0))
                ensure(strike)
                gex = oi * gamma * spot**2 * 0.01 * CONTRACT_MULTIPLIER * weight
                strikes[strike]["call_gex"] += gex
                strikes[strike]["net_gex"] += gex
                strikes[strike]["total_gamma"] += abs(gex)
                strikes[strike]["call_oi"] += oi
                strikes[strike]["call_volume"] += vol
                if dte <= 0:
                    strikes[strike]["call_iv"] = float(c.get("volatility", 0) or 0)
                    strikes[strike]["call_delta"] = float(c.get("delta", 0) or 0)
                    strikes[strike]["call_bid"] = float(c.get("bid", 0) or 0)
                    strikes[strike]["call_ask"] = float(c.get("ask", 0) or 0)

    for exp_key, smap in chain.get("putExpDateMap", {}).items():
        weight, dte = get_dte_weight(exp_key)
        for sk, contracts in smap.items():
            strike = float(sk)
            for c in contracts:
                oi = int(c.get("openInterest", 0))
                gamma = float(c.get("gamma", 0) or 0)
                vol = int(c.get("totalVolume", 0))
                ensure(strike)
                gex = oi * gamma * spot**2 * 0.01 * CONTRACT_MULTIPLIER * weight
                strikes[strike]["put_gex"] -= gex
                strikes[strike]["net_gex"] -= gex
                strikes[strike]["total_gamma"] += abs(gex)
                strikes[strike]["put_oi"] += oi
                strikes[strike]["put_volume"] += vol
                if dte <= 0:
                    strikes[strike]["put_iv"] = float(c.get("volatility", 0) or 0)
                    strikes[strike]["put_delta"] = float(c.get("delta", 0) or 0)
                    strikes[strike]["put_bid"] = float(c.get("bid", 0) or 0)
                    strikes[strike]["put_ask"] = float(c.get("ask", 0) or 0)

    return strikes


def filter_near_spot(strikes, spot, n=30):
    s = sorted(strikes.values(), key=lambda x: x["strike"])
    if not s: return []
    ci = min(range(len(s)), key=lambda i: abs(s[i]["strike"] - spot))
    return s[max(0, ci-n):min(len(s), ci+n+1)]


def generate_recommendation(symbol, spot, strikes, total_net_gex):
    if not strikes:
        return {"summary": "No data", "bias": "neutral", "action_items": []}
    max_abs = max(abs(s["net_gex"]) for s in strikes)
    if max_abs == 0:
        return {"summary": "No significant gamma", "bias": "neutral", "action_items": []}

    king = max(strikes, key=lambda s: s["total_gamma"])
    gw = max(strikes, key=lambda s: s["net_gex"])
    pw = min(strikes, key=lambda s: s["net_gex"])
    posA = sorted([s for s in strikes if s["strike"]>spot and s["net_gex"]>max_abs*.15], key=lambda s:s["strike"])
    posB = sorted([s for s in strikes if s["strike"]<spot and s["net_gex"]>max_abs*.15], key=lambda s:-s["strike"])

    profile = "positive" if total_net_gex>max_abs*.1 else "negative" if total_net_gex<-max_abs*.1 else "neutral"
    kd = king["strike"]-spot; kp=(kd/spot)*100
    bias = "range" if profile=="positive" else "trend" if profile=="negative" else "chop"
    items = []
    if abs(kp)>.02: items.append(f"DRIFT TARGET: {king['strike']:.1f} ({'above' if kd>0 else 'below'})")
    else: items.append(f"PIN ZONE: {king['strike']:.1f}")
    if posB: items.append(f"SUPPORT: {posB[0]['strike']:.1f}")
    if posA: items.append(f"RESISTANCE: {posA[0]['strike']:.1f}")
    hi = posA[0]["strike"] if posA else (king["strike"] if kd>0 else spot+20)
    lo = posB[0]["strike"] if posB else (king["strike"] if kd<0 else spot-20)

    if profile=="positive" and abs(kp)<.15:
        summary = f"PIN & CHOP — King {king['strike']:.1f}. Fade {lo:.1f}–{hi:.1f}."
    elif profile=="positive":
        summary = f"DRIFT TO KING — Magnet {king['strike']:.1f}. Range {lo:.1f}–{hi:.1f}."
    elif profile=="negative" and kd>0:
        summary = f"BULLISH MOMENTUM — King UP to {king['strike']:.1f}."
    elif profile=="negative" and kd<0:
        summary = f"BEARISH MOMENTUM — King DOWN to {king['strike']:.1f}."
    else:
        summary = f"CHOPPY — King {king['strike']:.1f}. Wait."

    return {
        "summary": summary, "bias": bias, "profile": profile,
        "king_node": {"strike":king["strike"],"gex":king["net_gex"],"total_gamma":king["total_gamma"],"direction":"above" if kd>0 else "below","distance":kd,"distance_pct":kp},
        "gamma_wall": {"strike":gw["strike"]}, "put_wall": {"strike":pw["strike"]},
        "expected_range": {"low":lo,"high":hi},
        "action_items": items, "timestamp": datetime.now().isoformat(),
    }


def fetch_gex(client, symbol, history, expiry=None, num_strikes=30):
    print(f"\n  {symbol} — Fetching 0DTE GEX...")
    spot = get_spot_price(client, symbol)
    chain = get_option_chain(client, symbol, expiry, num_strikes)
    ul = chain.get("underlying", {})
    if ul and ul.get("last"): spot = float(ul["last"])

    exps = sorted(set([e.split(":")[0] for e in list(chain.get("callExpDateMap",{}).keys())+list(chain.get("putExpDateMap",{}).keys())]))
    all_s = calculate_gex(chain, spot)
    filtered = filter_near_spot(all_s, spot, num_strikes)
    total = sum(s["net_gex"] for s in filtered)
    king = max(filtered, key=lambda s: s["total_gamma"])

    vol_surges = detect_volume_surges(history, symbol, filtered)
    record_snapshot(history, symbol, spot, king["strike"], king["net_gex"], filtered)
    king_timeline = get_king_history(history, symbol)
    rec = generate_recommendation(symbol, spot, filtered, total)
    print(f"  ${spot:,.2f} | {rec['summary']}")

    return {
        "symbol": symbol, "spot": spot,
        "timestamp": datetime.now().isoformat(),
        "expirations": exps, "total_net_gex": total,
        "gamma_wall": max(filtered,key=lambda s:s["net_gex"])["strike"],
        "put_wall": min(filtered,key=lambda s:s["net_gex"])["strike"],
        "king_node": king["strike"],
        "strikes": filtered,
        "recommendation": rec,
        "king_history": king_timeline,
        "volume_surges": vol_surges,
    }


def run_live(client, symbols, expiry, interval, output):
    print(f"\n🔴 LIVE — every {interval}s | Ctrl+C to stop\n")
    history = load_history()
    while True:
        try:
            data = {}
            for sym in symbols:
                data[sym] = fetch_gex(client, sym, history, expiry)
            save_history(history)
            with open(output, "w") as f: json.dump(data, f, indent=2)
            print(f"  ✅ {output} @ {datetime.now().strftime('%H:%M:%S')}")
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\n🛑 Stopped."); break
        except Exception as e:
            print(f"  ⚠️ {e}"); time.sleep(interval)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--symbol", nargs="+", default=["SPX","SPY","QQQ","IWM"])
    p.add_argument("--expiry", default=None)
    p.add_argument("--strikes", type=int, default=30)
    p.add_argument("--output", default="gex_data.json")
    p.add_argument("--live", action="store_true")
    p.add_argument("--interval", type=int, default=60)
    a = p.parse_args()
    client = get_schwab_client()
    history = load_history()
    if a.live:
        run_live(client, a.symbol, a.expiry, a.interval, a.output)
    else:
        data = {}
        for sym in a.symbol:
            data[sym] = fetch_gex(client, sym, history, a.expiry, a.strikes)
        save_history(history)
        with open(a.output, "w") as f: json.dump(data, f, indent=2)
        print(f"\n✅ Saved to {a.output}")

if __name__ == "__main__":
    main()
