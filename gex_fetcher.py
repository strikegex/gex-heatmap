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

DTE_WEIGHTS = {0: 1.0}
DTE_DEFAULT_WEIGHT = 0.0

# For "all expirations" mode: weight everything equally
ALL_EXP_WEIGHT = 1.0

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


def get_option_chain(client, symbol, expiry=None, num_strikes=60, all_expirations=False):
    sym = f"${symbol}" if symbol in ("SPX","NDX","RUT","DJX","VIX") else symbol
    kw = {"include_underlying_quote": True, "strike_count": num_strikes * 2}
    if expiry:
        d = date.fromisoformat(expiry)
        kw["from_date"] = d; kw["to_date"] = d + timedelta(days=1)
    elif all_expirations:
        # Fetch next ~45 days of expirations
        kw["from_date"] = date.today()
        kw["to_date"] = date.today() + timedelta(days=45)
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
        if weight == 0: continue
        for sk, contracts in smap.items():
            strike = float(sk)
            for c in contracts:
                oi = int(c.get("openInterest", 0))
                vol = int(c.get("totalVolume", 0))
                gamma = float(c.get("gamma", 0) or 0)
                ensure(strike)
                # GEX = OI * gamma * spot^2 * 0.01 * multiplier
                gex = oi * gamma * spot * spot * 0.01 * CONTRACT_MULTIPLIER * weight
                strikes[strike]["call_gex"] += gex
                strikes[strike]["net_gex"] += gex
                strikes[strike]["call_oi"] += oi
                strikes[strike]["call_volume"] += vol
                if dte <= 0:
                    strikes[strike]["call_iv"] = float(c.get("volatility", 0) or 0)
                    strikes[strike]["call_delta"] = float(c.get("delta", 0) or 0)
                    strikes[strike]["call_bid"] = float(c.get("bid", 0) or 0)
                    strikes[strike]["call_ask"] = float(c.get("ask", 0) or 0)

    for exp_key, smap in chain.get("putExpDateMap", {}).items():
        weight, dte = get_dte_weight(exp_key)
        if weight == 0: continue
        for sk, contracts in smap.items():
            strike = float(sk)
            for c in contracts:
                oi = int(c.get("openInterest", 0))
                vol = int(c.get("totalVolume", 0))
                gamma = float(c.get("gamma", 0) or 0)
                ensure(strike)
                gex = oi * gamma * spot * spot * 0.01 * CONTRACT_MULTIPLIER * weight
                strikes[strike]["put_gex"] -= gex
                strikes[strike]["net_gex"] -= gex
                strikes[strike]["put_oi"] += oi
                strikes[strike]["put_volume"] += vol
                if dte <= 0:
                    strikes[strike]["put_iv"] = float(c.get("volatility", 0) or 0)
                    strikes[strike]["put_delta"] = float(c.get("delta", 0) or 0)
                    strikes[strike]["put_bid"] = float(c.get("bid", 0) or 0)
                    strikes[strike]["put_ask"] = float(c.get("ask", 0) or 0)

    # total_gamma = call_gex + abs(put_gex) — king is the strike with highest gross gamma exposure
    for s in strikes.values():
        s["total_gamma"] = abs(s.get("call_gex", 0)) + abs(s.get("put_gex", 0))

    return strikes


def calculate_gex_per_expiry(chain, spot):
    """Calculate GEX broken out by expiration date. Returns {exp_date: {strike: data}}"""
    today = date.today()
    per_exp = {}  # {exp_date_str: {strike: {...}}}

    for exp_key, smap in chain.get("callExpDateMap", {}).items():
        parts = exp_key.split(":")
        exp_date = parts[0]
        try:
            dte = int(parts[1]) if len(parts) >= 2 else (date.fromisoformat(parts[0]) - today).days
        except:
            dte = 99
        if exp_date not in per_exp:
            per_exp[exp_date] = {}
        strikes = per_exp[exp_date]
        for sk, contracts in smap.items():
            strike = float(sk)
            if strike not in strikes:
                strikes[strike] = dict(
                    strike=strike, net_gex=0, call_gex=0, put_gex=0,
                    total_gamma=0, call_oi=0, put_oi=0,
                    call_volume=0, put_volume=0, dte=dte,
                )
            for c in contracts:
                oi = int(c.get("openInterest", 0))
                vol = int(c.get("totalVolume", 0))
                gamma = float(c.get("gamma", 0) or 0)
                gex = oi * gamma * spot * spot * 0.01 * CONTRACT_MULTIPLIER
                strikes[strike]["call_gex"] += gex
                strikes[strike]["net_gex"] += gex
                strikes[strike]["call_oi"] += oi
                strikes[strike]["call_volume"] += vol

    for exp_key, smap in chain.get("putExpDateMap", {}).items():
        parts = exp_key.split(":")
        exp_date = parts[0]
        try:
            dte = int(parts[1]) if len(parts) >= 2 else (date.fromisoformat(parts[0]) - today).days
        except:
            dte = 99
        if exp_date not in per_exp:
            per_exp[exp_date] = {}
        strikes = per_exp[exp_date]
        for sk, contracts in smap.items():
            strike = float(sk)
            if strike not in strikes:
                strikes[strike] = dict(
                    strike=strike, net_gex=0, call_gex=0, put_gex=0,
                    total_gamma=0, call_oi=0, put_oi=0,
                    call_volume=0, put_volume=0, dte=dte,
                )
            for c in contracts:
                oi = int(c.get("openInterest", 0))
                vol = int(c.get("totalVolume", 0))
                gamma = float(c.get("gamma", 0) or 0)
                gex = oi * gamma * spot * spot * 0.01 * CONTRACT_MULTIPLIER
                strikes[strike]["put_gex"] -= gex
                strikes[strike]["net_gex"] -= gex
                strikes[strike]["put_oi"] += oi
                strikes[strike]["put_volume"] += vol

    # Set total_gamma = gross gamma (call + put), ignoring direction
    for exp_strikes in per_exp.values():
        for s in exp_strikes.values():
            s["total_gamma"] = abs(s.get("call_gex", 0)) + abs(s.get("put_gex", 0))

    return per_exp


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


def fetch_gex_all_expirations(client, symbol, num_strikes=40):
    """Fetch ALL available expirations (up to 45 days) with per-expiry GEX breakdown."""
    print(f"\n  {symbol} — Fetching ALL expirations...")
    spot = get_spot_price(client, symbol)
    chain = get_option_chain(client, symbol, None, num_strikes, all_expirations=True)
    ul = chain.get("underlying", {})
    if ul and ul.get("last"): spot = float(ul["last"])

    # Get all expiration dates
    all_exp_keys = set()
    for k in chain.get("callExpDateMap", {}).keys():
        all_exp_keys.add(k)
    for k in chain.get("putExpDateMap", {}).keys():
        all_exp_keys.add(k)

    exps_info = []
    for ek in sorted(all_exp_keys):
        parts = ek.split(":")
        exp_date = parts[0]
        try:
            dte = int(parts[1]) if len(parts) >= 2 else (date.fromisoformat(parts[0]) - date.today()).days
        except:
            dte = 99
        exps_info.append({"date": exp_date, "dte": dte, "key": ek})

    # Per-expiry GEX
    per_exp = calculate_gex_per_expiry(chain, spot)

    # Build per-expiry summaries
    exp_data = {}
    for ei in exps_info:
        exp_d = ei["date"]
        strikes_dict = per_exp.get(exp_d, {})
        if not strikes_dict:
            continue
        strikes_list = sorted(strikes_dict.values(), key=lambda x: x["strike"])
        # Filter near spot
        if strikes_list:
            ci = min(range(len(strikes_list)), key=lambda i: abs(strikes_list[i]["strike"] - spot))
            n = num_strikes
            filtered = strikes_list[max(0, ci-n):min(len(strikes_list), ci+n+1)]
        else:
            filtered = []

        total = sum(s["net_gex"] for s in filtered)
        king = max(filtered, key=lambda s: abs(s.get("call_gex",0)) + abs(s.get("put_gex",0))) if filtered else None

        exp_data[exp_d] = {
            "expiration": exp_d,
            "dte": ei["dte"],
            "strikes": filtered,
            "total_net_gex": total,
            "king_strike": king["strike"] if king else 0,
            "gamma_wall": max(filtered, key=lambda s: s["net_gex"])["strike"] if filtered else 0,
            "put_wall": min(filtered, key=lambda s: s["net_gex"])["strike"] if filtered else 0,
        }

    # Also compute cumulative (all exps combined)
    all_strikes = {}
    for exp_strikes in per_exp.values():
        for strike, data in exp_strikes.items():
            if strike not in all_strikes:
                all_strikes[strike] = dict(
                    strike=strike, net_gex=0, call_gex=0, put_gex=0,
                    total_gamma=0, call_oi=0, put_oi=0,
                    call_volume=0, put_volume=0,
                )
            for k in ("net_gex","call_gex","put_gex","call_oi","put_oi","call_volume","put_volume"):
                all_strikes[strike][k] += data.get(k, 0)
            all_strikes[strike]["total_gamma"] = abs(all_strikes[strike].get("call_gex",0)) + abs(all_strikes[strike].get("put_gex",0))

    cum_list = sorted(all_strikes.values(), key=lambda x: x["strike"])
    if cum_list:
        ci = min(range(len(cum_list)), key=lambda i: abs(cum_list[i]["strike"] - spot))
        cum_filtered = cum_list[max(0, ci-num_strikes):min(len(cum_list), ci+num_strikes+1)]
    else:
        cum_filtered = []

    cum_total = sum(s["net_gex"] for s in cum_filtered)
    # King = max abs(net_gex) in 0DTE expiry only (nearest if no 0DTE)
    from datetime import date
    today_str = date.today().isoformat()
    odte_strikes = per_exp.get(today_str, {})
    if not odte_strikes:
        # fallback: use the nearest expiry
        sorted_exps = sorted(per_exp.keys())
        odte_strikes = per_exp[sorted_exps[0]] if sorted_exps else {}
    best_strike = None
    best_val = 0
    for strike2, sdata in odte_strikes.items():
        av = abs(sdata.get("net_gex", 0))
        if av > best_val:
            best_val = av
            best_strike = strike2
    cum_king = next((s for s in cum_filtered if s["strike"] == best_strike), None)
    if cum_king is None and cum_filtered:
        cum_king = max(cum_filtered, key=lambda s: abs(s["net_gex"]))

    exp_data["ALL"] = {
        "expiration": "ALL",
        "dte": -1,
        "strikes": cum_filtered,
        "total_net_gex": cum_total,
        "king_strike": cum_king["strike"] if cum_king else 0,
        "gamma_wall": max(cum_filtered, key=lambda s: s["net_gex"])["strike"] if cum_filtered else 0,
        "put_wall": min(cum_filtered, key=lambda s: s["net_gex"])["strike"] if cum_filtered else 0,
    }

    print(f"  ${spot:,.2f} | {len(exp_data)-1} expirations + cumulative")

    return {
        "symbol": symbol, "spot": spot,
        "timestamp": datetime.now().isoformat(),
        "expirations": [e["date"] for e in exps_info],
        "exp_data": exp_data,
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
