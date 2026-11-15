import copy
import json
import random
import time
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8000"
API_URL = f"{BASE_URL}/evaluate"
OPTIMIZE_URL = f"{BASE_URL}/agent/self-optimize"


class TopologyPseudonymizer:
    """Topology-preserving OOD pseudonymizer for slow-drip zero-day evasion streams."""
    def __init__(self, seed: int = 8080):
        self.rng = random.Random(seed)
        self.account_map = {}
        self.wallet_map = {}
        self.device_map = {}
        self.subnet_map = {}

    def _get_mapped_id(self, original_id: str, mapping_dict: dict, prefix: str) -> str:
        if original_id is None:
            return None
        if original_id not in mapping_dict:
            suffix = "".join(self.rng.choices("ABCDEF0123456789", k=6))
            mapping_dict[original_id] = f"{prefix}_{suffix}"
        return mapping_dict[original_id]

    def pseudonymize_stream(self, stream: list[dict]) -> list[dict]:
        new_stream = []
        for tx in stream:
            tx_copy = tx.copy()

            orig_acc = tx_copy.get("account_id")
            orig_payout = tx_copy.get("payout_wallet_id")
            orig_dev = tx_copy.get("device_hash")
            orig_ip = tx_copy.get("ip_subnet")

            tx_copy["account_id"] = self._get_mapped_id(orig_acc, self.account_map, "ACCT_ZDAY_OOD")
            tx_copy["payout_wallet_id"] = self._get_mapped_id(orig_payout, self.wallet_map, "WAL_ZDAY_OOD")
            tx_copy["device_hash"] = self._get_mapped_id(orig_dev, self.device_map, "HW_FP_ZDAY_OOD")

            if orig_ip:
                if orig_ip not in self.subnet_map:
                    rand_octet = self.rng.randint(192, 240)
                    self.subnet_map[orig_ip] = f"117.{rand_octet}.{self.rng.randint(1, 254)}.0/24"
                tx_copy["ip_subnet"] = self.subnet_map[orig_ip]

            new_stream.append(tx_copy)
        return new_stream


def build_base_stream_zero_day():
    rng = random.Random(9090)
    base_ts = 1700056800.0
    stream = []

    # 50 Background Organic Retail Accounts
    for i in range(50):
        stream.append({
            "tx_id": f"TXN_ZD_RET_{1000 + i}",
            "account_id": f"ACCT_BK_RET_{5000 + i}",
            "payout_wallet_id": f"ACCT_EXT_RET_{5000 + i}",
            "requested_amount": round(rng.uniform(22000.0, 88000.0), 2),
            "avg_historical_loan": round(rng.uniform(3200.0, 8200.0), 2),
            "request_timestamp": base_ts + rng.uniform(0, 3600),
            "ip_subnet": f"117.{rng.randint(10, 150)}.{rng.randint(1, 254)}.0/24",
            "device_hash": f"HW_FP_RET_{8000 + i}",
            "client_timezone": "Asia/Kolkata",
            "is_ground_truth_fraud": False,
        })

    # 15 Slow-Drip Zero-Day Sleeper Syndicates (45 transactions)
    for c in range(15):
        t_drip = base_ts + (c * 120.0)
        sleeper_acc = f"ACCT_BK_SLEEPER_{7000 + c}"
        base_hist = 4200.0

        for step in range(3):
            drip_amt = round(base_hist * rng.uniform(3.3, 3.9), 2)
            stream.append({
                "tx_id": f"TXN_ZD_ATTACK_{2000 + (c*3) + step}",
                "account_id": sleeper_acc,
                "payout_wallet_id": f"WAL_EXT_SLEEPER_OUT_{7000 + c}_{step}",
                "requested_amount": drip_amt,
                "avg_historical_loan": base_hist,
                "request_timestamp": t_drip + (step * 90.0),
                "ip_subnet": f"117.204.{c}.0/24",
                "device_hash": f"HW_FP_SLEEPER_DEV_{c}_{step}",
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            })

    stream.sort(key=lambda x: x["request_timestamp"])
    return stream


def post_json(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} from {url} -> {err_detail}") from e


def execute_pass(dataset: list[dict], pass_label: str):
    total_fraud_ground_truth = sum(1 for x in dataset if x["is_ground_truth_fraud"])
    total_non_fraud = len(dataset) - total_fraud_ground_truth

    t_start = time.perf_counter()
    tp = fp = tn = fn = 0
    latencies = []
    flagged_events = []
    last_saved = 0.0
    quarantined_nodes = 0
    last_bar = 0.0
    evolved_manifolds = 0

    for item in copy.deepcopy(dataset):
        tx_id = item.pop("tx_id")
        is_fraud_gt = item.pop("is_ground_truth_fraud")

        t0 = time.perf_counter()
        data = post_json(API_URL, item)
        latencies.append((time.perf_counter() - t0) * 1000.0)

        risk = float(data.get("risk_score", 0.0))
        verdict = str(data.get("verdict", "")).upper()
        action = str(data.get("action", "")).upper()
        last_bar = data.get("dynamic_velocity_bar", last_bar)
        last_saved = data.get("cumulative_capital_saved_inr", last_saved)
        quarantined_nodes = data.get("quarantined_node_count", quarantined_nodes)
        evolved_manifolds = data.get("evolved_manifolds_active", evolved_manifolds)

        is_blocked = (verdict == "BLOCK" or "BLOCK" in action or "QUARANTINE" in action or risk >= 0.85)

        if is_blocked and is_fraud_gt:
            tp += 1
            flagged_events.append((tx_id, item["account_id"], round(risk, 4), "TP", action))
        elif is_blocked and not is_fraud_gt:
            fp += 1
            flagged_events.append((tx_id, item["account_id"], round(risk, 4), "FP", action))
        elif not is_blocked and is_fraud_gt:
            fn += 1
            flagged_events.append((tx_id, item["account_id"], round(risk, 4), "FN", action))
        else:
            tn += 1

    total_ms = (time.perf_counter() - t_start) * 1000.0
    mean_latency = sum(latencies) / max(len(latencies), 1)
    recall = (tp / max(total_fraud_ground_truth, 1)) * 100.0
    precision = (tp / max(tp + fp, 1)) * 100.0

    print("\n" + "=" * 58)
    print(f"   OOD ZERO-DAY SLOW-DRIP AUDIT SCOREBOARD ({pass_label})")
    print("=" * 58)
    print(f"Total Wall Time      : {total_ms:.2f} ms")
    print(f"Mean Latency         : {mean_latency:.2f} ms / tx")
    print(f"True Positives (TP)  : {tp} / {total_fraud_ground_truth}")
    print(f"False Positives (FP) : {fp} / {total_non_fraud}")
    print(f"True Negatives (TN)  : {tn} / {total_non_fraud}")
    print(f"False Negatives (FN) : {fn} / {total_fraud_ground_truth}")
    print(f"Fraud Recall         : {recall:.2f}%")
    print(f"Precision            : {precision:.2f}%")
    print(f"Evolved Manifolds    : {evolved_manifolds}")
    print(f"Final Dynamic Bar    : {last_bar}x")
    print(f"Quarantined Nodes    : {quarantined_nodes}")
    print(f"Capital Protected    : ₹{last_saved:,.2f}")
    print("=" * 58)

    return fn, evolved_manifolds


def run():
    base_stream = build_base_stream_zero_day()
    pseudonymizer = TopologyPseudonymizer(seed=31415)
    dataset = pseudonymizer.pseudonymize_stream(base_stream)

    print(f"=== OOD ZERO-DAY SLOW-DRIP EVASION STREAM | TOTAL EVENTS: {len(dataset)} ===")

    # Pass 1: Live Stream Discovery & Online Manifold Learning
    fn_pass1, evolved_manifolds = execute_pass(dataset, "PASS 1 — LIVE DISCOVERY")

    # Autonomous Agent Trigger: If HERMES evolved new threat manifolds & had discovery misses, self-optimize & re-sweep
    if fn_pass1 > 0 and evolved_manifolds > 0:
        opt_res = post_json(OPTIMIZE_URL, {})
        print(f"\n[HERMES SELF-OPTIMIZATION TRIGGERED] Status={opt_res.get('status')} | Consolidated NN Updates={opt_res.get('consolidated_nn_updates')}")
        execute_pass(dataset, "PASS 2 — SELF-EVOLVED SWEEP")


if __name__ == "__main__":
    run()