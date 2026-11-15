import json
import random
import time
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8000"
API_URL = f"{BASE_URL}/evaluate"


class TopologyPseudonymizer:
    """Topology-preserving OOD pseudonymizer for stealth adversarial bypass streams."""
    def __init__(self, seed: int = 2026):
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

            tx_copy["account_id"] = self._get_mapped_id(orig_acc, self.account_map, "ACCT_STEALTH_OOD")
            tx_copy["payout_wallet_id"] = self._get_mapped_id(orig_payout, self.wallet_map, "WAL_STEALTH_OOD")
            tx_copy["device_hash"] = self._get_mapped_id(orig_dev, self.device_map, "HW_FP_STEALTH_OOD")
            
            if orig_ip:
                if orig_ip not in self.subnet_map:
                    rand_octet = self.rng.randint(192, 240)
                    self.subnet_map[orig_ip] = f"117.{rand_octet}.{self.rng.randint(1, 254)}.0/24"
                tx_copy["ip_subnet"] = self.subnet_map[orig_ip]

            new_stream.append(tx_copy)
        return new_stream


def build_base_stream_stealth():
    rng = random.Random(4242)
    base_ts = 1699970400.0
    stream = []

    # 50 Background Organic Retail Accounts
    for i in range(50):
        stream.append({
            "tx_id": f"TXN_STL_RET_{1000 + i}",
            "account_id": f"ACCT_BK_RET_{5000 + i}",
            "payout_wallet_id": f"ACCT_EXT_RET_{5000 + i}",
            "requested_amount": round(rng.uniform(25000.0, 90000.0), 2),
            "avg_historical_loan": round(rng.uniform(3000.0, 8000.0), 2),
            "request_timestamp": base_ts + rng.uniform(0, 1500),
            "ip_subnet": f"117.{rng.randint(10, 150)}.{rng.randint(1, 254)}.0/24",
            "device_hash": f"HW_FP_RET_{8000 + i}",
            "client_timezone": "Asia/Kolkata",
            "is_ground_truth_fraud": False,
        })

    # 15 Stealth Adversarial Rings (45 transactions designed to evade rules)
    for c in range(15):
        t_stealth = base_ts + (c * 40.0)
        stealth_acc = f"ACCT_BK_STEALTH_{7000 + c}"
        
        # Establishing a normal-looking baseline over 3 micro-siphons
        base_hist = 5000.0
        for step in range(3):
            siphon_amt = round(base_hist * rng.uniform(1.6, 2.2), 2) # ~1.8x velocity (bypasses 42x bar)
            stream.append({
                "tx_id": f"TXN_STL_ATTACK_{2000 + (c*3) + step}",
                "account_id": stealth_acc,
                "payout_wallet_id": f"WAL_EXT_STEALTH_OUT_{7000 + c}_{step}",
                "requested_amount": siphon_amt,
                "avg_historical_loan": base_hist,
                "request_timestamp": t_stealth + (step * 12.0),
                "ip_subnet": f"117.168.{c}.0/24", # Clean domestic IP
                "device_hash": f"HW_FP_STEALTH_DEV_{c}_{step}", # Unique rotating devices
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


def run():
    base_stream = build_base_stream_stealth()
    pseudonymizer = TopologyPseudonymizer(seed=555)
    dataset = pseudonymizer.pseudonymize_stream(base_stream)

    total_fraud_ground_truth = sum(1 for x in base_stream if x["is_ground_truth_fraud"])
    total_non_fraud = len(base_stream) - total_fraud_ground_truth

    print(f"=== OOD STEALTH ADVERSARIAL STREAM | TOTAL EVENTS: {len(dataset)} ===")
    t_start = time.perf_counter()
    
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    
    latencies = []
    flagged_events = []
    last_saved = 0.0
    quarantined_nodes = 0
    last_bar = 0.0

    for row in dataset:
        tx_id = row.pop("tx_id")
        is_fraud_gt = row.pop("is_ground_truth_fraud")
        
        t0 = time.perf_counter()
        data = post_json(API_URL, row)
        latencies.append((time.perf_counter() - t0) * 1000.0)

        risk = float(data.get("risk_score", 0.0))
        verdict = str(data.get("verdict", "")).upper()
        action = str(data.get("action", "")).upper()
        last_bar = data.get("dynamic_velocity_bar", last_bar)
        last_saved = data.get("cumulative_capital_saved_inr", last_saved)
        quarantined_nodes = data.get("quarantined_node_count", quarantined_nodes)

        is_blocked = (verdict == "BLOCK" or "BLOCK" in action or "QUARANTINE" in action or risk >= 0.85)

        if is_blocked and is_fraud_gt:
            tp += 1
            flagged_events.append((tx_id, row["account_id"], round(risk, 4), "TP", action))
        elif is_blocked and not is_fraud_gt:
            fp += 1
            flagged_events.append((tx_id, row["account_id"], round(risk, 4), "FP", action))
        elif not is_blocked and is_fraud_gt:
            fn += 1
            flagged_events.append((tx_id, row["account_id"], round(risk, 4), "FN", action))
        else:
            tn += 1

    total_ms = (time.perf_counter() - t_start) * 1000.0
    mean_latency = sum(latencies) / max(len(latencies), 1)
    recall = (tp / max(total_fraud_ground_truth, 1)) * 100.0
    precision = (tp / max(tp + fp, 1)) * 100.0

    print("\n" + "="*55)
    print("      OOD STEALTH ADVERSARIAL AUDIT SCOREBOARD")
    print("="*55)
    print(f"Total Wall Time      : {total_ms:.2f} ms")
    print(f"Mean Latency         : {mean_latency:.2f} ms / tx")
    print(f"True Positives (TP)  : {tp} / {total_fraud_ground_truth}")
    print(f"False Positives (FP) : {fp} / {total_non_fraud}")
    print(f"True Negatives (TN)  : {tn} / {total_non_fraud}")
    print(f"False Negatives (FN) : {fn} / {total_fraud_ground_truth}")
    print(f"Fraud Recall         : {recall:.2f}%")
    print(f"Precision            : {precision:.2f}%")
    print(f"Final Dynamic Bar    : {last_bar}x")
    print(f"Quarantined Nodes    : {quarantined_nodes}")
    print(f"Capital Protected    : ₹{last_saved:,.2f}")
    print("="*55)


if __name__ == "__main__":
    run()