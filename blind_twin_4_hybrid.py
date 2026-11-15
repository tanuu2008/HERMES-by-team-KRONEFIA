import json
import random
import time
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8000"
API_URL = f"{BASE_URL}/evaluate"


class TopologyPseudonymizer:
    """Topology-preserving OOD pseudonymizer for multi-vector hybrid attack streams."""
    def __init__(self, seed: int = 1337):
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
            orig_source = tx_copy.get("source_wallet_id")
            orig_dev = tx_copy.get("device_hash")
            orig_ip = tx_copy.get("ip_subnet")

            tx_copy["account_id"] = self._get_mapped_id(orig_acc, self.account_map, "ACCT_HYBRID_OOD")
            tx_copy["payout_wallet_id"] = self._get_mapped_id(orig_payout, self.wallet_map, "WAL_HYBRID_OOD")
            if orig_source:
                tx_copy["source_wallet_id"] = self._get_mapped_id(orig_source, self.wallet_map, "WAL_HYBRID_OOD")
            
            tx_copy["device_hash"] = self._get_mapped_id(orig_dev, self.device_map, "HW_FP_HYBRID_OOD")
            
            if orig_ip:
                if orig_ip not in self.subnet_map:
                    if "117." in orig_ip:
                        rand_octet = self.rng.randint(192, 240)
                        self.subnet_map[orig_ip] = f"117.{rand_octet}.{self.rng.randint(1, 254)}.0/24"
                    else:
                        rand_octet = self.rng.randint(10, 200)
                        self.subnet_map[orig_ip] = f"45.115.{rand_octet}.0/24"
                tx_copy["ip_subnet"] = self.subnet_map[orig_ip]

            new_stream.append(tx_copy)
        return new_stream


def build_base_stream_hybrid():
    rng = random.Random(777)
    base_ts = 1699884000.0
    stream = []

    # 1. Background Organic Retail Traffic (50 clean accounts)
    for i in range(50):
        stream.append({
            "tx_id": f"TXN_HYB_RET_{1000 + i}",
            "account_id": f"ACCT_BK_RET_{5000 + i}",
            "payout_wallet_id": f"ACCT_EXT_RET_{5000 + i}",
            "requested_amount": round(rng.uniform(28000.0, 95000.0), 2),
            "avg_historical_loan": round(rng.uniform(3000.0, 7500.0), 2),
            "request_timestamp": base_ts + rng.uniform(0, 1200),
            "ip_subnet": f"117.{rng.randint(192, 240)}.{rng.randint(1, 254)}.0/24",
            "device_hash": f"HW_FP_RET_{8000 + i}",
            "client_timezone": "Asia/Kolkata",
            "is_ground_truth_fraud": False,
        })

    # 2. Hybrid Composite Attack Vectors (12 multi-method syndicates = 48 transactions)
    for c in range(12):
        t_attack = base_ts + (c * 30.0)
        synth_acc = f"ACCT_BK_HYB_SYNTH_{7000 + c}"
        mule_wallet = f"WAL_EXT_MULE_{7000 + c}"
        secondary_wallet = f"WAL_EXT_RING_{7000 + c}"
        shared_dev = f"HW_FP_HYB_COLLISION_{100 + (c % 3)}"
        
        # Hybrid Method A: VPN-Masked Thin-File Profile Probe
        stream.append({
            "tx_id": f"TXN_HYB_ATTACK_{2000 + c*4}",
            "account_id": synth_acc,
            "payout_wallet_id": mule_wallet,
            "requested_amount": 1100.0,
            "avg_historical_loan": 950.0,
            "request_timestamp": t_attack,
            "ip_subnet": "198.51.100.45/24",  # Datacenter / Proxy IP
            "device_hash": shared_dev,
            "client_timezone": "America/New_York", # Timezone mismatch for VPN trigger
            "is_ground_truth_fraud": True,
        })

        # Hybrid Method B: Coordinated Credit Limit Bust-Out & Circular Ring Hop
        bustout_amt = round(rng.uniform(91000.0, 99000.0), 2)
        stream.extend([
            {
                "tx_id": f"TXN_HYB_ATTACK_{2001 + c*4}",
                "account_id": synth_acc,
                "payout_wallet_id": mule_wallet,
                "requested_amount": bustout_amt,
                "avg_historical_loan": 1000.0,
                "request_timestamp": t_attack + 5.2,
                "ip_subnet": "45.115.77.0/24",
                "device_hash": shared_dev,
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            },
            {
                "tx_id": f"TXN_HYB_ATTACK_{2002 + c*4}",
                "account_id": mule_wallet,
                "source_wallet_id": synth_acc,
                "payout_wallet_id": secondary_wallet,
                "requested_amount": round(bustout_amt * 0.92, 2),
                "avg_historical_loan": 900.0,
                "request_timestamp": t_attack + 14.8,
                "ip_subnet": "45.115.77.0/24",
                "device_hash": shared_dev,
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            },
            {
                "tx_id": f"TXN_HYB_ATTACK_{2003 + c*4}",
                "account_id": secondary_wallet,
                "source_wallet_id": mule_wallet,
                "payout_wallet_id": synth_acc, # Circular loop back to origin account
                "requested_amount": round(bustout_amt * 0.85, 2),
                "avg_historical_loan": 850.0,
                "request_timestamp": t_attack + 22.1,
                "ip_subnet": "45.115.77.0/24",
                "device_hash": shared_dev,
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            },
        ])

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
    base_stream = build_base_stream_hybrid()
    pseudonymizer = TopologyPseudonymizer(seed=999)
    dataset = pseudonymizer.pseudonymize_stream(base_stream)

    total_fraud_ground_truth = sum(1 for x in base_stream if x["is_ground_truth_fraud"])
    total_non_fraud = len(base_stream) - total_fraud_ground_truth

    print(f"=== OOD HYBRID MULTI-VECTOR ATTACK STREAM | TOTAL EVENTS: {len(dataset)} ===")
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
    print("      OOD HYBRID MULTI-VECTOR AUDIT SCOREBOARD")
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