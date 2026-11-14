import json
import random
import time
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8000"
API_URL = f"{BASE_URL}/evaluate"


class TopologyPseudonymizer:
    """Topology-preserving OOD pseudonymizer that maps entities to fresh codes 
    while keeping the adjacency matrix and temporal deltas 100% intact.
    """
    def __init__(self, seed: int = 42):
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

            # Determine entity category prefix to preserve semantic role
            acc_prefix = "ACCT_OOD"
            if orig_acc and "EXT" in orig_acc:
                acc_prefix = "WAL_EXT_OOD"
            elif orig_acc and "880" in orig_acc:  # Syndicate hubs
                acc_prefix = "HUB_OOD"

            payout_prefix = "WAL_OOD"
            if orig_payout and "MERCH" in orig_payout:
                payout_prefix = "MERCH_OOD"
            elif orig_payout and "EXT" in orig_payout:
                payout_prefix = "WAL_EXT_OOD"
            elif orig_payout and "880" in orig_payout:
                payout_prefix = "HUB_OOD"

            tx_copy["account_id"] = self._get_mapped_id(orig_acc, self.account_map, acc_prefix)
            tx_copy["payout_wallet_id"] = self._get_mapped_id(orig_payout, self.wallet_map, payout_prefix)
            if orig_source:
                tx_copy["source_wallet_id"] = self._get_mapped_id(orig_source, self.wallet_map, payout_prefix)
            
            tx_copy["device_hash"] = self._get_mapped_id(orig_dev, self.device_map, "HW_FP_OOD")
            
            if orig_ip:
                if orig_ip not in self.subnet_map:
                    if "49." in orig_ip:
                        rand_octet = self.rng.randint(32, 48)
                        self.subnet_map[orig_ip] = f"198.51.{rand_octet}.0/24"
                    else:
                        rand_octet = self.rng.randint(10, 200)
                        self.subnet_map[orig_ip] = f"203.0.{rand_octet}.0/24"
                tx_copy["ip_subnet"] = self.subnet_map[orig_ip]

            new_stream.append(tx_copy)
        return new_stream


def build_base_stream_1():
    rng = random.Random(42)
    base_ts = 1730492100.0
    stream = []

    # 40 Legitimate Festive Retail Users
    merchants = ["MERCH_IND_101", "MERCH_IND_102", "MERCH_IND_103", "MERCH_IND_104", "MERCH_IND_105"]
    for i in range(40):
        stream.append({
            "tx_id": f"TXN_N1_{1000 + i}",
            "account_id": f"ACCT_IN_{5000 + i}",
            "payout_wallet_id": rng.choice(merchants),
            "requested_amount": round(rng.uniform(35000.0, 145000.0), 2),
            "avg_historical_loan": round(rng.uniform(7500.0, 18000.0), 2),
            "request_timestamp": base_ts + rng.uniform(0, 1800),
            "ip_subnet": f"49.{rng.randint(32, 48)}.{rng.randint(1, 254)}.0/24",
            "device_hash": f"HW_FP_{9000 + i}",
            "client_timezone": "Asia/Kolkata",
            "is_ground_truth_fraud": False,
        })

    # 60 Sub-₹50k Mule Disbursements
    hubs = ["ACCT_IN_8801", "ACCT_IN_8802", "ACCT_IN_8803"]
    for i in range(60):
        stream.append({
            "tx_id": f"TXN_N1_{2000 + i}",
            "account_id": f"ACCT_IN_{6000 + i}",
            "payout_wallet_id": hubs[i % len(hubs)],
            "requested_amount": round(rng.uniform(38500.0, 44950.0), 2),
            "avg_historical_loan": round(rng.uniform(150.0, 320.0), 2),
            "request_timestamp": base_ts + (i * 1.4) + rng.uniform(0.1, 0.9),
            "ip_subnet": "103.178.44.0/24",
            "device_hash": f"HW_FP_7F3E{10 + (i % 6)}",
            "client_timezone": "UTC",
            "is_ground_truth_fraud": True,
        })

    # 3 Master Consolidation Sweeps
    for idx, hub in enumerate(hubs):
        stream.append({
            "tx_id": f"TXN_N1_{3000 + idx}",
            "account_id": hub,
            "payout_wallet_id": f"ACCT_EXT_{9900 + idx}",
            "requested_amount": round(rng.uniform(650000.0, 820000.0), 2),
            "avg_historical_loan": 500.0,
            "request_timestamp": base_ts + 110.0 + (idx * 3.5),
            "ip_subnet": "103.178.44.0/24",
            "device_hash": "HW_FP_7F3E10",
            "client_timezone": "UTC",
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
    # Generate base stream and apply topology-preserving pseudonymizer
    base_stream = build_base_stream_1()
    pseudonymizer = TopologyPseudonymizer(seed=42)
    dataset = pseudonymizer.pseudonymize_stream(base_stream)

    print(f"=== OOD PSEUDONYMIZED RUN 1 | TOTAL EVENTS: {len(dataset)} ===")
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
        status = str(data.get("settlement_status", "UNKNOWN")).upper()
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
    recall = (tp / max(tp + fn, 1)) * 100.0
    precision = (tp / max(tp + fp, 1)) * 100.0

    print("\n" + "="*55)
    print("      OOD PSEUDONYMIZED AUDIT SCOREBOARD — RUN 1")
    print("="*55)
    print(f"Total Wall Time      : {total_ms:.2f} ms")
    print(f"Mean Latency         : {mean_latency:.2f} ms / tx")
    print(f"True Positives (TP)  : {tp} / 63")
    print(f"False Positives (FP) : {fp} / 40")
    print(f"True Negatives (TN)  : {tn} / 40")
    print(f"False Negatives (FN) : {fn} / 63")
    print(f"Fraud Recall         : {recall:.2f}%")
    print(f"Precision            : {precision:.2f}%")
    print(f"Final Dynamic Bar    : {last_bar}x")
    print(f"Quarantined Nodes    : {quarantined_nodes}")
    print(f"Capital Protected    : ₹{last_saved:,.2f}")
    print("="*55)

    if flagged_events:
        print("\nSample Mapped Flagged Events:")
        for ev in flagged_events[:10]:
            print(f"  {ev[0]} (Alias: {ev[1]}) | Result: {ev[2]} | Score={ev[2]} | Action={ev[4]}")


if __name__ == "__main__":
    run()