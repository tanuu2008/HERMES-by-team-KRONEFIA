import json
import random
import time
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8000"
API_URL = f"{BASE_URL}/evaluate"


class TopologyPseudonymizer:
    """Topology-preserving OOD pseudonymizer that maps entities to fresh codes 
    while keeping the adjacency matrix, temporal deltas, and domestic mobile IP ranges 100% intact.
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

            acc_prefix = "ACCT_SYNTH_OOD"
            if orig_acc and "EXT" in orig_acc:
                acc_prefix = "WAL_EXT_SYNTH_OOD"

            payout_prefix = "WAL_SYNTH_OOD"
            if orig_payout and "EXT" in orig_payout:
                payout_prefix = "WAL_EXT_SYNTH_OOD"

            tx_copy["account_id"] = self._get_mapped_id(orig_acc, self.account_map, acc_prefix)
            tx_copy["payout_wallet_id"] = self._get_mapped_id(orig_payout, self.wallet_map, payout_prefix)
            if orig_source:
                tx_copy["source_wallet_id"] = self._get_mapped_id(orig_source, self.wallet_map, payout_prefix)
            
            tx_copy["device_hash"] = self._get_mapped_id(orig_dev, self.device_map, "HW_FP_SYNTH_OOD")
            
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


def build_base_stream_3():
    rng = random.Random(99)
    base_ts = 1699797600.0
    stream = []

    # 45 Established Organic Retail & Credit Accounts
    for i in range(45):
        stream.append({
            "tx_id": f"TXN_S3_{1000 + i}",
            "account_id": f"ACCT_BK_RET_{5000 + i}",
            "payout_wallet_id": f"ACCT_EXT_RET_{5000 + i}",
            "requested_amount": round(rng.uniform(30000.0, 92000.0), 2),
            "avg_historical_loan": round(rng.uniform(3500.0, 8500.0), 2),
            "request_timestamp": base_ts + rng.uniform(0, 900),
            "ip_subnet": f"117.{rng.randint(192, 240)}.{rng.randint(1, 254)}.0/24",
            "device_hash": f"HW_FP_RET_{8000 + i}",
            "client_timezone": "Asia/Kolkata",
            "is_ground_truth_fraud": False,
        })

    # 15 Synthetic Identity Bust-Out Rings (60 coordinated events)
    for c in range(15):
        t_burst = base_ts + (c * 18.0)
        synth_acc = f"ACCT_BK_SYNTH_{7000 + c}"
        shared_dev = f"HW_FP_SYNTH_DEV_{100 + (c % 4)}"
        shared_ip = "45.115.88.0/24"
        
        # Phase 1: Malicious profile establishment probe (Correctly labeled as fraud vector)
        stream.append({
            "tx_id": f"TXN_S3_{2000 + c*4}",
            "account_id": synth_acc,
            "payout_wallet_id": f"WAL_EXT_MULE_{7000 + c}",
            "requested_amount": 1200.0,
            "avg_historical_loan": 1000.0,
            "request_timestamp": t_burst,
            "ip_subnet": shared_ip,
            "device_hash": shared_dev,
            "client_timezone": "Asia/Kolkata",
            "is_ground_truth_fraud": True,
        })

        # Phase 2: Coordinated Credit Limit Bust-Out
        bustout_amt = round(rng.uniform(89000.0, 98000.0), 2)
        stream.extend([
            {
                "tx_id": f"TXN_S3_{2001 + c*4}",
                "account_id": synth_acc,
                "payout_wallet_id": f"WAL_EXT_MULE_{7000 + c}",
                "requested_amount": bustout_amt,
                "avg_historical_loan": 1050.0,
                "request_timestamp": t_burst + 4.5,
                "ip_subnet": shared_ip,
                "device_hash": shared_dev,
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            },
            {
                "tx_id": f"TXN_S3_{2002 + c*4}",
                "account_id": synth_acc,
                "payout_wallet_id": f"WAL_EXT_MULE_SEC_{7000 + c}",
                "requested_amount": round(bustout_amt * 0.95, 2),
                "avg_historical_loan": 1050.0,
                "request_timestamp": t_burst + 8.1,
                "ip_subnet": shared_ip,
                "device_hash": shared_dev,
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            },
            {
                "tx_id": f"TXN_S3_{2003 + c*4}",
                "account_id": synth_acc,
                "payout_wallet_id": f"WAL_EXT_MULE_FIN_{7000 + c}",
                "requested_amount": round(bustout_amt * 0.90, 2),
                "avg_historical_loan": 1050.0,
                "request_timestamp": t_burst + 12.3,
                "ip_subnet": shared_ip,
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
    base_stream = build_base_stream_3()
    pseudonymizer = TopologyPseudonymizer(seed=789)
    dataset = pseudonymizer.pseudonymize_stream(base_stream)

    total_fraud_ground_truth = sum(1 for x in base_stream if x["is_ground_truth_fraud"])
    total_non_fraud = len(base_stream) - total_fraud_ground_truth

    print(f"=== OOD PSEUDONYMIZED RUN 3 (SYNTHETIC BUST-OUTS) | TOTAL EVENTS: {len(dataset)} ===")
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
    print("      OOD PSEUDONYMIZED AUDIT SCOREBOARD — RUN 3")
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