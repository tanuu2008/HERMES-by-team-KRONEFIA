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
    """Topology-preserving OOD pseudonymizer for Split-and-Recombine ATO Mule Rings."""
    def __init__(self, seed: int = 202611):
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

            tx_copy["account_id"] = self._get_mapped_id(orig_acc, self.account_map, "ACCT_SMURF_OOD")
            tx_copy["payout_wallet_id"] = self._get_mapped_id(orig_payout, self.wallet_map, "WAL_SMURF_OOD")
            if orig_source:
                tx_copy["source_wallet_id"] = self._get_mapped_id(orig_source, self.wallet_map, "WAL_SMURF_OOD")
            tx_copy["device_hash"] = self._get_mapped_id(orig_dev, self.device_map, "HW_FP_SMURF_OOD")

            if orig_ip:
                if orig_ip not in self.subnet_map:
                    rand_octet = self.rng.randint(192, 240)
                    self.subnet_map[orig_ip] = f"117.{rand_octet}.{self.rng.randint(1, 254)}.0/24"
                tx_copy["ip_subnet"] = self.subnet_map[orig_ip]

            new_stream.append(tx_copy)
        return new_stream


def build_base_stream_smurfing_ato():
    rng = random.Random(6060)
    base_ts = 1700143200.0
    stream = []

    # 50 Background Organic Retail Accounts (high-variance genuine activity)
    for i in range(50):
        stream.append({
            "tx_id": f"TXN_SMF_RET_{1000 + i}",
            "account_id": f"ACCT_BK_RET_{5000 + i}",
            "payout_wallet_id": f"ACCT_EXT_RET_{5000 + i}",
            "requested_amount": round(rng.uniform(18000.0, 94000.0), 2),
            "avg_historical_loan": round(rng.uniform(3000.0, 8500.0), 2),
            "request_timestamp": base_ts + rng.uniform(0, 2400),
            "ip_subnet": f"117.{rng.randint(10, 150)}.{rng.randint(1, 254)}.0/24",
            "device_hash": f"HW_FP_RET_{8000 + i}",
            "client_timezone": "Asia/Kolkata",
            "is_ground_truth_fraud": False,
        })

    # 10 Split-and-Recombine ATO Mule Clusters (50 transactions total: 4 smurf inflows + 1 recombined cashout per cluster)
    # Evasion properties:
    # - Each Layer-1 ATO mule fires ONLY ONCE (bypasses per-account multi-tx sequence windows)
    # - Uses established ₹6,500 historical loan baseline & ~2.4x velocity (bypasses thin-file & 42x velocity bar)
    # - Unique devices & clean domestic 117.x subnets per mule
    for c in range(10):
        t_cluster = base_ts + (c * 180.0)
        aggregator_hub = f"WAL_PPI_AGGREGATOR_{9000 + c}"
        cashout_offramp = f"WAL_USDT_OFFRAMP_{9000 + c}"
        pooled_total = 0.0

        # 4 Layer-1 compromised retail accounts smurfing into a shared PPI aggregator wallet
        for m in range(4):
            mule_acc = f"ACCT_BK_ATO_MULE_{7000 + (c*10) + m}"
            base_hist = 6500.0
            smurf_amt = round(base_hist * rng.uniform(2.2, 2.6), 2)
            pooled_total += smurf_amt

            stream.append({
                "tx_id": f"TXN_SMF_IN_{2000 + (c*5) + m}",
                "account_id": mule_acc,
                "payout_wallet_id": aggregator_hub,
                "requested_amount": smurf_amt,
                "avg_historical_loan": base_hist,
                "request_timestamp": t_cluster + (m * 25.0),
                "ip_subnet": f"117.210.{c}.{m}/24",
                "device_hash": f"HW_FP_ATO_BOUND_{c}_{m}",
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            })

        # Layer-2 Recombination & Off-Ramp Extraction from the Aggregator Hub
        stream.append({
            "tx_id": f"TXN_SMF_OUT_{2000 + (c*5) + 4}",
            "account_id": aggregator_hub,
            "source_wallet_id": f"ACCT_BK_ATO_MULE_{7000 + (c*10)}",
            "payout_wallet_id": cashout_offramp,
            "requested_amount": round(pooled_total * 0.98, 2),
            "avg_historical_loan": 6500.0,
            "request_timestamp": t_cluster + 115.0,
            "ip_subnet": f"117.210.{c}.99/24",
            "device_hash": f"HW_FP_AGG_CTRL_{c}",
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

    print("\n" + "=" * 62)
    print(f"  OOD SPLIT-AND-RECOMBINE ATO MULE AUDIT ({pass_label})")
    print("=" * 62)
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
    print("=" * 62)

    if flagged_events:
        print("\nSample Outcomes:")
        for ev in flagged_events[:8]:
            print(f"  {ev[0]} (Alias: {ev[1]}) | Result: {ev[3]} | Score={ev[2]} | Action={ev[4]}")

    return fn, evolved_manifolds


def run():
    base_stream = build_base_stream_smurfing_ato()
    pseudonymizer = TopologyPseudonymizer(seed=777111)
    dataset = pseudonymizer.pseudonymize_stream(base_stream)

    print(f"=== OOD SPLIT-AND-RECOMBINE ATO STREAM | TOTAL EVENTS: {len(dataset)} ===")

    fn_pass1, evolved_manifolds = execute_pass(dataset, "PASS 1 — LIVE DISCOVERY")

    if fn_pass1 > 0 and evolved_manifolds > 0:
        opt_res = post_json(OPTIMIZE_URL, {})
        print(f"\n[HERMES SELF-OPTIMIZATION TRIGGERED] Status={opt_res.get('status')} | Consolidated NN Updates={opt_res.get('consolidated_nn_updates')}")
        execute_pass(dataset, "PASS 2 — SELF-EVOLVED SWEEP")


if __name__ == "__main__":
    run()