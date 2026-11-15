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
    """Topology-preserving OOD pseudonymizer for Multi-Tier Pig-Butchering & Task-Scam Syndicates."""
    def __init__(self, seed: int = 889900):
        self.rng = random.Random(seed)
        self.entity_map = {}
        self.device_map = {}
        self.subnet_map = {}

    def _map_entity(self, raw_id: str | None, prefix: str) -> str | None:
        if raw_id is None:
            return None
        if raw_id not in self.entity_map:
            suffix = "".join(self.rng.choices("ABCDEF0123456789", k=6))
            self.entity_map[raw_id] = f"{prefix}_{suffix}"
        return self.entity_map[raw_id]

    def pseudonymize_stream(self, stream: list[dict]) -> list[dict]:
        out = []
        for tx in stream:
            row = tx.copy()
            row["account_id"] = self._map_entity(row.get("account_id"), "ACC_PIG_OOD")
            row["payout_wallet_id"] = self._map_entity(row.get("payout_wallet_id"), "WAL_PIG_OOD")
            if row.get("source_wallet_id"):
                row["source_wallet_id"] = self._map_entity(row.get("source_wallet_id"), "WAL_PIG_OOD")

            raw_dev = row.get("device_hash")
            if raw_dev not in self.device_map:
                self.device_map[raw_dev] = "DEV_PIG_OOD_" + "".join(self.rng.choices("0123456789ABCDEF", k=6))
            row["device_hash"] = self.device_map[raw_dev]

            raw_ip = row.get("ip_subnet")
            if raw_ip not in self.subnet_map:
                first_octet = self.rng.choice(["49", "103", "106", "117"])
                self.subnet_map[raw_ip] = f"{first_octet}.{self.rng.randint(12, 240)}.{self.rng.randint(1, 254)}.0/24"
            row["ip_subnet"] = self.subnet_map[raw_ip]

            out.append(row)
        return out


def build_pig_butchering_dataset():
    rng = random.Random(9090)
    base_ts = 1700220000.0
    stream = []

    # 1. 60 Genuine High-Variance Retail & Salaried Accounts (Zero-FP Stress Baseline)
    for i in range(60):
        hist_base = round(rng.uniform(4500.0, 22000.0), 2)
        req_amt = round(hist_base * rng.uniform(1.2, 8.5), 2)
        acc = f"ACCT_ORGANIC_RETAIL_{1000 + i}"
        stream.append({
            "tx_id": f"TXN_ORG_{1000 + i}",
            "account_id": acc,
            "payout_wallet_id": acc,  # Direct retail self-settlement / card bill / EMI
            "requested_amount": req_amt,
            "avg_historical_loan": hist_base,
            "request_timestamp": base_ts + rng.uniform(0, 3200),
            "ip_subnet": f"103.{rng.randint(10, 200)}.{rng.randint(1, 254)}.0/24",
            "device_hash": f"HW_ORG_{5000 + i}",
            "client_timezone": "Asia/Kolkata",
            "is_ground_truth_fraud": False,
        })

    # 2. Multi-Tier Pig-Butchering / Task-Scam Syndicate (60 Fraudulent Events across 3 Laundering Layers)
    # Architecture:
    # - 6 Shell Front Merchants (Layer 1) receiving escalating victim deposits (2.1x - 3.6x velocity)
    # - 12 Cross-Cluster Layer-2 Mule Accounts forwarding pooled victim funds via relay chains
    # - 3 Offshore OTC Crypto Liquidator Endpoints (Layer 3)
    front_merchants = [f"WAL_SHELL_MERCH_{200 + m}" for m in range(6)]
    l2_mules = [f"ACCT_L2_MULE_{300 + k}" for k in range(12)]
    otc_liquidators = [f"WAL_OTC_LIQ_{400 + z}" for z in range(3)]

    tx_counter = 5000

    # Layer 1: 36 Victim Extraction Transfers into 6 Shell Front Merchants (6 victims per merchant)
    merchant_pools = {m: 0.0 for m in front_merchants}
    merchant_last_victim = {}
    for m_idx, merch_wal in enumerate(front_merchants):
        t_wave = base_ts + (m_idx * 240.0)
        for v in range(6):
            victim_acc = f"ACCT_SCAM_VICTIM_{m_idx}_{v}"
            hist = 15000.0
            amt = round(hist * rng.uniform(2.1, 3.6), 2)
            merchant_pools[merch_wal] += amt
            merchant_last_victim[merch_wal] = victim_acc

            stream.append({
                "tx_id": f"TXN_PIG_L1_{tx_counter}",
                "account_id": victim_acc,
                "payout_wallet_id": merch_wal,
                "requested_amount": amt,
                "avg_historical_loan": hist,
                "request_timestamp": t_wave + (v * 18.0),
                "ip_subnet": f"49.36.{m_idx}.{v}/24",
                "device_hash": f"HW_VICTIM_{m_idx}_{v}",
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            })
            tx_counter += 1

    # Layer 2: 18 Cross-Routed Mule Layering Transfers (Each front merchant splits into 3 L2 mules)
    l2_pools = {mule: 0.0 for mule in l2_mules}
    l2_upstream = {}
    for m_idx, merch_wal in enumerate(front_merchants):
        t_layer2 = base_ts + (m_idx * 240.0) + 130.0
        split_amt = round((merchant_pools[merch_wal] * 0.96) / 3.0, 2)
        for s in range(3):
            target_mule = l2_mules[(m_idx * 2 + s) % len(l2_mules)]
            l2_pools[target_mule] += split_amt
            l2_upstream[target_mule] = merch_wal

            stream.append({
                "tx_id": f"TXN_PIG_L2_{tx_counter}",
                "account_id": merch_wal,
                "source_wallet_id": merchant_last_victim[merch_wal],
                "payout_wallet_id": target_mule,
                "requested_amount": split_amt,
                "avg_historical_loan": 15000.0,
                "request_timestamp": t_layer2 + (s * 12.0),
                "ip_subnet": f"106.51.{m_idx}.{s}/24",
                "device_hash": f"HW_SYND_OP_{m_idx}_{s}",
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            })
            tx_counter += 1

    # Layer 3: 6 High-Value OTC Crypto Off-Ramp Cash-Outs (Consolidating L2 mules into 3 OTC hubs)
    for idx in range(6):
        mule_acc = l2_mules[idx * 2]
        otc_hub = otc_liquidators[idx % len(otc_liquidators)]
        cashout_amt = round(max(l2_pools[mule_acc], 68000.0) * 0.97, 2)
        stream.append({
            "tx_id": f"TXN_PIG_L3_{tx_counter}",
            "account_id": mule_acc,
            "source_wallet_id": l2_upstream.get(mule_acc, front_merchants[0]),
            "payout_wallet_id": otc_hub,
            "requested_amount": cashout_amt,
            "avg_historical_loan": 15000.0,
            "request_timestamp": base_ts + 1650.0 + (idx * 20.0),
            "ip_subnet": f"103.88.19.{idx}/24",
            "device_hash": f"HW_OTC_DESK_{idx}",
            "client_timezone": "Asia/Kolkata",
            "is_ground_truth_fraud": True,
        })
        tx_counter += 1

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
    total_fraud_gt = sum(1 for x in dataset if x["is_ground_truth_fraud"])
    total_clean_gt = len(dataset) - total_fraud_gt

    t_start = time.perf_counter()
    tp = fp = tn = fn = 0
    latencies = []
    outcomes = []
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
            outcomes.append((tx_id, item["account_id"], round(risk, 4), "TP", action))
        elif is_blocked and not is_fraud_gt:
            fp += 1
            outcomes.append((tx_id, item["account_id"], round(risk, 4), "FP", action))
        elif not is_blocked and is_fraud_gt:
            fn += 1
            outcomes.append((tx_id, item["account_id"], round(risk, 4), "FN", action))
        else:
            tn += 1

    total_ms = (time.perf_counter() - t_start) * 1000.0
    mean_latency = sum(latencies) / max(len(latencies), 1)
    recall = (tp / max(total_fraud_gt, 1)) * 100.0
    precision = (tp / max(tp + fp, 1)) * 100.0

    print("\n" + "=" * 66)
    print(f"  OOD PIG-BUTCHERING & TASK-SCAM SYNDICATE AUDIT ({pass_label})")
    print("=" * 66)
    print(f"Total Wall Time      : {total_ms:.2f} ms")
    print(f"Mean Latency         : {mean_latency:.2f} ms / tx")
    print(f"True Positives (TP)  : {tp} / {total_fraud_gt}")
    print(f"False Positives (FP) : {fp} / {total_clean_gt}")
    print(f"True Negatives (TN)  : {tn} / {total_clean_gt}")
    print(f"False Negatives (FN) : {fn} / {total_fraud_gt}")
    print(f"Fraud Recall         : {recall:.2f}%")
    print(f"Precision            : {precision:.2f}%")
    print(f"Evolved Manifolds    : {evolved_manifolds}")
    print(f"Final Dynamic Bar    : {last_bar}x")
    print(f"Quarantined Nodes    : {quarantined_nodes}")
    print(f"Capital Protected    : ₹{last_saved:,.2f}")
    print("=" * 66)

    if outcomes:
        print("\nSample Outcomes:")
        for ev in outcomes[:10]:
            print(f"  {ev[0]} (Alias: {ev[1]}) | Result: {ev[3]} | Score={ev[2]} | Action={ev[4]}")

    return fn, evolved_manifolds


def run():
    raw_stream = build_pig_butchering_dataset()
    pseudonymizer = TopologyPseudonymizer(seed=202699)
    dataset = pseudonymizer.pseudonymize_stream(raw_stream)

    print(f"=== OOD MULTI-TIER PIG-BUTCHERING & TASK-SCAM STREAM | TOTAL EVENTS: {len(dataset)} ===")

    fn_pass1, evolved_manifolds = execute_pass(dataset, "PASS 1 — LIVE DISCOVERY")

    if fn_pass1 > 0 and evolved_manifolds > 0:
        opt_res = post_json(OPTIMIZE_URL, {})
        print(
            f"\n[HERMES SELF-OPTIMIZATION TRIGGERED] Status={opt_res.get('status')} | "
            f"Consolidated NN Updates={opt_res.get('consolidated_nn_updates')}"
        )
        execute_pass(dataset, "PASS 2 — SELF-EVOLVED SWEEP")


if __name__ == "__main__":
    run()