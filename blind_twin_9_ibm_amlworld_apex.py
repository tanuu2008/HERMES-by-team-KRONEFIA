import concurrent.futures
import copy
import http.client
import json
import random
import threading
import time
from urllib.parse import urlparse

BASE_URL = "http://127.0.0.1:8000"
API_URL = f"{BASE_URL}/evaluate"
OPTIMIZE_URL = f"{BASE_URL}/agent/self-optimize"

_thread_local = threading.local()


class TopologyPseudonymizer:
    """Topology-preserving OOD pseudonymizer for IBM AMLWorld multi-bank graph streams."""
    def __init__(self, seed: int = 20261114):
        self.rng = random.Random(seed)
        self.entity_map = {}
        self.device_map = {}
        self.subnet_map = {}

    def _map_entity(self, raw_id: str | None, prefix: str) -> str | None:
        if raw_id is None:
            return None
        if raw_id not in self.entity_map:
            suffix = "".join(self.rng.choices("ABCDEF0123456789", k=7))
            self.entity_map[raw_id] = f"{prefix}_{suffix}"
        return self.entity_map[raw_id]

    def pseudonymize_stream(self, stream: list[dict]) -> list[dict]:
        out = []
        for tx in stream:
            row = tx.copy()
            row["account_id"] = self._map_entity(row.get("account_id"), "ACC_AML_OOD")
            row["payout_wallet_id"] = self._map_entity(row.get("payout_wallet_id"), "WAL_AML_OOD")
            if row.get("source_wallet_id"):
                row["source_wallet_id"] = self._map_entity(row.get("source_wallet_id"), "WAL_AML_OOD")

            raw_dev = row.get("device_hash")
            if raw_dev not in self.device_map:
                self.device_map[raw_dev] = "DEV_AML_OOD_" + "".join(self.rng.choices("0123456789ABCDEF", k=6))
            row["device_hash"] = self.device_map[raw_dev]

            raw_ip = row.get("ip_subnet")
            if raw_ip not in self.subnet_map:
                first_octet = self.rng.choice(["49", "103", "106", "117", "152"])
                self.subnet_map[raw_ip] = f"{first_octet}.{self.rng.randint(10, 245)}.{self.rng.randint(1, 254)}.0/24"
            row["ip_subnet"] = self.subnet_map[raw_ip]
            out.append(row)
        return out


def build_ibm_amlworld_apex_dataset():
    rng = random.Random(2026)
    base_ts = 1700300000.0
    stream = []

    for i in range(9800):
        hist_base = round(rng.uniform(3500.0, 45000.0), 2)
        req_amt = round(hist_base * rng.uniform(0.6, 9.5), 2)
        acc = f"CORP_RETAIL_{100000 + i}"
        stream.append({
            "tx_id": f"TXN_CLEAN_{100000 + i}",
            "topology": "CLEAN_RETAIL",
            "account_id": acc,
            "payout_wallet_id": acc,
            "requested_amount": req_amt,
            "avg_historical_loan": hist_base,
            "request_timestamp": base_ts + rng.uniform(0, 7200),
            "ip_subnet": f"103.{rng.randint(10, 220)}.{rng.randint(1, 254)}.0/24",
            "device_hash": f"HW_CLEAN_{100000 + i}",
            "client_timezone": "Asia/Kolkata",
            "is_ground_truth_fraud": False,
        })

    tx_seq = 900000

    # 1. Fan-Out (25 tx)
    for c in range(5):
        src = f"AML_FANOUT_SRC_{c}"
        t0 = base_ts + 200 + c * 400
        for k in range(5):
            stream.append({
                "tx_id": f"TXN_AML_FANOUT_{tx_seq}",
                "topology": "FAN_OUT",
                "account_id": src,
                "payout_wallet_id": f"AML_FANOUT_MULE_{c}_{k}",
                "requested_amount": round(18500.0 * rng.uniform(1.8, 2.4), 2),
                "avg_historical_loan": 18500.0,
                "request_timestamp": t0 + k * 9.0,
                "ip_subnet": f"49.40.{c}.{k}/24",
                "device_hash": f"DEV_FO_{c}_{k % 2}",
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            })
            tx_seq += 1

    # 2. Fan-In (25 tx)
    for c in range(5):
        hub = f"AML_FANIN_HUB_{c}"
        t0 = base_ts + 350 + c * 400
        for k in range(5):
            stream.append({
                "tx_id": f"TXN_AML_FANIN_{tx_seq}",
                "topology": "FAN_IN",
                "account_id": f"AML_FANIN_SMURF_{c}_{k}",
                "payout_wallet_id": hub,
                "requested_amount": round(14000.0 * rng.uniform(1.9, 2.5), 2),
                "avg_historical_loan": 14000.0,
                "request_timestamp": t0 + k * 11.0,
                "ip_subnet": f"106.22.{c}.{k}/24",
                "device_hash": f"DEV_FI_{c}_{k}",
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            })
            tx_seq += 1

    # 3. Gather-Scatter (25 tx)
    for c in range(5):
        bridge = f"AML_GS_BRIDGE_{c}"
        t0 = base_ts + 500 + c * 450
        for k in range(3):
            stream.append({
                "tx_id": f"TXN_AML_GS_IN_{tx_seq}",
                "topology": "GATHER_SCATTER",
                "account_id": f"AML_GS_SRC_{c}_{k}",
                "payout_wallet_id": bridge,
                "requested_amount": 26000.0,
                "avg_historical_loan": 12000.0,
                "request_timestamp": t0 + k * 8.0,
                "ip_subnet": f"117.18.{c}.{k}/24",
                "device_hash": f"DEV_GS_IN_{c}_{k}",
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            })
            tx_seq += 1
        for s in range(2):
            stream.append({
                "tx_id": f"TXN_AML_GS_OUT_{tx_seq}",
                "topology": "GATHER_SCATTER",
                "account_id": bridge,
                "source_wallet_id": f"AML_GS_SRC_{c}_0",
                "payout_wallet_id": f"AML_GS_EXIT_{c}_{s}",
                "requested_amount": 37500.0,
                "avg_historical_loan": 12000.0,
                "request_timestamp": t0 + 40.0 + s * 7.0,
                "ip_subnet": f"117.18.{c}.{10 + s}/24",
                "device_hash": f"DEV_GS_OUT_{c}_{s}",
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            })
            tx_seq += 1

    # 4. Scatter-Gather (25 tx)
    for c in range(5):
        origin = f"AML_SG_ORIGIN_{c}"
        collector = f"AML_SG_COLLECTOR_{c}"
        t0 = base_ts + 650 + c * 450
        for k in range(3):
            mule = f"AML_SG_MULE_{c}_{k}"
            stream.append({
                "tx_id": f"TXN_AML_SG_SCAT_{tx_seq}",
                "topology": "SCATTER_GATHER",
                "account_id": origin,
                "payout_wallet_id": mule,
                "requested_amount": 21000.0,
                "avg_historical_loan": 11000.0,
                "request_timestamp": t0 + k * 6.0,
                "ip_subnet": f"49.77.{c}.{k}/24",
                "device_hash": f"DEV_SG_{c}_{k}",
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            })
            tx_seq += 1
            if k < 2:
                stream.append({
                    "tx_id": f"TXN_AML_SG_GATH_{tx_seq}",
                    "topology": "SCATTER_GATHER",
                    "account_id": mule,
                    "source_wallet_id": origin,
                    "payout_wallet_id": collector,
                    "requested_amount": 20400.0,
                    "avg_historical_loan": 11000.0,
                    "request_timestamp": t0 + 35.0 + k * 6.0,
                    "ip_subnet": f"49.77.{c}.{20 + k}/24",
                    "device_hash": f"DEV_SG_COL_{c}_{k}",
                    "client_timezone": "Asia/Kolkata",
                    "is_ground_truth_fraud": True,
                })
                tx_seq += 1

    # 5. Cycles (25 tx)
    for c in range(5):
        ring_nodes = [f"AML_CYCLE_NODE_{c}_{h}" for h in range(5)]
        t0 = base_ts + 800 + c * 500
        for h in range(5):
            src_node = ring_nodes[h]
            dst_node = ring_nodes[(h + 1) % 5]
            prev_node = ring_nodes[(h - 1) % 5]
            stream.append({
                "tx_id": f"TXN_AML_CYCLE_{tx_seq}",
                "topology": "CYCLE_RING",
                "account_id": src_node,
                "source_wallet_id": prev_node,
                "payout_wallet_id": dst_node,
                "requested_amount": round(48000.0 * (0.985 ** h), 2),
                "avg_historical_loan": 16000.0,
                "request_timestamp": t0 + h * 10.0,
                "ip_subnet": f"103.91.{c}.{h}/24",
                "device_hash": f"DEV_CYC_{c}_{h}",
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            })
            tx_seq += 1

    # 6. Bipartite Web (25 tx)
    for c in range(5):
        t0 = base_ts + 950 + c * 500
        for k in range(5):
            src_l1 = f"AML_BIP_L1_{c}_{k % 2}"
            dst_l2 = f"AML_BIP_L2_{c}_{(k + 1) % 3}"
            stream.append({
                "tx_id": f"TXN_AML_BIP_{tx_seq}",
                "topology": "BIPARTITE_WEB",
                "account_id": src_l1,
                "payout_wallet_id": dst_l2,
                "requested_amount": round(19200.0 + k * 310.0, 2),
                "avg_historical_loan": 10500.0,
                "request_timestamp": t0 + k * 7.5,
                "ip_subnet": f"106.80.{c}.{k}/24",
                "device_hash": f"DEV_BIP_{c}_{k}",
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            })
            tx_seq += 1

    # 7. Stack Chain (25 tx)
    for c in range(5):
        chain = [f"AML_STACK_{c}_{h}" for h in range(6)]
        t0 = base_ts + 1100 + c * 500
        for h in range(5):
            stream.append({
                "tx_id": f"TXN_AML_STACK_{tx_seq}",
                "topology": "STACK_CHAIN",
                "account_id": chain[h],
                "source_wallet_id": chain[h - 1] if h > 0 else f"AML_EXT_FEED_{c}",
                "payout_wallet_id": chain[h + 1],
                "requested_amount": round(55000.0 * (0.97 ** h), 2),
                "avg_historical_loan": 15000.0,
                "request_timestamp": t0 + h * 14.0,
                "ip_subnet": f"152.58.{c}.{h}/24",
                "device_hash": f"DEV_STK_{c}_{h}",
                "client_timezone": "Asia/Kolkata",
                "is_ground_truth_fraud": True,
            })
            tx_seq += 1

    # 8. Tor / Shared Device Ring (25 tx)
    for c in range(5):
        shared_hw = f"DEV_SHARED_TOR_RIG_{c}"
        t0 = base_ts + 1250 + c * 500
        for k in range(5):
            stream.append({
                "tx_id": f"TXN_AML_TOR_{tx_seq}",
                "topology": "TOR_DEVICE_RING",
                "account_id": f"AML_TOR_ACC_{c}_{k}",
                "payout_wallet_id": f"AML_TOR_OFFSHORE_{c}_{k}",
                "requested_amount": round(32000.0 + k * 450.0, 2),
                "avg_historical_loan": 13500.0,
                "request_timestamp": t0 + k * 5.0,
                "ip_subnet": f"185.220.101.{c * 5 + k}/24",
                "device_hash": shared_hw,
                "client_timezone": "Europe/Amsterdam",
                "is_ground_truth_fraud": True,
            })
            tx_seq += 1

    stream.sort(key=lambda x: x["request_timestamp"])
    return stream


def post_json(url: str, payload: dict) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8000
    path = parsed.path or "/"

    conn = getattr(_thread_local, "conn", None)
    if conn is None:
        conn = http.client.HTTPConnection(host, port, timeout=25)
        _thread_local.conn = conn

    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "Connection": "keep-alive"}

    for attempt in range(2):
        try:
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8")
            if resp.status >= 400:
                raise RuntimeError(f"HTTP {resp.status} from {url} -> {raw}")
            return json.loads(raw)
        except (http.client.HTTPException, OSError):
            try:
                conn.close()
            except Exception:
                pass
            conn = http.client.HTTPConnection(host, port, timeout=25)
            _thread_local.conn = conn
            if attempt == 1:
                raise


def evaluate_single(item: dict) -> dict:
    tx_id = item.pop("tx_id")
    topology = item.pop("topology")
    is_fraud_gt = item.pop("is_ground_truth_fraud")

    t0 = time.perf_counter()
    data = post_json(API_URL, item)
    lat_ms = (time.perf_counter() - t0) * 1000.0

    risk = float(data.get("risk_score", 0.0))
    verdict = str(data.get("verdict", "")).upper()
    action = str(data.get("action", "")).upper()
    is_blocked = (verdict == "BLOCK" or "BLOCK" in action or "QUARANTINE" in action or risk >= 0.85)

    return {
        "tx_id": tx_id,
        "topology": topology,
        "account_id": item["account_id"],
        "is_fraud_gt": is_fraud_gt,
        "is_blocked": is_blocked,
        "risk": risk,
        "action": action,
        "lat_ms": lat_ms,
        "bar": data.get("dynamic_velocity_bar", 42.0),
        "saved": data.get("cumulative_capital_saved_inr", 0.0),
        "quarantined": data.get("quarantined_node_count", 0),
        "manifolds": data.get("evolved_manifolds_active", 0),
    }


def execute_pass(dataset: list[dict], pass_label: str, workers: int = 24):
    total_fraud_gt = sum(1 for x in dataset if x["is_ground_truth_fraud"])
    total_clean_gt = len(dataset) - total_fraud_gt

    t_start = time.perf_counter()
    tp = fp = tn = fn = 0
    latencies = []
    topo_stats = {
        t: {"tp": 0, "total": 0}
        for t in [
            "FAN_OUT", "FAN_IN", "GATHER_SCATTER", "SCATTER_GATHER",
            "CYCLE_RING", "BIPARTITE_WEB", "STACK_CHAIN", "TOR_DEVICE_RING",
        ]
    }
    fp_samples = []
    fn_samples = []
    max_saved = 0.0
    max_quarantined = 0
    last_bar = 42.0
    max_manifolds = 0

    batch_size = 50
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for i in range(0, len(dataset), batch_size):
            chunk = [copy.deepcopy(x) for x in dataset[i : i + batch_size]]
            futures = [pool.submit(evaluate_single, item) for item in chunk]
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                latencies.append(res["lat_ms"])
                last_bar = res["bar"]
                max_saved = max(max_saved, res["saved"])
                max_quarantined = max(max_quarantined, res["quarantined"])
                max_manifolds = max(max_manifolds, res["manifolds"])

                if res["is_fraud_gt"]:
                    topo = res["topology"]
                    topo_stats[topo]["total"] += 1
                    if res["is_blocked"]:
                        tp += 1
                        topo_stats[topo]["tp"] += 1
                    else:
                        fn += 1
                        fn_samples.append(res)
                else:
                    if res["is_blocked"]:
                        fp += 1
                        fp_samples.append(res)
                    else:
                        tn += 1

    total_sec = time.perf_counter() - t_start
    throughput_rps = len(dataset) / max(total_sec, 0.001)
    mean_latency = sum(latencies) / max(len(latencies), 1)
    recall = (tp / max(total_fraud_gt, 1)) * 100.0
    precision = (tp / max(tp + fp, 1)) * 100.0 if (tp + fp) > 0 else 100.0

    print("\n" + "=" * 72)
    print(f"  IBM AMLWORLD 8-TOPOLOGY 10,000-EVENT APEX AUDIT ({pass_label})")
    print("=" * 72)
    print(f"Total Wall Time      : {total_sec:.2f} s ({throughput_rps:,.1f} tx/sec across {workers} threads)")
    print(f"Mean Client Latency  : {mean_latency:.2f} ms / tx")
    print(f"True Positives (TP)  : {tp} / {total_fraud_gt}")
    print(f"False Positives (FP) : {fp} / {total_clean_gt}")
    print(f"True Negatives (TN)  : {tn} / {total_clean_gt}")
    print(f"False Negatives (FN) : {fn} / {total_fraud_gt}")
    print(f"Fraud Recall         : {recall:.2f}%")
    print(f"Precision            : {precision:.2f}%")
    print(f"Evolved Manifolds    : {max_manifolds}")
    print(f"Final Dynamic Bar    : {last_bar}x")
    print(f"Quarantined Nodes    : {max_quarantined}")
    print(f"Capital Protected    : ₹{max_saved:,.2f}")
    print("-" * 72)
    print("Per-Topology Recall Breakdown (IBM AMLWorld Standard):")
    for topo_name, st in topo_stats.items():
        t_rec = (st["tp"] / max(st["total"], 1)) * 100.0
        print(f"  - {topo_name:<18}: {st['tp']:>2} / {st['total']:<2} ({t_rec:6.2f}%)")
    print("=" * 72)

    if fp_samples:
        print("\nFalse Positive Samples:")
        for s in fp_samples[:5]:
            print(f"  {s['tx_id']} ({s['account_id']}) | Score={s['risk']} | Action={s['action']}")
    if fn_samples:
        print("\nFalse Negative Samples:")
        for s in fn_samples[:5]:
            print(f"  {s['tx_id']} [{s['topology']}] ({s['account_id']}) | Score={s['risk']}")

    return fn, max_manifolds


def run():
    raw_stream = build_ibm_amlworld_apex_dataset()
    pseudonymizer = TopologyPseudonymizer(seed=20261114)
    dataset = pseudonymizer.pseudonymize_stream(raw_stream)

    print(f"=== IBM AMLWORLD 10,000-EVENT MULTI-TOPOLOGY STREAM | ILLICIT RATIO: 2.00% ===")

    fn_pass1, evolved_manifolds = execute_pass(dataset, "PASS 1 — LIVE CONCURRENT DISCOVERY")

    if fn_pass1 > 0 and evolved_manifolds > 0:
        opt_res = post_json(OPTIMIZE_URL, {})
        print(
            f"\n[HERMES SELF-OPTIMIZATION TRIGGERED] Status={opt_res.get('status')} | "
            f"Consolidated NN Updates={opt_res.get('consolidated_nn_updates')}"
        )
        execute_pass(dataset, "PASS 2 — SELF-EVOLVED CONCURRENT SWEEP")


if __name__ == "__main__":
    run()