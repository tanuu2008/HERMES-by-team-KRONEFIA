import concurrent.futures
import os
import random
import time
import requests

BASE_URL = "http://127.0.0.1:8000"
ADMIN_HEADERS = {"X-API-Key": os.getenv("FRAUD_ADMIN_KEY", "fraud-admin-secret-2026")}
TOTAL_HTTP_REQUESTS = 250
CONCURRENCY = 10


def test_closed_loop_auto_tracing():
    print("\n=== 1. TESTING ZERO-CLICK AUTO-TRACING & CLOSED-LOOP NEURAL UPDATES ===")
    requests.post(f"{BASE_URL}/admin/reset", headers=ADMIN_HEADERS)

    burst_ts = time.time()
    for i in range(1, 5):
        payload = {
            "account_id": f"ACC_AUTO_BOT_{i:02d}",
            "requested_amount": 4800 + i * 3,
            "avg_historical_loan": 1250,
            "device_hash": f"DEV_UNIQUE_{i:02d}",
            "ip_subnet": f"172.20.{i}.0/24",
            "payout_wallet_id": f"WAL_UNIQUE_{i:02d}",
            "request_timestamp": burst_ts + i * 0.1,
        }
        res = requests.post(f"{BASE_URL}/evaluate", json=payload).json()
        print(
            f" Tx #{i} ({payload['account_id']}) -> Verdict: {res['verdict']:13s} | "
            f"NN P(fraud): {res.get('nn_probability', 0.0):.3f} | Auto-Peers: {res['inferred_cohort_peers']}"
        )
        time.sleep(0.05)


def test_full_1m_dataset_sweep():
    print("\n=== 2. EXECUTING FULL 1,000,000-USER NEURAL & FALSE-POSITIVE SWEEP ===")
    res = requests.post(f"{BASE_URL}/benchmark/sweep-1m", headers=ADMIN_HEADERS).json()
    print(f" Total Users Evaluated : {res['total_users_evaluated']:,}")
    print(f" Execution Wall Time   : {res['wall_time_seconds']} seconds")
    print(f" Neural Throughput     : {res['throughput_users_per_sec']:,} users/sec")
    print(f" True Positives Caught : {res['true_positives']} / {res['true_positives'] + res['false_negatives']} (Recall: {res['fraud_recall_pct']}%)")
    print(f" False Positives       : {res['false_positives']} / {res['true_negatives'] + res['false_positives']} (FPR: {res['false_positive_rate_pct']}%)")


def send_stress_req(index):
    account_id = f"ACC_LOAD_{index:03d}"
    if index % 5 == 0:
        req, avg = 25000, 1000
    elif index % 10 == 3:
        req, avg = 28000, 25000  # Whale Hard Negative
    else:
        req, avg = random.randint(800, 1800), 1000

    payload = {
        "account_id": account_id,
        "requested_amount": req,
        "avg_historical_loan": avg,
        "device_hash": f"DEV_LOAD_{index}",
        "ip_subnet": "192.168.1.0/24",
        "payout_wallet_id": f"WAL_LOAD_{index}",
    }
    start = time.perf_counter()
    try:
        res = requests.post(f"{BASE_URL}/evaluate", json=payload, timeout=5)
        latency = (time.perf_counter() - start) * 1000
        return res.status_code, res.json().get("verdict", "UNKNOWN"), latency
    except Exception as e:
        return 500, str(e), (time.perf_counter() - start) * 1000


def run_stress_test():
    test_closed_loop_auto_tracing()
    test_full_1m_dataset_sweep()

    print(
        f"\n=== 3. LIVE CONCURRENT HTTP API BENCHMARK ({TOTAL_HTTP_REQUESTS} reqs, {CONCURRENCY} threads) ==="
    )
    requests.post(f"{BASE_URL}/admin/reset", headers=ADMIN_HEADERS)

    latencies = []
    verdicts = {"ALLOW": 0, "FLAG_FRICTION": 0, "BLOCK": 0}
    errors = 0

    wall_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        results = list(executor.map(send_stress_req, range(1, TOTAL_HTTP_REQUESTS + 1)))
    total_wall_time = time.perf_counter() - wall_start

    for status_code, verdict, latency in results:
        latencies.append(latency)
        if status_code == 200 and verdict in verdicts:
            verdicts[verdict] += 1
        else:
            errors += 1

    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    max_latency = max(latencies) if latencies else 0
    min_latency = min(latencies) if latencies else 0
    rps = TOTAL_HTTP_REQUESTS / total_wall_time if total_wall_time > 0 else 0

    print("\n" + "=" * 54)
    print("    NEURAL + O(log N) LIVE API BENCHMARK RESULTS    ")
    print("=" * 54)
    print(f" Total HTTP Reqs    : {TOTAL_HTTP_REQUESTS}")
    print(f" Concurrency Level  : {CONCURRENCY} threads")
    print(f" Execution Wall Time: {total_wall_time:.2f} seconds")
    print(f" Throughput (RPS)   : {rps:.2f} req/sec")
    print("-" * 54)
    print(f" Latency (Avg)      : {avg_latency:.2f} ms")
    print(f" Latency (Min)      : {min_latency:.2f} ms")
    print(f" Latency (Max)      : {max_latency:.2f} ms")
    print("-" * 54)
    print(f" Verdict Breakdown  :")
    print(f"  ├─ ALLOW          : {verdicts['ALLOW']}")
    print(f"  ├─ FLAG_FRICTION  : {verdicts['FLAG_FRICTION']}")
    print(f"  ├─ BLOCK          : {verdicts['BLOCK']}")
    print(f"  └─ ERRORS         : {errors}")
    print("=" * 54)


if __name__ == "__main__":
    run_stress_test()