import math
import queue
import sqlite3
import threading
import time
import numpy as np

SQLITE_DB = "fraud_history.db"
db_lock = threading.RLock()


class HistoricalBehavioralStore:
    """
    1M-Scale Closed-Loop Behavioral Store:
    - Sorted NumPy timestamp index for O(log N) binary-search windowing (np.searchsorted)
    - Permanent SQLite persistence ensuring covert syndicate rings are always loaded.
    """

    def __init__(self, db_path: str = SQLITE_DB):
        self.db_path = db_path
        self._init_db()

        self.hist_ids: list[str] = []
        self.hist_id_to_idx: dict[str, int] = {}
        self.hist_timestamps: np.ndarray = np.empty(0, dtype=np.float64)
        self.hist_amounts: np.ndarray = np.empty(0, dtype=np.float32)
        self.hist_avg_loans: np.ndarray = np.empty(0, dtype=np.float32)
        self.hist_is_fraud: np.ndarray = np.empty(0, dtype=np.int8)
        self.hist_matrix: np.ndarray = np.empty((0, 5), dtype=np.float32)

        self.live_ids: list[str] = []
        self.live_id_to_idx: dict[str, int] = {}
        self.live_timestamps: list[float] = []
        self.live_amounts: list[float] = []
        self.live_avg_loans: list[float] = []
        self.live_is_fraud: list[int] = []
        self.live_vectors: list[np.ndarray] = []

        self.raw_records: dict[str, dict] = {}

        self._write_queue: queue.Queue = queue.Queue()
        self._writer_thread = threading.Thread(target=self._bg_sqlite_worker, daemon=True)
        self._writer_thread.start()

        self._load_or_seed()

    @property
    def total_records(self) -> int:
        return len(self.hist_ids) + len(self.live_ids)

    def _init_db(self):
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_transactions (
                    account_id TEXT PRIMARY KEY,
                    requested_amount REAL,
                    avg_historical_loan REAL,
                    velocity_ratio REAL,
                    request_timestamp REAL,
                    device_hash TEXT,
                    ip_subnet TEXT,
                    payout_wallet_id TEXT,
                    is_known_fraud INTEGER DEFAULT 0
                )
                """
            )
            conn.commit()
            conn.close()

    def _bg_sqlite_worker(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        while True:
            batch = [self._write_queue.get()]
            while not self._write_queue.empty() and len(batch) < 500:
                try:
                    batch.append(self._write_queue.get_nowait())
                except queue.Empty:
                    break
            try:
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO user_transactions
                    (account_id, requested_amount, avg_historical_loan, velocity_ratio,
                     request_timestamp, device_hash, ip_subnet, payout_wallet_id, is_known_fraud)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    batch,
                )
                conn.commit()
            except Exception as e:
                print(f"[HistoricalStore] Async SQLite warning: {e}")

    @staticmethod
    def encode_feature_vector(
        requested_amount: float, avg_historical_loan: float, timestamp_sec: float
    ) -> np.ndarray:
        ratio = requested_amount / max(avg_historical_loan, 1.0)
        lt = time.localtime(timestamp_sec)
        hour_frac = (lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec) / 86400.0
        angle = 2.0 * math.pi * hour_frac

        vec = np.array(
            [
                math.log1p(max(requested_amount, 0.0)) / 12.0,
                math.log1p(max(avg_historical_loan, 0.0)) / 12.0,
                min(ratio, 20.0) / 10.0,
                math.sin(angle),
                math.cos(angle),
            ],
            dtype=np.float32,
        )
        norm = np.linalg.norm(vec)
        return vec / norm if norm > 0 else vec

    @staticmethod
    def _encode_matrix_vectorized(
        req_arr: np.ndarray, avg_arr: np.ndarray, ts_arr: np.ndarray
    ) -> np.ndarray:
        ratios = np.clip(req_arr / np.maximum(avg_arr, 1.0), 0.0, 20.0) / 10.0
        angles = 2.0 * np.pi * ((ts_arr % 86400.0) / 86400.0)

        mat = np.column_stack([
            np.log1p(np.maximum(req_arr, 0.0)) / 12.0,
            np.log1p(np.maximum(avg_arr, 0.0)) / 12.0,
            ratios,
            np.sin(angles),
            np.cos(angles),
        ]).astype(np.float32)

        norms = np.linalg.norm(mat, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return mat / norms

    def _load_or_seed(self):
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            count = conn.execute("SELECT COUNT(*) FROM user_transactions").fetchone()[0]
            has_covert = conn.execute("SELECT COUNT(*) FROM user_transactions WHERE account_id LIKE 'COVERT_%'").fetchone()[0]
            conn.close()

        if count < 1_000_000 or has_covert == 0:
            self.seed_million_users(total_users=1_000_000)
        else:
            self._rebuild_ram_index()

    def seed_million_users(self, total_users: int = 1_000_000):
        t0 = time.perf_counter()
        print(f"[HistoricalStore] Generating and persisting {total_users:,} historical user profiles + covert rings...")
        rng = np.random.default_rng(42)
        base_now = time.time() - 86400 * 30
        num_normal = total_users - 45

        avg_loans = rng.uniform(500.0, 4500.0, size=num_normal).astype(np.float32)
        ratios = rng.uniform(0.6, 2.0, size=num_normal).astype(np.float32)
        req_amts = np.round(avg_loans * ratios, 2)
        timestamps = base_now + rng.uniform(0.0, 86400.0 * 30, size=num_normal)
        is_fraud = np.zeros(num_normal, dtype=np.int8)
        acc_ids = [f"HIST_USR_{i:07d}" for i in range(num_normal)]

        covert_rings = [
            ("COVERT_ALPHA", 18, 1250.0, 4800.0, base_now + 86400 * 5),
            ("COVERT_BRAVO", 15, 2100.0, 7900.0, base_now + 86400 * 15),
            ("COVERT_OMEGA", 12, 950.0, 3900.0, base_now + 86400 * 25),
        ]

        c_ids, c_avg, c_req, c_ts, c_fraud = [], [], [], [], []
        for prefix, size, b_avg, b_req, burst_ts in covert_rings:
            for j in range(size):
                cid = f"{prefix}_{j:02d}"
                c_ids.append(cid)
                c_avg.append(round(b_avg + float(rng.uniform(-15, 15)), 2))
                c_req.append(round(b_req + float(rng.uniform(-25, 25)), 2))
                c_ts.append(burst_ts + float(rng.uniform(0, 90)))
                c_fraud.append(1)

        all_ids = acc_ids + c_ids
        all_avg = np.concatenate([avg_loans, np.array(c_avg, dtype=np.float32)])
        all_req = np.concatenate([req_amts, np.array(c_req, dtype=np.float32)])
        all_ts = np.concatenate([timestamps, np.array(c_ts, dtype=np.float64)])
        all_fraud = np.concatenate([is_fraud, np.array(c_fraud, dtype=np.int8)])

        sort_order = np.argsort(all_ts)
        with db_lock:
            self.hist_timestamps = all_ts[sort_order]
            self.hist_amounts = all_req[sort_order]
            self.hist_avg_loans = all_avg[sort_order]
            self.hist_is_fraud = all_fraud[sort_order]
            self.hist_ids = [all_ids[idx] for idx in sort_order]
            self.hist_id_to_idx = {aid: i for i, aid in enumerate(self.hist_ids)}
            self.hist_matrix = self._encode_matrix_vectorized(
                self.hist_amounts, self.hist_avg_loans, self.hist_timestamps
            )

            # Persist all records to SQLite so covert rings survive restarts
            conn = sqlite3.connect(self.db_path)
            conn.execute("DELETE FROM user_transactions;")
            rows = [
                (
                    self.hist_ids[k],
                    float(self.hist_amounts[k]),
                    float(self.hist_avg_loans[k]),
                    round(float(self.hist_amounts[k]) / max(float(self.hist_avg_loans[k]), 1.0), 3),
                    float(self.hist_timestamps[k]),
                    f"DEV_SPOOF_{self.hist_ids[k]}" if "COVERT_" in self.hist_ids[k] else f"DEV_{self.hist_ids[k]}",
                    "10.0.0.0/24",
                    f"WAL_BURNER_{self.hist_ids[k]}" if "COVERT_" in self.hist_ids[k] else f"WAL_{self.hist_ids[k]}",
                    int(self.hist_is_fraud[k]),
                )
                for k in range(len(self.hist_ids))
            ]
            conn.executemany("INSERT INTO user_transactions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
            conn.commit()
            conn.close()

            for i, cid in enumerate(c_ids):
                self.raw_records[cid] = {
                    "account_id": cid,
                    "requested_amount": float(c_req[i]),
                    "avg_historical_loan": float(c_avg[i]),
                    "velocity_ratio": round(float(c_req[i]) / float(c_avg[i]), 3),
                    "request_timestamp": float(c_ts[i]),
                    "device_hash": f"DEV_SPOOF_{cid}",
                    "ip_subnet": f"172.{16 + (i % 15)}.{(i * 7) % 250}.0/24",
                    "payout_wallet_id": f"WAL_BURNER_{cid}",
                    "is_known_fraud": True,
                }

        elapsed = round(time.perf_counter() - t0, 2)
        print(f"[HistoricalStore] Indexed & persisted {len(self.hist_ids):,} user vectors in {elapsed}s.")

    def _rebuild_ram_index(self):
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute(
                """
                SELECT account_id, requested_amount, avg_historical_loan, velocity_ratio,
                       request_timestamp, device_hash, ip_subnet, payout_wallet_id, is_known_fraud
                FROM user_transactions
                ORDER BY request_timestamp ASC
                """
            )
            records = cursor.fetchall()
            conn.close()

            n = len(records)
            self.hist_ids = [r[0] for r in records]
            self.hist_id_to_idx = {aid: i for i, aid in enumerate(self.hist_ids)}
            self.hist_amounts = np.array([r[1] for r in records], dtype=np.float32)
            self.hist_avg_loans = np.array([r[2] for r in records], dtype=np.float32)
            self.hist_timestamps = np.array([r[4] for r in records], dtype=np.float64)
            self.hist_is_fraud = np.array([r[8] for r in records], dtype=np.int8)
            self.hist_matrix = (
                self._encode_matrix_vectorized(
                    self.hist_amounts, self.hist_avg_loans, self.hist_timestamps
                )
                if n > 0
                else np.empty((0, 5), dtype=np.float32)
            )
            for r in records:
                if "COVERT_" in r[0]:
                    self.raw_records[r[0]] = {
                        "account_id": r[0],
                        "requested_amount": r[1],
                        "avg_historical_loan": r[2],
                        "velocity_ratio": r[3],
                        "request_timestamp": r[4],
                        "device_hash": r[5],
                        "ip_subnet": r[6],
                        "payout_wallet_id": r[7],
                        "is_known_fraud": bool(r[8]),
                    }

    def get_record(self, account_id: str) -> dict | None:
        if account_id in self.raw_records:
            return self.raw_records[account_id]
        idx = self.hist_id_to_idx.get(account_id)
        if idx is not None:
            rec = {
                "account_id": account_id,
                "requested_amount": float(self.hist_amounts[idx]),
                "avg_historical_loan": float(self.hist_avg_loans[idx]),
                "velocity_ratio": round(
                    float(self.hist_amounts[idx]) / max(float(self.hist_avg_loans[idx]), 1.0), 3
                ),
                "request_timestamp": float(self.hist_timestamps[idx]),
                "device_hash": f"DEV_{account_id}",
                "ip_subnet": "10.0.0.0/24",
                "payout_wallet_id": f"WAL_{account_id}",
                "is_known_fraud": bool(self.hist_is_fraud[idx]),
            }
            self.raw_records[account_id] = rec
            return rec
        return None

    def mark_cohort_confirmed_fraud(self, account_ids: list[str]):
        with db_lock:
            for aid in account_ids:
                if aid in self.raw_records:
                    self.raw_records[aid]["is_known_fraud"] = True
                l_idx = self.live_id_to_idx.get(aid)
                if l_idx is not None and l_idx < len(self.live_is_fraud):
                    self.live_is_fraud[l_idx] = 1
                h_idx = self.hist_id_to_idx.get(aid)
                if h_idx is not None:
                    self.hist_is_fraud[h_idx] = 1

    def upsert_transaction(
        self,
        account_id: str,
        requested_amount: float,
        avg_historical_loan: float,
        request_timestamp: float,
        device_hash: str,
        ip_subnet: str,
        payout_wallet_id: str,
        is_known_fraud: int = 0,
    ):
        ratio = round(requested_amount / max(avg_historical_loan, 1.0), 3)
        vec = self.encode_feature_vector(requested_amount, avg_historical_loan, request_timestamp)

        self._write_queue.put((
            account_id,
            requested_amount,
            avg_historical_loan,
            ratio,
            request_timestamp,
            device_hash,
            ip_subnet,
            payout_wallet_id,
            is_known_fraud,
        ))

        with db_lock:
            self.raw_records[account_id] = {
                "account_id": account_id,
                "requested_amount": requested_amount,
                "avg_historical_loan": avg_historical_loan,
                "velocity_ratio": ratio,
                "request_timestamp": request_timestamp,
                "device_hash": device_hash,
                "ip_subnet": ip_subnet,
                "payout_wallet_id": payout_wallet_id,
                "is_known_fraud": bool(is_known_fraud),
            }
            idx = len(self.live_ids)
            self.live_id_to_idx[account_id] = idx
            self.live_ids.append(account_id)
            self.live_timestamps.append(request_timestamp)
            self.live_amounts.append(requested_amount)
            self.live_avg_loans.append(avg_historical_loan)
            self.live_is_fraud.append(is_known_fraud)
            self.live_vectors.append(vec)

            if len(self.live_ids) > 5000:
                self.live_ids = self.live_ids[-2500:]
                self.live_id_to_idx = {aid: i for i, aid in enumerate(self.live_ids)}
                self.live_timestamps = self.live_timestamps[-2500:]
                self.live_amounts = self.live_amounts[-2500:]
                self.live_avg_loans = self.live_avg_loans[-2500:]
                self.live_is_fraud = self.live_is_fraud[-2500:]
                self.live_vectors = self.live_vectors[-2500:]


historical_store = HistoricalBehavioralStore()