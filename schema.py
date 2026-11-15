# schema.py
from pydantic import BaseModel

class LoanApplication(BaseModel):
    account_id: str             # Unique ID for the borrower (e.g., "ACC_101")
    requested_amount: float     # Loan amount requested (e.g., 50000.0)
    avg_historical_loan: float # Average past loan baseline (e.g., 1000.0)
    device_hash: str          # Unique device fingerprint (e.g., "DEV_9901")
    ip_subnet: str            # Network range (e.g., "192.168.1.0/24")
    payout_wallet_id: str     # Destination bank/UPI account (e.g., "WAL_7702")

class RiskVerdict(BaseModel):
    account_id: str
    risk_score: float         #game changer- a value between 0.0 and 1.0 indicating the risk level
    tier1_flagged: bool
    tier2_cluster_flagged: bool
    verdict: str               # "ALLOW", "FLAG_FRICTION", "BLOCK"
    reason: str