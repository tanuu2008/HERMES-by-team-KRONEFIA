import math

class AdaptiveVelocityEnvelope:
    def __init__(self, alpha: float = 0.08, k_sigma: float = 2.5, min_floor: float = 2.0):
        self.alpha = alpha
        self.k_sigma = k_sigma
        self.min_floor = min_floor
        self.ema_mean = 1.5
        self.ema_var = 0.25
        self.quarantined_entities = set()
        self.blocked_ledger_inr = 0.0

    def reset_session(self):
        self.quarantined_entities.clear()
        self.blocked_ledger_inr = 0.0

    def update_and_get_bar(self, observed_velocity_ratio: float, cohort_size: int) -> float:
        # Adapt baseline bar strictly on uncoordinated organic traffic so rings cannot poison the threshold
        if cohort_size == 0:
            diff = observed_velocity_ratio - self.ema_mean
            self.ema_mean += self.alpha * diff
            self.ema_var = (1.0 - self.alpha) * (self.ema_var + self.alpha * (diff ** 2))
        dynamic_std = math.sqrt(max(self.ema_var, 0.05))
        return max(self.min_floor, round(self.ema_mean + (self.k_sigma * dynamic_std), 3))

adaptive_guard = AdaptiveVelocityEnvelope()

def enforce_autonomous_action(
    user_id: str,
    recipient_id: str,
    amount: float,
    risk_score: float,
    cohort_size: int = 0,
    historical_avg_amount: float = 1000.0,
) -> dict:
    hist_avg = max(float(historical_avg_amount or 1000.0), 1.0)
    observed_velocity = float(amount) / hist_avg
    dynamic_bar = adaptive_guard.update_and_get_bar(observed_velocity, cohort_size)

    ring_tainted = (
        user_id in adaptive_guard.quarantined_entities
        or recipient_id in adaptive_guard.quarantined_entities
    )

    if ring_tainted:
        risk_score = max(float(risk_score), 0.99)

    if risk_score >= 0.85 or ring_tainted:
        action = "QUARANTINE_AND_FREEZE_RING"
        settlement_status = "BLOCKED_AT_SWITCH"
        adaptive_guard.quarantined_entities.update([user_id, recipient_id])
        adaptive_guard.blocked_ledger_inr += float(amount)
    elif risk_score >= 0.65 or (cohort_size >= 3 and observed_velocity > dynamic_bar):
        action = "BLOCK_AND_STEPUP_VKYC"
        settlement_status = "HELD_IN_ESCROW"
        adaptive_guard.quarantined_entities.add(user_id)
        adaptive_guard.blocked_ledger_inr += float(amount)
    elif risk_score >= 0.45:
        action = "CHALLENGE_OTP_DEVICE_BIND"
        settlement_status = "PENDING_2FA"
    else:
        action = "APPROVE_SETTLEMENT"
        settlement_status = "SETTLED"

    return {
        "risk_score": round(float(risk_score), 4),
        "action": action,
        "decision": action,
        "settlement_status": settlement_status,
        "dynamic_velocity_bar": dynamic_bar,
        "observed_velocity": round(observed_velocity, 3),
        "quarantined_node_count": len(adaptive_guard.quarantined_entities),
        "cumulative_capital_saved_inr": round(adaptive_guard.blocked_ledger_inr, 2),
    }