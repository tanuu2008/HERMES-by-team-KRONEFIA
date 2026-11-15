# tier1.py
from schema import LoanApplication

def check_tier1_rules(app: LoanApplication) -> tuple[bool, str]:
    """
    Evaluates microsecond pre-filter rules.
    Returns a tuple: (is_flagged, reason_message)
    """
    # Rule 1: 10x Velocity Spike Check
    if app.avg_historical_loan > 0:
        multiplier = app.requested_amount / app.avg_historical_loan
        if multiplier >= 10.0:
            return True, f"10x Velocity Spike: Requested {multiplier:.1f}x historical baseline."

    # Rule 2: Zero-History High Credit Check
    if app.avg_historical_loan == 0 and app.requested_amount >= 25000:
        return True, "High credit request (>= ₹25,000) on a zero-history account."

    return False, "Tier 1 Passed"