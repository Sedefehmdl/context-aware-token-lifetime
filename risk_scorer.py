import datetime

def compute_risk_score(ip_known, off_hours, failed_logins, mfa_used):
    score = 0
    if not ip_known:
        score += 3
    if off_hours:
        score += 2
    if failed_logins >= 3:
        score += 3
    if not mfa_used:
        score += 2
    return score

def get_dynamic_lifetime(score):
    if score <= 3:
        return 7200   # Low risk
    elif score <= 6:
        return 3600   # Medium risk
    else:
        return 900    # High risk

if __name__ == "__main__":
    scenarios = [
        ("Low risk",    True,  False, 0, True),
        ("Medium risk", False, False, 0, True),
        ("High risk",   False, True,  5, False),
    ]
    for label, ip_known, off_hours, failed, mfa in scenarios:
        score = compute_risk_score(ip_known, off_hours, failed, mfa)
        lifetime = get_dynamic_lifetime(score)
        print(f"{label}: score={score}, lifetime={lifetime}s")
