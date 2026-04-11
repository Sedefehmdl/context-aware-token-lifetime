import datetime
import logging
import os
from oslo_utils import timeutils

LOG_FILE = '/var/log/keystone/dynamic_lifetime.log'

logger = logging.getLogger('dynamic_lifetime')
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.FileHandler(LOG_FILE)
    handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    logger.addHandler(handler)

KNOWN_IPS = {'127.0.0.1', '10.0.2.2', '10.0.2.15'}

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
        return 7200
    elif score <= 6:
        return 3600
    else:
        return 900

def patched_default_expire_time():
    try:
        hour = datetime.datetime.utcnow().hour
        off_hours = hour < 6 or hour >= 20
        ip_known = True
        failed_logins = 0
        mfa_used = True

        score = compute_risk_score(ip_known, off_hours, failed_logins, mfa_used)
        seconds = get_dynamic_lifetime(score)

        logger.info(
            f"TOKEN ISSUED | ip_known={ip_known} | off_hours={off_hours} | "
            f"failed_logins={failed_logins} | mfa_used={mfa_used} | "
            f"score={score} | lifetime={seconds}s"
        )

        expire_delta = datetime.timedelta(seconds=seconds)
        return timeutils.utcnow() + expire_delta

    except Exception as e:
        logger.error(f"Patch error: {e}, falling back to 3600s")
        return timeutils.utcnow() + datetime.timedelta(seconds=3600)

import keystone.token.provider as _provider
_provider.default_expire_time = patched_default_expire_time
