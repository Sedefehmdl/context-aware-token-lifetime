import datetime
import logging
import os
from oslo_utils import timeutils

logger = logging.getLogger('dynamic_lifetime')
logger.setLevel(logging.INFO)
if not logger.handlers:
    fh = logging.FileHandler('/var/log/keystone/dynamic_lifetime.log')
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    logger.addHandler(fh)

KNOWN_IPS_FILE = '/etc/keystone/known_ips.txt'

def load_known_ips():
    if not os.path.exists(KNOWN_IPS_FILE):
        return set()
    with open(KNOWN_IPS_FILE, 'r') as f:
        return set(line.strip() for line in f if line.strip())

def check_ip(ip):
    known = load_known_ips()
    if ip not in known:
        with open(KNOWN_IPS_FILE, 'a') as f:
            f.write(ip + '\n')
        return False
    return True

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

        try:
            from flask import request
            ip = request.environ.get('HTTP_X_FORWARDED_FOR',
                 request.environ.get('REMOTE_ADDR', '0.0.0.0'))
        except Exception:
            ip = '0.0.0.0'

        ip_known = check_ip(ip)
        failed_logins = 0
        mfa_used = True

        score = compute_risk_score(ip_known, off_hours,
                                   failed_logins, mfa_used)
        seconds = get_dynamic_lifetime(score)

        logger.info(
            "TOKEN ISSUED | ip=%s | ip_known=%s | off_hours=%s | "
            "failed_logins=%s | mfa_used=%s | score=%s | lifetime=%ss"
            % (ip, ip_known, off_hours, failed_logins,
               mfa_used, score, seconds)
        )
        return timeutils.utcnow() + datetime.timedelta(seconds=seconds)

    except Exception as e:
        logger.error("Patch error: %s, falling back to 3600s" % e)
        return timeutils.utcnow() + datetime.timedelta(seconds=3600)

import keystone.token.provider as _provider
_provider.default_expire_time = patched_default_expire_time
