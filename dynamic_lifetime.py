"""
dynamic_lifetime.py — Context-Aware Token Lifetime for OpenStack Keystone
"""

import datetime
import logging
import os

import pymysql
from oslo_utils import timeutils
from zoneinfo import ZoneInfo

KNOWN_IPS_FILE  = "/etc/keystone/known_ips.txt"
AUDIT_LOG_FILE  = "/var/log/keystone/dynamic_lifetime.log"
LOCAL_TIMEZONE  = ZoneInfo("Europe/Budapest")
BUSINESS_START  = 6
BUSINESS_END    = 20
FAILURE_WINDOW  = 900
FAILURE_THRESH  = 3

DB_CONFIG = {
    "host":   "localhost",
    "user":   "keystone",
    "passwd": "keystonepass",
    "db":     "keystone",
    "connect_timeout": 2,
}

logger = logging.getLogger("dynamic_lifetime")
logger.setLevel(logging.INFO)
if not logger.handlers:
    try:
        fh = logging.FileHandler(AUDIT_LOG_FILE)
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.addHandler(fh)
    except Exception as e:
        print(f"dynamic_lifetime: could not open audit log: {e}")

def check_ip(ip):
    try:
        known = set()
        if os.path.exists(KNOWN_IPS_FILE):
            with open(KNOWN_IPS_FILE, "r") as f:
                known = {line.strip() for line in f if line.strip()}
        if ip in known:
            return True
        with open(KNOWN_IPS_FILE, "a") as f:
            f.write(ip + "\n")
        return False
    except Exception as e:
        logger.warning("check_ip error (%s): %s — defaulting ip_known=True", ip, e)
        return True

def is_off_hours():
    local_now = datetime.datetime.now(tz=LOCAL_TIMEZONE)
    hour = local_now.hour
    return not (BUSINESS_START <= hour < BUSINESS_END)

def get_failed_login_count(user_id):
    if not user_id:
        return 0
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cur:
            window_start = datetime.datetime.utcnow() - datetime.timedelta(seconds=FAILURE_WINDOW)
            cur.execute(
                "SELECT COUNT(*) FROM login_failures WHERE user_id = %s AND attempted_at >= %s",
                (user_id, window_start),
            )
            row = cur.fetchone()
        conn.close()
        return int(row[0]) if row else 0
    except pymysql.err.ProgrammingError as e:
        logger.warning("login_failures table not found, defaulting to 0: %s", e)
        return 0
    except Exception as e:
        logger.warning("get_failed_login_count error: %s — defaulting to 0", e)
        return 0

def check_mfa_used():
    try:
        from flask import request
        body = request.get_json(silent=True, force=True)
        if not body:
            return True
        methods = body.get("auth", {}).get("identity", {}).get("methods", [])
        mfa_methods = {"totp", "mapped", "oauth1", "application_credential"}
        return bool(mfa_methods.intersection(set(methods)))
    except Exception as e:
        logger.warning("check_mfa_used error: %s — defaulting mfa_used=True", e)
        return True

def compute_risk_score(ip_known, off_hours, failed_logins, mfa_used):
    score = 0
    if not ip_known:
        score += 3
    if off_hours:
        score += 2
    if failed_logins >= FAILURE_THRESH:
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

def _get_user_id_from_request():
    try:
        from flask import request
        body = request.get_json(silent=True, force=True) or {}
        user = body.get("auth", {}).get("identity", {}).get("password", {}).get("user", {})
        return user.get("id") or user.get("name") or ""
    except Exception:
        return ""

def patched_default_expire_time():
    try:
        from flask import request
        ip = request.environ.get("HTTP_X_FORWARDED_FOR",
                                 request.environ.get("REMOTE_ADDR", "0.0.0.0"))
        ip = ip.split(",")[0].strip()

        ip_known      = check_ip(ip)
        off_hours     = is_off_hours()
        user_id       = _get_user_id_from_request()
        failed_logins = get_failed_login_count(user_id)
        mfa_used      = check_mfa_used()

        score    = compute_risk_score(ip_known, off_hours, failed_logins, mfa_used)
        lifetime = get_dynamic_lifetime(score)

        local_now = datetime.datetime.now(tz=LOCAL_TIMEZONE)
        logger.info(
            "TOKEN ISSUED | ip=%s | ip_known=%s | off_hours=%s | local_time=%s "
            "| failed_logins=%d | mfa_used=%s | score=%d | lifetime=%ds",
            ip, ip_known, off_hours,
            local_now.strftime("%H:%M %Z"),
            failed_logins, mfa_used,
            score, lifetime,
        )

        return timeutils.utcnow() + datetime.timedelta(seconds=lifetime)

    except Exception as e:
        logger.error("Patch error: %s, falling back to 3600s", e)
        return timeutils.utcnow() + datetime.timedelta(seconds=3600)

def apply_patch():
    try:
        import keystone.token.provider as provider
        provider.default_expire_time = patched_default_expire_time
        logger.info("dynamic_lifetime patch applied successfully")
    except Exception as e:
        logger.error("Failed to apply patch: %s", e)

apply_patch()
