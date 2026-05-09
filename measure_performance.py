import subprocess, time, statistics, requests

KEYSTONE_URL = "http://localhost:5000/v3/auth/tokens"
AUTH_BODY = {
    "auth": {
        "identity": {
            "methods": ["password"],
            "password": {"user": {"name": "admin", "domain": {"id": "default"}, "password": "AdminPass123"}}
        },
        "scope": {"project": {"name": "admin", "domain": {"id": "default"}}}
    }
}
HEADERS = {"Content-Type": "application/json"}

def request_token():
    t0 = time.perf_counter()
    r = requests.post(KEYSTONE_URL, headers=HEADERS, json=AUTH_BODY, timeout=30)
    return time.perf_counter() - t0

def run(label):
    print(f"\n[{label}] warming up (5 requests)...", flush=True)
    for _ in range(5):
        request_token()
    time.sleep(1)
    times = []
    print(f"[{label}] timing 10 requests...", flush=True)
    for i in range(1, 11):
        t = request_token()
        times.append(t)
        print(f"  Run {i:2d}: {t:.3f}s")
    print(f"  Mean: {statistics.mean(times):.3f}s  StdDev: {statistics.stdev(times):.3f}s")
    return times

# --- PATCHED run ---
patched = run("PATCHED")

# --- UNPATCHED run ---
input("\nNow disable the patch: comment out 'import dynamic_lifetime' in /usr/bin/keystone-wsgi-public, then restart Apache. Press ENTER when ready...")
subprocess.run(["sudo", "systemctl", "restart", "apache2"])
time.sleep(5)
unpatched = run("UNPATCHED")

# --- results ---
print("\n{:<6} {:>12} {:>12}".format("Run", "Patched(s)", "Unpatched(s)"))
print("-" * 32)
for i,(p,u) in enumerate(zip(patched, unpatched), 1):
    print(f"{i:<6} {p:>12.3f} {u:>12.3f}")
print("-" * 32)
print(f"{'Mean':<6} {statistics.mean(patched):>12.3f} {statistics.mean(unpatched):>12.3f}")
print(f"{'StdDev':<6} {statistics.stdev(patched):>12.3f} {statistics.stdev(unpatched):>12.3f}")
overhead = (statistics.mean(patched) - statistics.mean(unpatched)) * 1000
print(f"\nMean overhead: {overhead:+.1f} ms")
