"""
measure_metrics.py
Runs all 4 attack scenarios through the detector and times the responder,
to produce real numbers for the CV. Runs fully offline (no AWS needed).

Place this file in the project root (next to the src/ folder) and run:
    python measure_metrics.py
"""
import sys, os, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from attack_chain import AttackChainDetector
from responder import AutomatedResponder

def make_event(source, ts, event_name, ip="203.0.113.50", user="target-user", error=None):
    return {
        'source': source,
        'timestamp': ts,
        'message': json.dumps({
            'eventName': event_name, 'username': user,
            'sourceIP': ip, 'errorCode': error, 'resources': []
        })
    }

# Each scenario = a fresh detector fed a clean sequence for ONE attack type.
def scenario_brute_force(d, t):
    for i in range(5):
        d.add_event(make_event('cloudtrail', t + i*1000, 'ConsoleLogin', error='Failed authentication'))
    d.add_event(make_event('cloudtrail', t + 6000, 'ConsoleLogin', error=None))
    return d.add_event(make_event('cloudtrail', t + 7000, 'CreateUser'))

def scenario_data_exfil(d, t):
    for i, ev in enumerate(['ListBuckets','ListObjects','ListUsers','ListRoles','DescribeInstances']):
        d.add_event(make_event('cloudtrail', t + i*1000, ev))
    d.add_event(make_event('cloudtrail', t + 6000, 'GetObject'))
    return d.add_event(make_event('vpc_flows', t + 7000, 'NETWORK_OUT'))

def scenario_defense_evasion(d, t):
    d.add_event(make_event('cloudtrail', t, 'DeleteTrail', ip='198.51.100.7', user='attacker'))
    return d.add_event(make_event('cloudtrail', t + 5000, 'DeleteBucket', ip='198.51.100.7', user='attacker'))

def scenario_credential_compromise(d, t):
    d.add_event(make_event('cloudtrail', t, 'CreateAccessKey'))
    for i, ev in enumerate(['GetCallerIdentity','ListBuckets','DescribeInstances']):
        d.add_event(make_event('cloudtrail', t + (i+1)*1000, ev))
    return None  # last add_event above returns the detection

scenarios = [
    ("Brute Force Takeover", scenario_brute_force),
    ("Data Exfiltration", scenario_data_exfil),
    ("Defense Evasion", scenario_defense_evasion),
    ("Credential Compromise", scenario_credential_compromise),
]

print("="*60)
print("ATTACK DETECTION TEST")
print("="*60)

base = int(time.time() * 1000)
detected = 0
all_detections = []
for name, fn in scenarios:
    d = AttackChainDetector()
    fn(d, base)
    hits = len(d.detected_chains)
    ok = hits >= 1
    detected += 1 if ok else 0
    if d.detected_chains:
        all_detections.append(d.detected_chains[0])
    print(f"  {'CAUGHT ' if ok else 'MISSED '} {name}")

total = len(scenarios)
accuracy = round(detected / total * 100)
print("-"*60)
print(f"RESULT: detected {detected} of {total} attack scenarios ({accuracy}% detection rate)")

# ---- Time the automated responder ----
print("\n" + "="*60)
print("RESPONSE TIME TEST")
print("="*60)
if all_detections:
    responder = AutomatedResponder()
    start = time.time()
    responder.respond_to_detection(all_detections[0])
    elapsed = time.time() - start
    print("-"*60)
    print(f"Automated response completed in {elapsed:.2f} seconds")
    print(f"(Manual equivalent in AWS console: ~2-3 minutes)")

print("\n>>> Copy these numbers for your CV:")
print(f"    X (caught) = {detected}")
print(f"    Y (total)  = {total}")
print(f"    Z (accuracy %) = {accuracy}")
if all_detections:
    print(f"    N (response seconds) = {elapsed:.2f}")
