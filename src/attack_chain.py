import json
import time
from datetime import datetime, timezone, timedelta
from collections import defaultdict

TIMEZONE_OFFSET = 7  # Thailand UTC+7

# Attack chain definitions
# Each chain is a sequence of steps that together = a confirmed attack
ATTACK_CHAINS = {
    "brute_force_takeover": {
        "description": "Brute force login followed by account takeover",
        "severity": 9,
        "steps": [
            {
                "id": "multiple_failed_logins",
                "description": "Multiple failed login attempts",
                "condition": lambda e, ctx: (
                    json.loads(e.get('message', '{}')).get('eventName') == 'ConsoleLogin' and
                    json.loads(e.get('message', '{}')).get('errorCode') is not None
                ),
                "threshold": 5,  # must see this 5 times
                "window_seconds": 300  # within 5 minutes
            },
            {
                "id": "successful_login",
                "description": "Successful login after failures",
                "condition": lambda e, ctx: (
                    json.loads(e.get('message', '{}')).get('eventName') == 'ConsoleLogin' and
                    json.loads(e.get('message', '{}')).get('errorCode') is None
                ),
                "threshold": 1,
                "window_seconds": 600
            },
            {
                "id": "privilege_escalation",
                "description": "Attempt to escalate privileges",
                "condition": lambda e, ctx: (
                    json.loads(e.get('message', '{}')).get('eventName') in [
                        'CreateUser', 'AttachUserPolicy', 'AddUserToGroup',
                        'CreateAccessKey', 'PutUserPolicy', 'CreateRole'
                    ]
                ),
                "threshold": 1,
                "window_seconds": 1800
            }
        ]
    },

    "data_exfiltration": {
        "description": "Reconnaissance followed by data theft",
        "severity": 8,
        "steps": [
            {
                "id": "reconnaissance",
                "description": "Scanning/listing resources",
                "condition": lambda e, ctx: (
                    json.loads(e.get('message', '{}')).get('eventName') in [
                        'ListBuckets', 'ListObjects', 'DescribeInstances',
                        'ListUsers', 'ListRoles', 'DescribeDBInstances'
                    ]
                ),
                "threshold": 5,
                "window_seconds": 300
            },
            {
                "id": "data_access",
                "description": "Accessing sensitive data",
                "condition": lambda e, ctx: (
                    json.loads(e.get('message', '{}')).get('eventName') in [
                        'GetObject', 'GetSecretValue', 'GetParameter',
                        'DownloadDBLogFilePortion', 'GetPasswordData'
                    ]
                ),
                "threshold": 1,
                "window_seconds": 600
            },
            {
                "id": "high_network_outbound",
                "description": "Unusual outbound network traffic",
                "condition": lambda e, ctx: (
                    e.get('source') == 'vpc_flows'
                ),
                "threshold": 1,
                "window_seconds": 1800
            }
        ]
    },

    "defense_evasion": {
        "description": "Attacker trying to cover tracks",
        "severity": 10,
        "steps": [
            {
                "id": "disable_logging",
                "description": "Attempt to disable security logging",
                "condition": lambda e, ctx: (
                    json.loads(e.get('message', '{}')).get('eventName') in [
                        'DeleteTrail', 'StopLogging', 'DeleteLogGroup',
                        'PutEventSelectors', 'DeleteFlowLogs'
                    ]
                ),
                "threshold": 1,
                "window_seconds": 60
            },
            {
                "id": "delete_evidence",
                "description": "Deleting resources to remove evidence",
                "condition": lambda e, ctx: (
                    json.loads(e.get('message', '{}')).get('eventName') in [
                        'DeleteBucket', 'DeleteObject', 'TerminateInstances',
                        'DeleteLogStream', 'DeleteAlarm'
                    ]
                ),
                "threshold": 1,
                "window_seconds": 300
            }
        ]
    },

    "credential_compromise": {
        "description": "Credentials being stolen or misused",
        "severity": 8,
        "steps": [
            {
                "id": "access_key_creation",
                "description": "New access key created suspiciously",
                "condition": lambda e, ctx: (
                    json.loads(e.get('message', '{}')).get('eventName') == 'CreateAccessKey'
                ),
                "threshold": 1,
                "window_seconds": 60
            },
            {
                "id": "new_key_used",
                "description": "New credentials used immediately",
                "condition": lambda e, ctx: (
                    json.loads(e.get('message', '{}')).get('eventName') in [
                        'GetCallerIdentity', 'ListBuckets', 'DescribeInstances'
                    ]
                ),
                "threshold": 3,
                "window_seconds": 300
            }
        ]
    }
}


class AttackChainDetector:
    def __init__(self):
        self.event_buffer = []
        self.detected_chains = []
        self.step_progress = defaultdict(lambda: defaultdict(list))

    def add_event(self, event):
        """Add event to buffer and check for attack chains"""
        self.event_buffer.append(event)
        # Keep only last 2 hours of events
        cutoff = time.time() * 1000 - (2 * 60 * 60 * 1000)
        self.event_buffer = [
            e for e in self.event_buffer
            if e.get('timestamp', 0) > cutoff
        ]
        return self.check_chains(event)

    def check_chains(self, new_event):
        """Check if new event completes or advances any attack chain"""
        detections = []

        for chain_name, chain in ATTACK_CHAINS.items():
            detection = self.evaluate_chain(chain_name, chain, new_event)
            if detection:
                detections.append(detection)
                self.detected_chains.append(detection)
                print(f"\n{'='*60}")
                print(f"[ATTACK CHAIN DETECTED] {chain_name.upper()}")
                print(f"Description: {chain['description']}")
                print(f"Severity: {chain['severity']}/10")
                print(f"Steps completed: {len(detection['completed_steps'])}")
                for step in detection['completed_steps']:
                    print(f"  ✓ {step}")
                print(f"{'='*60}\n")

        return detections

    def evaluate_chain(self, chain_name, chain, new_event):
        """Evaluate if events match a specific attack chain"""
        steps = chain['steps']
        completed_steps = []
        step_events = {}
        current_time = new_event.get('timestamp', 0)

        for i, step in enumerate(steps):
            matching_events = []
            window_start = current_time - (step['window_seconds'] * 1000)

            for event in self.event_buffer:
                if event.get('timestamp', 0) < window_start:
                    continue
                try:
                    if step['condition'](event, {}):
                        matching_events.append(event)
                except:
                    continue

            if len(matching_events) >= step['threshold']:
                completed_steps.append(step['description'])
                step_events[step['id']] = matching_events
            else:
                # Chain broken — not all steps completed
                if i > 0 and len(completed_steps) > 0:
                    # Partial chain — still interesting
                    pass
                break

        # Full chain detected
        if len(completed_steps) == len(steps):
            return {
                'chain_name': chain_name,
                'description': chain['description'],
                'severity': chain['severity'],
                'completed_steps': completed_steps,
                'step_events': step_events,
                'detected_at': datetime.now(timezone.utc).isoformat(),
                'event_count': sum(len(v) for v in step_events.values())
            }
        return None

    def analyze_file(self, events_file):
        """Analyze all events from file"""
        print(f"[ATTACK CHAIN] Loading events from {events_file}")
        events = []
        try:
            with open(events_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
        except FileNotFoundError:
            print(f"[ATTACK CHAIN] No events file found")
            return []

        print(f"[ATTACK CHAIN] Analyzing {len(events)} events for attack chains...")
        all_detections = []
        for event in events:
            detections = self.add_event(event)
            all_detections.extend(detections)

        print(f"[ATTACK CHAIN] Analysis complete. {len(all_detections)} chains detected.")
        return all_detections

    def simulate_attacks(self):
        """Simulate multiple attack types to test detection"""
        print("\n[SIMULATE] Running attack chain simulations...\n")
        base_time = int(time.time() * 1000)

        # Simulation 1: Brute Force Takeover
        print("[SIMULATE] Attack 1: Brute Force Takeover")
        for i in range(6):
            self.add_event({
                'source': 'cloudtrail',
                'timestamp': base_time + (i * 15000),
                'message': json.dumps({
                    'eventName': 'ConsoleLogin',
                    'username': 'victim-user',
                    'sourceIP': '192.168.1.100',
                    'errorCode': 'Failed authentication',
                    'resources': []
                })
            })

        self.add_event({
            'source': 'cloudtrail',
            'timestamp': base_time + 100000,
            'message': json.dumps({
                'eventName': 'ConsoleLogin',
                'username': 'victim-user',
                'sourceIP': '192.168.1.100',
                'errorCode': None,
                'resources': []
            })
        })

        self.add_event({
            'source': 'cloudtrail',
            'timestamp': base_time + 200000,
            'message': json.dumps({
                'eventName': 'CreateUser',
                'username': 'victim-user',
                'sourceIP': '192.168.1.100',
                'errorCode': None,
                'resources': []
            })
        })

        # Simulation 2: Defense Evasion
        print("[SIMULATE] Attack 2: Defense Evasion")
        self.add_event({
            'source': 'cloudtrail',
            'timestamp': base_time + 300000,
            'message': json.dumps({
                'eventName': 'DeleteTrail',
                'username': 'attacker',
                'sourceIP': '10.0.0.1',
                'errorCode': None,
                'resources': []
            })
        })

        self.add_event({
            'source': 'cloudtrail',
            'timestamp': base_time + 310000,
            'message': json.dumps({
                'eventName': 'DeleteLogGroup',
                'username': 'attacker',
                'sourceIP': '10.0.0.1',
                'errorCode': None,
                'resources': []
            })
        })

        print(f"\n[SIMULATE] Total chains detected: {len(self.detected_chains)}")
        for chain in self.detected_chains:
            print(f"  → {chain['chain_name']} | Severity {chain['severity']}/10")


if __name__ == "__main__":
    import os
    detector = AttackChainDetector()
    events_file = os.path.expanduser('~/security-detector/logs/events.jsonl')

    # Analyze real events
    detector.analyze_file(events_file)

    # Run simulations
    detector.simulate_attacks()
