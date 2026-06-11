import json
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import os

TIMEZONE_OFFSET = 7  # Thailand UTC+7

class BehavioralBaselineEngine:
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.is_trained = False
        self.baseline_data = []
        self.user_profiles = defaultdict(lambda: {
            'api_calls': defaultdict(int),
            'ip_addresses': set(),
            'hours_active': defaultdict(int),
            'total_events': 0,
            'error_count': 0
        })
        self.anomalies = []

    def get_local_hour(self, timestamp_ms):
        """Convert UTC timestamp to local Thai time hour"""
        dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
        local_dt = dt + timedelta(hours=TIMEZONE_OFFSET)
        return local_dt.hour, local_dt

    def extract_features(self, event):
        """Convert raw event into numbers the ML model can understand"""
        try:
            message = json.loads(event.get('message', '{}'))
        except:
            message = {}

        timestamp = event.get('timestamp', 0)
        hour, dt = self.get_local_hour(timestamp)

        # Feature 1: Hour of day in local time (0-23)
        # Feature 2: Is weekend?
        is_weekend = 1 if dt.weekday() >= 5 else 0
        # Feature 3: Is outside business hours? (before 8am or after 10pm local)
        is_off_hours = 1 if hour < 8 or hour > 22 else 0
        # Feature 4: Is high-risk API?
        high_risk_apis = [
            'CreateUser', 'DeleteUser', 'AttachUserPolicy',
            'CreateAccessKey', 'PutUserPolicy', 'AddUserToGroup',
            'CreateRole', 'AttachRolePolicy', 'PassRole',
            'DeleteTrail', 'StopLogging', 'DeleteLogGroup',
            'AuthorizeSecurityGroupIngress', 'CreateVpc'
        ]
        event_name = message.get('eventName', '')
        is_high_risk = 1 if event_name in high_risk_apis else 0
        # Feature 5: Has error?
        has_error = 1 if message.get('errorCode') else 0
        # Feature 6: Unknown IP?
        source_ip = message.get('sourceIP', 'unknown')
        is_unknown_ip = 1 if source_ip == 'unknown' else 0
        # Feature 7: Source type
        source_map = {'cloudtrail': 0, 'vpc_flows': 1, 'app_logs': 2}
        source_num = source_map.get(event.get('source', ''), 3)

        return [hour, is_weekend, is_off_hours, is_high_risk,
                has_error, is_unknown_ip, source_num]

    def update_user_profile(self, event):
        """Track behavior patterns per user"""
        try:
            message = json.loads(event.get('message', '{}'))
        except:
            return

        username = message.get('username', 'unknown')
        profile = self.user_profiles[username]
        profile['total_events'] += 1

        event_name = message.get('eventName', '')
        if event_name:
            profile['api_calls'][event_name] += 1

        source_ip = message.get('sourceIP', '')
        if source_ip and source_ip != 'unknown':
            profile['ip_addresses'].add(source_ip)

        timestamp = event.get('timestamp', 0)
        hour, _ = self.get_local_hour(timestamp)
        profile['hours_active'][hour] += 1

        if message.get('errorCode'):
            profile['error_count'] += 1

    def train(self, events):
        """Train the model on historical events"""
        if len(events) < 10:
            print(f"[BASELINE] Need at least 10 events to train. Have {len(events)}.")
            return False

        print(f"[BASELINE] Training on {len(events)} events...")
        features = []
        for event in events:
            self.update_user_profile(event)
            features.append(self.extract_features(event))

        X = np.array(features)
        self.model.fit(X)
        self.is_trained = True
        self.baseline_data = events
        print(f"[BASELINE] Training complete. Baseline established.")
        print(f"[BASELINE] Tracking {len(self.user_profiles)} users.")
        return True

    def score_event(self, event):
        """Score a single event"""
        features = self.extract_features(event)
        self.update_user_profile(event)

        try:
            message = json.loads(event.get('message', '{}'))
        except:
            message = {}

        severity = 0
        reasons = []

        timestamp = event.get('timestamp', 0)
        hour, dt = self.get_local_hour(timestamp)

        # Rule 1: Off hours (local Thai time)
        if hour < 6 or hour > 23:
            severity += 3
            reasons.append(f"Activity at unusual hour: {hour:02d}:00 Thai time")

        # Rule 2: High-risk API
        high_risk_apis = [
            'CreateUser', 'DeleteUser', 'AttachUserPolicy',
            'CreateAccessKey', 'PutUserPolicy', 'AddUserToGroup',
            'CreateRole', 'AttachRolePolicy', 'DeleteTrail',
            'StopLogging', 'DeleteLogGroup'
        ]
        event_name = message.get('eventName', '')
        if event_name in high_risk_apis:
            severity += 4
            reasons.append(f"High-risk API call detected: {event_name}")

        # Rule 3: Error spike per user
        username = message.get('username', 'unknown')
        profile = self.user_profiles.get(username, {})
        error_count = profile.get('error_count', 0) if isinstance(profile, dict) else 0
        if error_count > 5:
            severity += 2
            reasons.append(f"High error count for {username}: {error_count} errors")

        # Rule 4: ML anomaly detection
        if self.is_trained:
            X = np.array([features])
            score = self.model.score_samples(X)[0]
            ml_severity = max(0, int((-score - 0.1) * 10))
            severity += ml_severity
            if ml_severity > 3:
                reasons.append(
                    f"ML model flagged unusual behavior pattern (score: {score:.3f})"
                )

        result = {
            'event': event,
            'features': features,
            'is_anomaly': severity >= 4,
            'anomaly_score': severity,
            'severity': min(severity, 10),
            'reasons': reasons,
            'event_name': event_name,
            'username': username,
            'hour_local': hour
        }

        if result['is_anomaly']:
            self.anomalies.append(result)
            reason_str = '; '.join(reasons) if reasons else 'ML pattern anomaly'
            print(f"[ANOMALY] Severity {severity}/10 | {event_name} | {reason_str}")

        return result

    def analyze_events(self, events_file):
        """Load, train, and score all events"""
        events = []
        try:
            with open(events_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
        except FileNotFoundError:
            print(f"[BASELINE] No events file found at {events_file}")
            return []

        print(f"[BASELINE] Loaded {len(events)} events from file")
        split = max(10, int(len(events) * 0.7))
        self.train(events[:split])

        results = []
        for event in events:
            result = self.score_event(event)
            results.append(result)

        anomaly_count = sum(1 for r in results if r['is_anomaly'])
        print(f"\n[BASELINE] Analysis complete:")
        print(f"  Total events:    {len(results)}")
        print(f"  Anomalies found: {anomaly_count}")
        print(f"  Clean events:    {len(results) - anomaly_count}")
        print(f"  Anomaly rate:    {anomaly_count/len(results)*100:.1f}%")
        return results

    def simulate_attack(self):
        """Inject a fake attack to test detection"""
        print("\n[SIMULATE] Injecting fake brute force attack...")
        fake_events = []
        base_time = 1781090000000

        # 15 failed logins at 3am
        for i in range(15):
            fake_events.append({
                'source': 'cloudtrail',
                'timestamp': base_time + (i * 10000),
                'message': json.dumps({
                    'eventName': 'ConsoleLogin',
                    'username': 'security-detector-user',
                    'sourceIP': '45.33.32.156',
                    'errorCode': 'Failed authentication',
                    'resources': []
                }),
                'ingested_at': '2026-06-10T03:00:00Z'
            })

        # Then CreateUser after login
        fake_events.append({
            'source': 'cloudtrail',
            'timestamp': base_time + 200000,
            'message': json.dumps({
                'eventName': 'CreateUser',
                'username': 'security-detector-user',
                'sourceIP': '45.33.32.156',
                'errorCode': None,
                'resources': []
            }),
            'ingested_at': '2026-06-10T03:05:00Z'
        })

        results = []
        for event in fake_events:
            result = self.score_event(event)
            results.append(result)

        high_severity = [r for r in results if r['severity'] >= 6]
        print(f"[SIMULATE] {len(high_severity)} high-severity events detected from attack simulation")
        return results

if __name__ == "__main__":
    engine = BehavioralBaselineEngine()
    events_file = os.path.expanduser('~/security-detector/logs/events.jsonl')

    # Analyze real events
    results = engine.analyze_events(events_file)

    # Show top anomalies
    anomalies = [r for r in results if r['is_anomaly']]
    anomalies.sort(key=lambda x: x['severity'], reverse=True)
    if anomalies:
        print("\n[BASELINE] Top anomalies found:")
        for a in anomalies[:5]:
            print(f"  Severity {a['severity']}/10 | {a['event_name']} | {'; '.join(a['reasons']) if a['reasons'] else 'ML pattern'}")

    # Run attack simulation
    engine.simulate_attack()
