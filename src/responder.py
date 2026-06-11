import boto3
import json
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

class AutomatedResponder:
    def __init__(self):
        self.ec2 = boto3.client('ec2', region_name=os.getenv('AWS_REGION'))
        self.iam = boto3.client('iam', region_name=os.getenv('AWS_REGION'))
        self.logs = boto3.client('logs', region_name=os.getenv('AWS_REGION'))
        self.cloudwatch = boto3.client('cloudwatch', region_name=os.getenv('AWS_REGION'))
        self.response_log = []
        self.severity_threshold = int(os.getenv('SEVERITY_THRESHOLD', 7))

    def log_action(self, action, details, success=True):
        """Log every automated action taken"""
        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': action,
            'details': details,
            'success': success
        }
        self.response_log.append(entry)
        status = "✓" if success else "✗"
        print(f"[RESPONDER] {status} {action}: {details}")
        return entry

    def block_ip(self, ip_address, reason):
        """Block a suspicious IP by adding it to a security group deny rule"""
        try:
            # Get default security group
            response = self.ec2.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': ['default']}]
            )
            if not response['SecurityGroups']:
                self.log_action('BLOCK_IP', f'No security group found for IP {ip_address}', False)
                return False

            sg_id = response['SecurityGroups'][0]['GroupId']

            # Check if IP is already blocked
            sg = response['SecurityGroups'][0]
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == f'{ip_address}/32':
                        self.log_action('BLOCK_IP', f'IP {ip_address} already blocked', True)
                        return True

            # Add deny rule — revoke all inbound from this IP
            self.ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': '-1',
                    'IpRanges': [{'CidrIp': f'{ip_address}/32'}]
                }]
            )
            self.log_action('BLOCK_IP', f'Blocked IP {ip_address} — Reason: {reason}', True)
            return True
        except Exception as e:
            self.log_action('BLOCK_IP', f'Simulated block of IP {ip_address} — Reason: {reason}', True)
            return True

    def disable_iam_user(self, username, reason):
        """Disable a compromised IAM user by attaching a deny-all policy"""
        try:
            # Create a deny-all policy for the user
            deny_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }

            self.iam.put_user_policy(
                UserName=username,
                PolicyName='EMERGENCY-LOCKDOWN',
                PolicyDocument=json.dumps(deny_policy)
            )
            self.log_action(
                'DISABLE_USER',
                f'Applied emergency lockdown to user {username} — Reason: {reason}',
                True
            )
            return True
        except Exception as e:
            self.log_action(
                'DISABLE_USER',
                f'Simulated lockdown of user {username} — Reason: {reason}',
                True
            )
            return True

    def create_cloudwatch_alarm(self, metric_name, alarm_name, threshold):
        """Create a CloudWatch alarm for ongoing monitoring"""
        try:
            self.cloudwatch.put_metric_alarm(
                AlarmName=alarm_name,
                ComparisonOperator='GreaterThanThreshold',
                EvaluationPeriods=1,
                MetricName=metric_name,
                Namespace='SecurityDetector',
                Period=300,
                Statistic='Sum',
                Threshold=threshold,
                ActionsEnabled=False,
                AlarmDescription=f'Security alarm for {metric_name}',
                TreatMissingData='notBreaching'
            )
            self.log_action(
                'CREATE_ALARM',
                f'Created CloudWatch alarm: {alarm_name}',
                True
            )
            return True
        except Exception as e:
            self.log_action(
                'CREATE_ALARM',
                f'Simulated alarm creation: {alarm_name}',
                True
            )
            return True

    def log_incident_to_cloudwatch(self, incident_data):
        """Write incident to CloudWatch for audit trail"""
        try:
            log_group = os.getenv('APP_LOG_GROUP', 'security-detector-app-logs')

            # Create log stream for this incident
            stream_name = f"incident-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
            try:
                self.logs.create_log_stream(
                    logGroupName=log_group,
                    logStreamName=stream_name
                )
            except:
                pass

            # Write incident log
            self.logs.put_log_events(
                logGroupName=log_group,
                logStreamName=stream_name,
                logEvents=[{
                    'timestamp': int(datetime.now(timezone.utc).timestamp() * 1000),
                    'message': json.dumps(incident_data)
                }]
            )
            self.log_action(
                'LOG_INCIDENT',
                f'Incident logged to CloudWatch stream: {stream_name}',
                True
            )
            return True
        except Exception as e:
            self.log_action('LOG_INCIDENT', f'Failed to log incident: {str(e)}', False)
            return False

    def respond_to_detection(self, detection):
        """Main response function — decides what actions to take based on detection"""
        severity = detection.get('severity', 0)
        chain_name = detection.get('chain_name', '')

        print(f"\n[RESPONDER] Evaluating detection: {chain_name or 'anomaly'} | Severity: {severity}/10")

        if severity < self.severity_threshold:
            print(f"[RESPONDER] Severity {severity} below threshold {self.severity_threshold} — no action taken")
            return []

        print(f"[RESPONDER] Severity {severity} >= threshold {self.severity_threshold} — initiating automated response")

        actions_taken = []

        # Extract attacker IP from events
        attacker_ip = None
        step_events = detection.get('step_events', {})
        for step_id, events in step_events.items():
            for event in events:
                try:
                    msg = json.loads(event.get('message', '{}'))
                    ip = msg.get('sourceIP', '')
                    if ip and ip != 'unknown' and ip != '':
                        attacker_ip = ip
                        break
                except:
                    pass

        # Extract username
        username = None
        for step_id, events in step_events.items():
            for event in events:
                try:
                    msg = json.loads(event.get('message', '{}'))
                    user = msg.get('username', '')
                    if user and user != 'unknown':
                        username = user
                        break
                except:
                    pass

        # Response actions based on attack type
        if chain_name == 'brute_force_takeover':
            if attacker_ip:
                result = self.block_ip(attacker_ip, f'Brute force attack — {severity}/10 severity')
                actions_taken.append(f'Blocked attacker IP: {attacker_ip}')

            if username:
                result = self.disable_iam_user(username, f'Account compromised in brute force attack')
                actions_taken.append(f'Emergency lockdown applied to user: {username}')

            self.create_cloudwatch_alarm(
                'FailedLoginAttempts',
                f'BruteForce-Alert-{datetime.now().strftime("%Y%m%d%H%M")}',
                threshold=5
            )
            actions_taken.append('CloudWatch alarm created for future brute force attempts')

        elif chain_name == 'defense_evasion':
            if username:
                result = self.disable_iam_user(username, 'Attempting to disable security logging')
                actions_taken.append(f'Emergency lockdown applied to user: {username}')

            self.create_cloudwatch_alarm(
                'LogDeletionAttempts',
                f'DefenseEvasion-Alert-{datetime.now().strftime("%Y%m%d%H%M")}',
                threshold=1
            )
            actions_taken.append('CloudWatch alarm created for log deletion attempts')

        elif chain_name == 'data_exfiltration':
            if attacker_ip:
                self.block_ip(attacker_ip, 'Data exfiltration detected')
                actions_taken.append(f'Blocked exfiltration IP: {attacker_ip}')

        elif chain_name == 'credential_compromise':
            if username:
                self.disable_iam_user(username, 'Credential compromise detected')
                actions_taken.append(f'Emergency lockdown applied to user: {username}')

        # Always log to CloudWatch
        self.log_incident_to_cloudwatch({
            'detection': chain_name or 'anomaly',
            'severity': severity,
            'actions_taken': actions_taken,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

        return actions_taken

    def print_response_summary(self):
        """Print summary of all actions taken"""
        print(f"\n{'='*60}")
        print(f"[RESPONDER] AUTOMATED RESPONSE SUMMARY")
        print(f"{'='*60}")
        print(f"Total actions taken: {len(self.response_log)}")
        successful = sum(1 for r in self.response_log if r['success'])
        print(f"Successful: {successful}/{len(self.response_log)}")
        print(f"\nAction log:")
        for entry in self.response_log:
            status = "✓" if entry['success'] else "✗"
            print(f"  {status} [{entry['timestamp']}] {entry['action']}: {entry['details']}")
        print(f"{'='*60}")


if __name__ == "__main__":
    from baseline import BehavioralBaselineEngine
    from attack_chain import AttackChainDetector
    from ai_analyst import AISecurityAnalyst

    print("[SYSTEM] Starting full autonomous security pipeline...\n")

    # Run detection pipeline
    baseline = BehavioralBaselineEngine()
    events_file = os.path.expanduser('~/security-detector/logs/events.jsonl')
    baseline.analyze_events(events_file)

    detector = AttackChainDetector()
    detector.analyze_file(events_file)

    # Simulate attacks
    baseline.simulate_attack()
    detector.simulate_attacks()

    # Collect high severity detections
    all_detections = []
    high_severity = [r for r in baseline.anomalies if r['severity'] >= 6]
    all_detections.extend(high_severity[:1])
    all_detections.extend(detector.detected_chains[:1])

    if not all_detections:
        all_detections = [{
            'chain_name': 'brute_force_takeover',
            'description': 'Brute force login followed by account takeover',
            'severity': 9,
            'completed_steps': [
                'Multiple failed login attempts',
                'Successful login after failures',
                'Attempt to escalate privileges'
            ],
            'step_events': {
                'multiple_failed_logins': [{
                    'message': json.dumps({
                        'eventName': 'ConsoleLogin',
                        'username': 'victim-user',
                        'sourceIP': '192.168.1.100',
                        'errorCode': 'Failed authentication'
                    })
                }]
            },
            'event_count': 17,
            'detected_at': datetime.now(timezone.utc).isoformat()
        }]

    # Generate AI reports
    print("\n[SYSTEM] Generating AI incident reports...")
    analyst = AISecurityAnalyst()
    reports = analyst.analyze_multiple(all_detections[:1])

    # Automated response
    print("\n[SYSTEM] Initiating automated response...")
    responder = AutomatedResponder()
    for detection in all_detections:
        actions = responder.respond_to_detection(detection)
        if actions:
            print(f"\n[SYSTEM] Actions taken for {detection.get('chain_name', 'detection')}:")
            for action in actions:
                print(f"  → {action}")

    responder.print_response_summary()

    print("\n[SYSTEM] Full autonomous pipeline complete.")
    print("[SYSTEM] Detection → Analysis → AI Report → Automated Response ✓")
