import json
import os
import anthropic
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

class AISecurityAnalyst:
    def __init__(self):
        self.client = anthropic.Anthropic(
            api_key=os.getenv('ANTHROPIC_API_KEY')
        )
        self.model = "claude-haiku-4-5-20251001"  # Fast and cheap
        self.reports = []

    def generate_incident_report(self, detection_data):
        """Send detected attack to Claude and get a professional incident report"""

        # Build context from detection
        if 'chain_name' in detection_data:
            # Attack chain detection
            context = f"""
ATTACK CHAIN DETECTED: {detection_data.get('chain_name', '').upper()}
Description: {detection_data.get('description', '')}
Severity: {detection_data.get('severity', 0)}/10
Steps completed: {', '.join(detection_data.get('completed_steps', []))}
Total events involved: {detection_data.get('event_count', 0)}
Detected at: {detection_data.get('detected_at', '')}
"""
        else:
            # Single anomaly detection
            event = detection_data.get('event', {})
            try:
                message = json.loads(event.get('message', '{}'))
            except:
                message = {}

            context = f"""
ANOMALY DETECTED
Event: {message.get('eventName', 'Unknown')}
User: {message.get('username', 'Unknown')}
Source IP: {message.get('sourceIP', 'Unknown')}
Error Code: {message.get('errorCode', 'None')}
Severity: {detection_data.get('severity', 0)}/10
Reasons flagged: {'; '.join(detection_data.get('reasons', []))}
Timestamp: {event.get('ingested_at', '')}
"""

        prompt = f"""You are a senior cloud security analyst at a Fortune 500 company. 
You have just received an automated alert from the security monitoring system.

Here is the detection data:
{context}

Write a professional security incident report that includes:

1. EXECUTIVE SUMMARY (2-3 sentences for non-technical management)
2. TECHNICAL ANALYSIS (what happened, how, attack pattern identified)
3. MITRE ATT&CK MAPPING (which techniques were used)
4. AFFECTED RESOURCES (what is at risk)
5. IMMEDIATE ACTIONS REQUIRED (prioritized response steps)
6. LONG-TERM RECOMMENDATIONS (how to prevent this in future)

Be specific, professional, and actionable. Use real security terminology.
Format clearly with headers."""

        print(f"[AI ANALYST] Generating incident report...")

        response = self.client.messages.create(
            model=self.model,
            max_tokens=1000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        report = {
            'detection': detection_data,
            'report': response.content[0].text,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'tokens_used': response.usage.input_tokens + response.usage.output_tokens
        }

        self.reports.append(report)
        return report

    def analyze_multiple(self, detections):
        """Generate reports for multiple detections"""
        reports = []
        for i, detection in enumerate(detections):
            print(f"[AI ANALYST] Processing detection {i+1}/{len(detections)}...")
            report = self.generate_incident_report(detection)
            reports.append(report)
        return reports

    def save_reports(self, reports, output_file):
        """Save all reports to file"""
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            for i, report in enumerate(reports):
                f.write(f"\n{'='*70}\n")
                f.write(f"INCIDENT REPORT #{i+1}\n")
                f.write(f"Generated: {report['generated_at']}\n")
                f.write(f"Tokens used: {report['tokens_used']}\n")
                f.write(f"{'='*70}\n\n")
                f.write(report['report'])
                f.write(f"\n\n")
        print(f"[AI ANALYST] Reports saved to {output_file}")


if __name__ == "__main__":
    from baseline import BehavioralBaselineEngine
    from attack_chain import AttackChainDetector

    print("[AI ANALYST] Starting full security analysis pipeline...\n")

    # Step 1: Run behavioral baseline
    baseline = BehavioralBaselineEngine()
    events_file = os.path.expanduser('~/security-detector/logs/events.jsonl')
    baseline_results = baseline.analyze_events(events_file)

    # Step 2: Run attack chain detector
    detector = AttackChainDetector()
    detector.analyze_file(events_file)

    # Step 3: Simulate attacks to generate detections
    print("\n[AI ANALYST] Running attack simulations to generate detections...")
    baseline.simulate_attack()
    detector.simulate_attacks()

    # Step 4: Collect all detections
    all_detections = []

    # Add high severity baseline anomalies
    high_severity = [r for r in baseline.anomalies if r['severity'] >= 6]
    all_detections.extend(high_severity[:2])  # Top 2

    # Add attack chain detections
    all_detections.extend(detector.detected_chains[:2])  # Top 2

    if not all_detections:
        print("[AI ANALYST] No high-severity detections. Using simulated data...")
        all_detections = [{
            'chain_name': 'brute_force_takeover',
            'description': 'Brute force login followed by account takeover',
            'severity': 9,
            'completed_steps': [
                'Multiple failed login attempts',
                'Successful login after failures',
                'Attempt to escalate privileges'
            ],
            'event_count': 17,
            'detected_at': datetime.now(timezone.utc).isoformat()
        }]

    # Step 5: Generate AI reports
    print(f"\n[AI ANALYST] Generating AI incident reports for {len(all_detections)} detections...")
    analyst = AISecurityAnalyst()
    reports = analyst.analyze_multiple(all_detections)

    # Step 6: Print and save reports
    output_file = os.path.expanduser('~/security-detector/logs/incident_reports.txt')
    analyst.save_reports(reports, output_file)

    print(f"\n{'='*70}")
    print("INCIDENT REPORTS PREVIEW")
    print(f"{'='*70}")
    for i, report in enumerate(reports):
        print(f"\n--- Report #{i+1} ---")
        print(report['report'][:500] + "...")
        print(f"\nFull report saved to: {output_file}")
