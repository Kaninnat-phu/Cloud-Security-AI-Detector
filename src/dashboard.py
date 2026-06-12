from flask import Flask, render_template_string, jsonify
import json
import os
from datetime import datetime, timezone
from baseline import BehavioralBaselineEngine
from attack_chain import AttackChainDetector
from ai_analyst import AISecurityAnalyst
from responder import AutomatedResponder

app = Flask(__name__)

pipeline_state = {
    'events': [], 'anomalies': [], 'attack_chains': [], 'incidents': [],
    'actions': [], 'last_updated': None,
    'stats': {'total_events': 0, 'anomalies_found': 0, 'chains_detected': 0,
              'actions_taken': 0, 'reports_generated': 0}
}

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cloud Security AI Detector</title>
<meta http-equiv="refresh" content="30">
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
* { margin:0; padding:0; box-sizing:border-box; }
:root {
  --bg:#0b0f17; --panel:#131926; --panel-2:#0f1420;
  --border:#1f2937; --text:#e5e9f0; --muted:#6b7688;
  --accent:#3b82f6; --green:#10b981; --amber:#f59e0b;
  --red:#ef4444; --orange:#f97316;
}
body {
  background:var(--bg); color:var(--text);
  font-family:'Inter',sans-serif; padding:28px 32px;
  max-width:1400px; margin:0 auto; line-height:1.5;
}
.topbar {
  display:flex; justify-content:space-between; align-items:center;
  padding-bottom:20px; margin-bottom:24px; border-bottom:1px solid var(--border);
}
.brand { display:flex; align-items:center; gap:12px; }
.brand .logo { font-size:22px; }
.brand h1 { font-size:17px; font-weight:600; letter-spacing:-0.01em; }
.brand p { font-size:12px; color:var(--muted); margin-top:2px; }
.status-pill {
  display:flex; align-items:center; gap:8px; font-size:12px;
  color:var(--green); font-weight:500;
}
.status-dot {
  width:8px; height:8px; border-radius:50%; background:var(--green);
  box-shadow:0 0 8px var(--green);
}
.updated { font-size:11px; color:var(--muted); margin-top:2px; }
.stats { display:grid; grid-template-columns:repeat(5,1fr); gap:14px; margin-bottom:24px; }
.stat {
  background:var(--panel); border:1px solid var(--border);
  border-radius:12px; padding:18px 20px;
}
.stat .num { font-size:30px; font-weight:700; font-family:'JetBrains Mono',monospace; letter-spacing:-0.02em; }
.stat .lbl { font-size:11px; color:var(--muted); margin-top:4px; font-weight:500; text-transform:uppercase; letter-spacing:0.04em; }
.cols { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }
.panel { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:20px; }
.panel-head {
  display:flex; align-items:center; gap:8px; margin-bottom:16px;
  font-size:13px; font-weight:600; letter-spacing:0.02em;
}
.panel-head .count {
  margin-left:auto; font-size:11px; color:var(--muted);
  background:var(--panel-2); padding:2px 8px; border-radius:6px;
  font-family:'JetBrains Mono',monospace;
}
.card {
  background:var(--panel-2); border-radius:10px; padding:14px;
  margin-bottom:10px; border-left:3px solid var(--border);
}
.card:last-child { margin-bottom:0; }
.card.crit { border-left-color:var(--red); }
.card.high { border-left-color:var(--orange); }
.card.med { border-left-color:var(--amber); }
.card.low { border-left-color:var(--green); }
.card-top { display:flex; align-items:center; gap:8px; margin-bottom:6px; }
.tag {
  font-size:10px; font-weight:700; padding:3px 8px; border-radius:5px;
  font-family:'JetBrains Mono',monospace; letter-spacing:0.03em;
}
.tag.crit { background:rgba(239,68,68,0.15); color:#fca5a5; }
.tag.high { background:rgba(249,115,22,0.15); color:#fdba74; }
.tag.med { background:rgba(245,158,11,0.15); color:#fcd34d; }
.tag.low { background:rgba(16,185,129,0.15); color:#6ee7b7; }
.card-title { font-size:13px; font-weight:600; }
.card-desc { font-size:12px; color:var(--muted); margin-top:2px; }
.step { font-size:12px; color:var(--green); margin-top:5px; display:flex; align-items:center; gap:6px; }
.action { display:flex; gap:10px; padding:12px 14px; background:var(--panel-2); border-radius:10px; margin-bottom:8px; }
.action .ico { color:var(--green); font-size:14px; }
.action-body { flex:1; }
.action-name { font-size:12px; font-weight:600; font-family:'JetBrains Mono',monospace; }
.action-detail { font-size:11px; color:var(--muted); margin-top:2px; }
.action-time { font-size:10px; color:var(--muted); margin-top:4px; font-family:'JetBrains Mono',monospace; }
.anomaly-row {
  display:flex; align-items:center; gap:10px; padding:10px 12px;
  background:var(--panel-2); border-radius:8px; margin-bottom:6px;
}
.sev-badge {
  font-size:11px; font-weight:700; font-family:'JetBrains Mono',monospace;
  padding:3px 7px; border-radius:5px; min-width:42px; text-align:center;
}
.anomaly-info { flex:1; min-width:0; }
.anomaly-name { font-size:12px; font-weight:500; }
.anomaly-reason { font-size:11px; color:var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.report {
  background:var(--panel-2); border-radius:10px; padding:16px;
  font-size:12px; line-height:1.7; font-family:'JetBrains Mono',monospace;
  color:#cbd5e1; max-height:280px; overflow-y:auto; white-space:pre-wrap;
}
.empty { text-align:center; color:var(--muted); font-size:12px; padding:28px 0; }
.empty .ok { color:var(--green); font-size:18px; display:block; margin-bottom:6px; }
.footer {
  display:flex; gap:20px; flex-wrap:wrap; padding:14px 18px;
  background:var(--panel); border:1px solid var(--border);
  border-radius:12px; font-size:11px; color:var(--muted);
}
.footer span { display:flex; align-items:center; gap:6px; }
::-webkit-scrollbar { width:6px; }
::-webkit-scrollbar-thumb { background:var(--border); border-radius:3px; }
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">
    <span class="logo">🛡️</span>
    <div>
      <h1>Cloud Security AI Detector</h1>
      <p>Autonomous threat detection &amp; response</p>
    </div>
  </div>
  <div style="text-align:right;">
    <div class="status-pill"><span class="status-dot"></span>System online</div>
    <div class="updated">Updated {{ last_updated }}</div>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="num">{{ stats.total_events }}</div><div class="lbl">Events analyzed</div></div>
  <div class="stat"><div class="num" style="color:{% if stats.anomalies_found>0 %}var(--amber){% else %}var(--green){% endif %}">{{ stats.anomalies_found }}</div><div class="lbl">Anomalies</div></div>
  <div class="stat"><div class="num" style="color:{% if stats.chains_detected>0 %}var(--red){% else %}var(--green){% endif %}">{{ stats.chains_detected }}</div><div class="lbl">Attack chains</div></div>
  <div class="stat"><div class="num" style="color:var(--accent)">{{ stats.reports_generated }}</div><div class="lbl">AI reports</div></div>
  <div class="stat"><div class="num" style="color:var(--green)">{{ stats.actions_taken }}</div><div class="lbl">Auto responses</div></div>
</div>

<div class="cols">
  <div class="panel">
    <div class="panel-head">⚠️ Attack chains <span class="count">{{ attack_chains|length }}</span></div>
    {% if attack_chains %}
      {% for chain in attack_chains %}
      <div class="card crit">
        <div class="card-top">
          <span class="tag crit">{{ chain.severity }}/10</span>
          <span class="card-title">{{ chain.chain_name.upper().replace('_',' ') }}</span>
        </div>
        <div class="card-desc">{{ chain.description }}</div>
        {% for step in chain.completed_steps %}
        <div class="step">✓ {{ step }}</div>
        {% endfor %}
      </div>
      {% endfor %}
    {% else %}
      <div class="empty"><span class="ok">✓</span>No attack chains detected</div>
    {% endif %}
  </div>

  <div class="panel">
    <div class="panel-head">⚡ Automated response <span class="count">{{ actions|length }}</span></div>
    {% if actions %}
      {% for action in actions %}
      <div class="action">
        <span class="ico">✓</span>
        <div class="action-body">
          <div class="action-name">{{ action.action }}</div>
          <div class="action-detail">{{ action.details }}</div>
          <div class="action-time">{{ action.timestamp }}</div>
        </div>
      </div>
      {% endfor %}
    {% else %}
      <div class="empty">No automated actions taken</div>
    {% endif %}
  </div>
</div>

<div class="cols">
  <div class="panel">
    <div class="panel-head">🔍 Anomaly log <span class="count">{{ anomalies|length }}</span></div>
    {% if anomalies %}
      {% for a in anomalies[:8] %}
      {% set sev = a.severity %}
      <div class="anomaly-row">
        <span class="sev-badge {% if sev>=8 %}tag crit{% elif sev>=6 %}tag high{% elif sev>=4 %}tag med{% else %}tag low{% endif %}">{{ sev }}/10</span>
        <div class="anomaly-info">
          <div class="anomaly-name">{{ a.event_name }}</div>
          <div class="anomaly-reason">{{ a.reasons|join(', ') if a.reasons else 'ML pattern anomaly' }}</div>
        </div>
      </div>
      {% endfor %}
    {% else %}
      <div class="empty"><span class="ok">✓</span>All events within normal baseline</div>
    {% endif %}
  </div>

  <div class="panel">
    <div class="panel-head">🤖 AI incident report <span class="count">{{ incidents|length }}</span></div>
    {% if incidents %}
      {% for incident in incidents[:1] %}
      <div class="report">{{ incident.report[:700] }}...</div>
      {% endfor %}
    {% else %}
      <div class="empty">No incidents requiring analysis</div>
    {% endif %}
  </div>
</div>

<div class="footer">
  <span>🛡️ v1.0</span>
  <span>Sources: CloudTrail · VPC Flow Logs · CloudWatch</span>
  <span>ML: Isolation Forest + Attack Chain Detection</span>
  <span>AI: Claude</span>
</div>
</body>
</html>
'''

def run_pipeline():
    global pipeline_state
    events_file = os.path.expanduser('~/security-detector/logs/events.jsonl')
    baseline = BehavioralBaselineEngine()
    baseline_results = baseline.analyze_events(events_file)
    baseline.simulate_attack()
    detector = AttackChainDetector()
    detector.analyze_file(events_file)
    detector.simulate_attacks()
    anomalies = [r for r in baseline.anomalies if r['severity'] >= 4]
    chains = detector.detected_chains[:3]
    analyst = AISecurityAnalyst()
    high_severity = [r for r in baseline.anomalies if r['severity'] >= 6]
    all_detections = high_severity[:1] + chains[:1]
    reports = []
    if all_detections:
        reports = analyst.analyze_multiple(all_detections[:1])
    responder = AutomatedResponder()
    for detection in chains[:1]:
        responder.respond_to_detection(detection)
    pipeline_state['anomalies'] = anomalies
    pipeline_state['attack_chains'] = chains
    pipeline_state['incidents'] = reports
    pipeline_state['actions'] = responder.response_log
    pipeline_state['last_updated'] = datetime.now(timezone.utc).strftime('%H:%M:%S UTC')
    pipeline_state['stats'] = {
        'total_events': len(baseline_results),
        'anomalies_found': len(anomalies),
        'chains_detected': len(chains),
        'reports_generated': len(reports),
        'actions_taken': len(responder.response_log)
    }

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE, **pipeline_state)

@app.route('/api/status')
def api_status():
    return jsonify(pipeline_state['stats'])

if __name__ == '__main__':
    print("[DASHBOARD] Running initial security pipeline...")
    run_pipeline()
    print("[DASHBOARD] Pipeline complete. Starting web server...")
    print("[DASHBOARD] Open your browser at: http://localhost:5001")
    app.run(host='0.0.0.0', port=5001, debug=False)
