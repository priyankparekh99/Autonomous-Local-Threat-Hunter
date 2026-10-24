import os
import json
import duckdb
from typing import Annotated, TypedDict, List
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

# 1. Define Agent State Schema
class ThreatHunterState(TypedDict):
    messages: Annotated[list, add_messages]
    log_file_path: str
    detected_anomalies: List[dict]
    threat_summary: str

# 2. Initialize Local LLM via Ollama
local_llm = ChatOllama(
    model="qwen2.5:7b",  # Match the model you pulled in Step 1
    temperature=0.0,
    format="json"
)

# 3. Setup In-Memory DuckDB Engine
def setup_log_database(log_file: str):
    con = duckdb.connect(database=':memory:')
    con.execute(f"CREATE TABLE access_logs AS SELECT * FROM read_json_auto('{log_file}');")
    return con

# 4. Define Nodes
def log_ingestion_node(state: ThreatHunterState) -> ThreatHunterState:
    log_path = state["log_file_path"]
    print(f"\n[1/3] 📥 Indexing raw logs from '{log_path}' into DuckDB...")
    
    con = setup_log_database(log_path)
    total_logs = con.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]
    unique_ips = con.execute("SELECT COUNT(DISTINCT ip) FROM access_logs").fetchone()[0]
    
    info_msg = f"Indexed {total_logs} log entries across {unique_ips} unique IPs."
    print(f"      {info_msg}")
    return {"messages": [HumanMessage(content=info_msg)]}

def threat_query_analyzer_node(state: ThreatHunterState) -> ThreatHunterState:
    print("[2/3] 🔍 Executing SQL threat queries & running local AI evaluation...")
    con = setup_log_database(state["log_file_path"])
    
    # SQL Query 1: Detect Brute Force Probes (Failed logins > 3)
    brute_force_query = """
        SELECT ip, status_code, COUNT(*) as attempts 
        FROM access_logs 
        WHERE status_code = 401 OR status_code = 403
        GROUP BY ip, status_code
        HAVING COUNT(*) > 3;
    """
    failed_logins = con.execute(brute_force_query).df().to_dict(orient="records")
    
    # SQL Query 2: Detect Injection / Path Traversal attempts
    sqli_query = """
        SELECT ip, request_path, status_code
        FROM access_logs
        WHERE lower(request_path) LIKE '%select%' 
           OR lower(request_path) LIKE '%union%' 
           OR lower(request_path) LIKE '%../%';
    """
    sqli_attempts = con.execute(sqli_query).df().to_dict(orient="records")
    
    prompt = f"""You are a Principal Cyber Threat Intelligence Analyst.
Analyze these query results from raw server logs:

Failed Login Bursts:
{json.dumps(failed_logins)}

Malicious Payload Requests:
{json.dumps(sqli_attempts)}

Determine threat severity and attack vectors.
Return a valid JSON object matching this strict schema:
{{
  "threats": [
    {{
      "attacker_ip": "IP address",
      "attack_type": "Brute Force / SQL Injection / Directory Traversal",
      "severity": "CRITICAL / HIGH / MEDIUM",
      "evidence": "Brief description of finding",
      "recommended_action": "e.g. Block IP at firewall, rotate compromise keys"
    }}
  ]
}}"""

    response = local_llm.invoke([
        SystemMessage(content="You analyze structured security telemetry. Output JSON strictly."),
        HumanMessage(content=prompt)
    ])
    
    try:
        parsed = json.loads(response.content)
        anomalies = parsed.get("threats", [])
    except Exception:
        anomalies = [{"attacker_ip": "Unknown", "attack_type": "Parse Error", "severity": "MEDIUM", "evidence": response.content, "recommended_action": "Review raw logs"}]

    return {"detected_anomalies": anomalies, "messages": [response]}

def threat_report_node(state: ThreatHunterState) -> ThreatHunterState:
    print("[3/3] 📝 Compiling Markdown Threat Report...")
    anomalies = state["detected_anomalies"]
    
    report = "# 🚨 Air-Gapped Local SOC Threat Report\n\n"
    report += f"**Log File Source:** `{state['log_file_path']}`\n"
    report += f"**Inference Engine:** Qwen 2.5 7B (Local Ollama) + DuckDB\n\n"
    report += "---\n\n## Discovered Threat Indicators (IOCs)\n\n"
    
    if not anomalies:
        report += "✅ No suspicious attack indicators found in the provided log sample.\n"
    else:
        for idx, t in enumerate(anomalies, 1):
            report += f"### {idx}. [{t.get('severity')}] {t.get('attack_type')} from IP `{t.get('attacker_ip')}`\n"
            report += f"- **Evidence:** {t.get('evidence')}\n"
            report += f"- **Recommended Mitigation:** `{t.get('recommended_action')}`\n\n"
            
    return {"threat_summary": report, "messages": [HumanMessage(content="Report generated successfully.")]}

# 5. Build LangGraph Graph
workflow = StateGraph(ThreatHunterState)
workflow.add_node("ingest_logs", log_ingestion_node)
workflow.add_node("analyze_threats", threat_query_analyzer_node)
workflow.add_node("generate_report", threat_report_node)

workflow.add_edge(START, "ingest_logs")
workflow.add_edge("ingest_logs", "analyze_threats")
workflow.add_edge("analyze_threats", "generate_report")
workflow.add_edge("generate_report", END)

app = workflow.compile()

# 6. Entrypoint with Mock Data Generation
if __name__ == "__main__":
    sample_log = "access_logs.json"
    
    # Generate mock log telemetry containing attacks
    mock_logs = [
        {"timestamp": "2026-10-24T10:00:01Z", "ip": "192.168.1.50", "request_path": "/home", "status_code": 200},
        {"timestamp": "2026-10-24T10:01:05Z", "ip": "45.33.32.156", "request_path": "/login", "status_code": 401},
        {"timestamp": "2026-10-24T10:01:06Z", "ip": "45.33.32.156", "request_path": "/login", "status_code": 401},
        {"timestamp": "2026-10-24T10:01:07Z", "ip": "45.33.32.156", "request_path": "/login", "status_code": 401},
        {"timestamp": "2026-10-24T10:01:08Z", "ip": "45.33.32.156", "request_path": "/login", "status_code": 401},
        {"timestamp": "2026-10-24T10:01:09Z", "ip": "45.33.32.156", "request_path": "/login", "status_code": 401},
        {"timestamp": "2026-10-24T10:05:12Z", "ip": "103.21.244.11", "request_path": "/api/users?id=1 UNION SELECT username, password FROM users", "status_code": 500},
        {"timestamp": "2026-10-24T10:06:00Z", "ip": "103.21.244.11", "request_path": "/../../etc/passwd", "status_code": 403}
    ]
    
    with open(sample_log, "w") as f:
        json.dump(mock_logs, f, indent=2)

    print("🚀 Initializing Local Threat Hunter...")
    result = app.invoke({
        "messages": [],
        "log_file_path": sample_log,
        "detected_anomalies": [],
        "threat_summary": ""
    })

    print("\n" + "="*60)
    print(result["threat_summary"])
    print("="*60)
    
    if os.path.exists(sample_log):
        os.remove(sample_log)
