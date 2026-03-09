"""
Zero Trust AI Agent - Streamlit Dashboard
==========================================
Interactive web UI for the Zero Trust AI Agent Framework.
Displays Claude's reasoning, security checks, risk scoring,
and audit trail in real time.
"""

import streamlit as st
import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
from anthropic import Anthropic
from dotenv import load_dotenv

# Load API key
load_dotenv()
client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Base directory and paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "demo.db")
AUDIT_LOG_PATH = os.path.join(BASE_DIR, "audit_log.txt")
POLICY_PATH = os.path.join(BASE_DIR, "policies.json")

# Page config
st.set_page_config(
    page_title="Zero Trust AI Agent",
    page_icon="🛡️",
    layout="wide",
)

# ============================================================
# SESSION STATE
# ============================================================
if "request_history" not in st.session_state:
    st.session_state.request_history = defaultdict(list)
if "session_risk_history" not in st.session_state:
    st.session_state.session_risk_history = []


# ============================================================
# SECURITY LAYER 1: INPUT VALIDATION (Blocklist + Allowlist)
# ============================================================

DANGEROUS_PATTERNS = [
    (r"\.\./", "Path traversal attempt"),
    (r"~/", "Home directory access"),
    (r"/etc/", "System file access"),
    (r"/root/", "Root directory access"),
    (r"passwd", "Password file access"),
    (r";", "Command injection (semicolon)"),
    (r"\|", "Pipe command injection"),
    (r"&", "Command chaining"),
    (r"`", "Command substitution (backtick)"),
    (r"\$\(", "Command substitution (dollar-paren)"),
    (r"\$\{", "Variable expansion"),
    (r"%2e%2e", "URL-encoded path traversal"),
    (r"\\x2e\\x2e", "Hex-encoded path traversal"),
    (r"\.\\/", "Backslash path traversal"),
]

ALLOWED_FILE_EXTENSIONS = {".txt", ".csv", ".json", ".log", ".md", ".py"}
ALLOWED_SHELL_COMMANDS = {"echo", "date", "whoami", "ls", "cat", "wc", "head", "tail"}
ALLOWED_DB_TABLES = {"employees", "projects", "security_events"}
ALLOWED_API_DOMAINS = {"api.github.com", "httpbin.org", "jsonplaceholder.typicode.com"}

DANGEROUS_SQL_PATTERNS = [
    (r"\bDROP\b", "DROP statement detected"),
    (r"\bDELETE\b", "DELETE statement detected"),
    (r"\bINSERT\b", "INSERT statement detected"),
    (r"\bUPDATE\b", "UPDATE statement detected"),
    (r"\bALTER\b", "ALTER statement detected"),
    (r"\bTRUNCATE\b", "TRUNCATE statement detected"),
    (r"\bEXEC\b", "EXEC statement detected"),
    (r"--", "SQL comment injection"),
    (r"\bUNION\b.*\bSELECT\b", "UNION SELECT injection"),
]


def validate_file_input(filename):
    filename_lower = filename.lower()
    for pattern, reason in DANGEROUS_PATTERNS:
        if re.search(pattern, filename_lower):
            return False, f"BLOCKED: {reason} detected in '{filename}'"
    _, ext = os.path.splitext(filename)
    if ext and ext.lower() not in ALLOWED_FILE_EXTENSIONS:
        return False, f"BLOCKED: File extension '{ext}' not in allowlist"
    resolved = os.path.realpath(os.path.join(BASE_DIR, filename))
    if not resolved.startswith(BASE_DIR):
        return False, "BLOCKED: Path resolves outside sandbox directory"
    return True, "Input validated (blocklist + allowlist + sandbox)"


def validate_sql_input(query):
    query_upper = query.upper().strip()
    if not query_upper.startswith("SELECT"):
        return False, "BLOCKED: Only SELECT queries are allowed"
    for pattern, reason in DANGEROUS_SQL_PATTERNS:
        if re.search(pattern, query_upper):
            return False, f"BLOCKED: {reason}"
    table_pattern = r"(?:FROM|JOIN)\s+(\w+)"
    referenced_tables = re.findall(table_pattern, query_upper)
    for table in referenced_tables:
        if table.lower() not in ALLOWED_DB_TABLES:
            return False, f"BLOCKED: Table '{table.lower()}' not in allowlist"
    return True, "SQL validated (SELECT-only, table allowlist)"


def validate_shell_input(command):
    parts = command.strip().split()
    if not parts:
        return False, "BLOCKED: Empty command"
    base_command = parts[0].lower()
    if base_command not in ALLOWED_SHELL_COMMANDS:
        return False, f"BLOCKED: Command '{base_command}' not in allowlist"
    full_command = command.lower()
    for pattern, reason in [(r";", "Semicolon chaining"), (r"\|", "Pipe injection"),
                             (r"&&", "AND chaining"), (r"`", "Backtick substitution"),
                             (r"\$\(", "Dollar-paren substitution"), (r">", "Output redirection")]:
        if re.search(pattern, full_command):
            return False, f"BLOCKED: {reason} in arguments"
    return True, "Shell command validated (allowlist + injection check)"


def validate_api_input(url):
    domain_match = re.match(r"https?://([^/]+)", url)
    if not domain_match:
        return False, "BLOCKED: Invalid URL format"
    domain = domain_match.group(1).lower().split(":")[0]
    if domain not in ALLOWED_API_DOMAINS:
        return False, f"BLOCKED: Domain '{domain}' not in allowlist"
    return True, f"API URL validated ('{domain}' allowlisted)"


# ============================================================
# SECURITY LAYER 2: RATE LIMITING
# ============================================================

def check_rate_limit(function_name, max_requests=5, window_seconds=60):
    now = datetime.now()
    cutoff = now - timedelta(seconds=window_seconds)
    st.session_state.request_history[function_name] = [
        ts for ts in st.session_state.request_history[function_name] if ts > cutoff
    ]
    current_count = len(st.session_state.request_history[function_name])
    if current_count >= max_requests:
        return False, f"Rate limit exceeded: {current_count}/{max_requests}", current_count
    st.session_state.request_history[function_name].append(now)
    return True, f"Rate limit OK: {current_count + 1}/{max_requests}", current_count + 1


# ============================================================
# SECURITY LAYER 3: POLICY ENGINE
# ============================================================

def load_policies():
    with open(POLICY_PATH, "r") as f:
        return json.load(f)


def check_permission(function_name):
    policies = load_policies()
    return policies.get(function_name, {}).get("allowed", False)


# ============================================================
# SECURITY LAYER 4: CONTEXTUAL RISK SCORING
# ============================================================

def calculate_risk_score(function_name, arguments):
    score = 0
    reasons = []

    risk_levels = {
        "delete_file": 40, "execute_shell": 35, "write_file": 20,
        "query_database": 15, "call_api": 15, "read_file": 10,
    }
    func_risk = risk_levels.get(function_name, 20)
    score += func_risk
    reasons.append(f"Operation risk ({function_name}): +{func_risk}")

    sensitive_keywords = [
        "credential", "password", "secret", "key", "token",
        "api", "private", "confidential", "admin", "root",
    ]
    all_args_str = json.dumps(arguments).lower()
    matched_keywords = [kw for kw in sensitive_keywords if kw in all_args_str]
    if matched_keywords:
        sensitivity_score = 60
        if len(matched_keywords) >= 2:
            sensitivity_score += 10
        if function_name in ("write_file", "delete_file"):
            sensitivity_score += 10
        score += sensitivity_score
        reasons.append(f"Sensitive target ({', '.join(matched_keywords)}): +{sensitivity_score}")

    current_hour = datetime.now().hour
    if current_hour < 6 or current_hour > 22:
        score += 30
        reasons.append(f"After-hours access ({current_hour}:00): +30")

    # Session escalation
    escalation_bonus = _calculate_escalation()
    if escalation_bonus > 0:
        score += escalation_bonus
        reasons.append(f"Session escalation pattern: +{escalation_bonus}")

    if score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    st.session_state.session_risk_history.append({
        "timestamp": datetime.now().isoformat(),
        "function": function_name,
        "score": score,
        "level": risk_level,
    })

    return score, reasons, risk_level


def _calculate_escalation():
    history = st.session_state.session_risk_history
    if len(history) < 2:
        return 0
    recent = history[-5:]
    scores = [e["score"] for e in recent]
    increasing = sum(1 for i in range(1, len(scores)) if scores[i] > scores[i - 1])
    if increasing >= 3:
        return 25
    elif increasing >= 2:
        return 10
    high_count = sum(1 for e in recent if e["level"] == "HIGH")
    if high_count >= 2:
        return 20
    return 0


# ============================================================
# AUDIT LOGGING
# ============================================================

def log_audit_event(function_name, arguments, decision, risk_score=None,
                    risk_level=None, risk_reasons=None, block_reason=None):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "function": function_name,
        "arguments": arguments,
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
        "block_reason": block_reason,
        "session_operation_count": len(st.session_state.session_risk_history),
    }
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    return log_entry


# ============================================================
# TOOL IMPLEMENTATIONS
# ============================================================

def read_file(filename):
    filepath = os.path.join(BASE_DIR, filename)
    with open(filepath, "r") as f:
        return f"File content of '{filename}':\n{f.read()}"


def write_file(filename, content):
    filepath = os.path.join(BASE_DIR, filename)
    with open(filepath, "w") as f:
        f.write(content)
    return f"Successfully wrote {len(content)} characters to '{filename}'"


def delete_file(filename):
    filepath = os.path.join(BASE_DIR, filename)
    os.remove(filepath)
    return f"Successfully deleted '{filename}'"


def query_database(query):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()
    results = [dict(row) for row in rows]
    conn.close()
    return json.dumps(results, indent=2, default=str)


def call_api(url, method="GET"):
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "ZeroTrustAgent/1.0")
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read().decode("utf-8")
            if len(body) > 2000:
                body = body[:2000] + "\n... [truncated]"
            return f"HTTP {response.status} from {url}:\n{body}"
    except urllib.error.HTTPError as e:
        return f"HTTP Error {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return f"URL Error: {e.reason}"


def execute_shell(command):
    result = subprocess.run(
        command.split(), capture_output=True, text=True, timeout=10, cwd=BASE_DIR,
    )
    output = result.stdout if result.stdout else result.stderr
    return f"Shell output:\n{output}" if output else "Shell output:\n(no output)"


# ============================================================
# EXECUTION ENGINE
# ============================================================

VALIDATORS = {
    "read_file": lambda args: validate_file_input(args.get("filename", "")),
    "write_file": lambda args: validate_file_input(args.get("filename", "")),
    "delete_file": lambda args: validate_file_input(args.get("filename", "")),
    "query_database": lambda args: validate_sql_input(args.get("query", "")),
    "call_api": lambda args: validate_api_input(args.get("url", "")),
    "execute_shell": lambda args: validate_shell_input(args.get("command", "")),
}

EXECUTORS = {
    "read_file": lambda args: read_file(args["filename"]),
    "write_file": lambda args: write_file(args["filename"], args["content"]),
    "delete_file": lambda args: delete_file(args["filename"]),
    "query_database": lambda args: query_database(args["query"]),
    "call_api": lambda args: call_api(args["url"], args.get("method", "GET")),
    "execute_shell": lambda args: execute_shell(args["command"]),
}


def execute_function(function_name, arguments):
    """Run all security layers, return (result, status, checks_detail)."""
    checks = {}

    # Layer 1: Input Validation
    validator = VALIDATORS.get(function_name)
    if not validator:
        log_audit_event(function_name, arguments, "BLOCKED", block_reason="Unknown function")
        return f"BLOCKED: Unknown function '{function_name}'", "BLOCKED_VALIDATION", checks

    valid, validation_msg = validator(arguments)
    checks["validation"] = {"passed": valid, "message": validation_msg}
    if not valid:
        log_audit_event(function_name, arguments, "BLOCKED", block_reason=validation_msg)
        return validation_msg, "BLOCKED_VALIDATION", checks

    # Layer 2: Rate Limiting
    rate_ok, rate_msg, count = check_rate_limit(function_name)
    checks["rate_limit"] = {"passed": rate_ok, "message": rate_msg, "count": count}
    if not rate_ok:
        log_audit_event(function_name, arguments, "BLOCKED", block_reason=rate_msg)
        return rate_msg, "BLOCKED_RATE_LIMIT", checks

    # Layer 3: Policy Check
    policy_allowed = check_permission(function_name)
    checks["policy"] = {"passed": policy_allowed, "message": "Allowed" if policy_allowed else "Denied by policy"}
    if not policy_allowed:
        reason = f"Function '{function_name}' denied by policy"
        log_audit_event(function_name, arguments, "BLOCKED", block_reason=reason)
        return reason, "BLOCKED_POLICY", checks

    # Layer 4: Risk Assessment
    risk_score, risk_reasons, risk_level = calculate_risk_score(function_name, arguments)
    checks["risk"] = {"score": risk_score, "level": risk_level, "reasons": risk_reasons}

    if risk_score >= 70:
        log_audit_event(function_name, arguments, "BLOCKED",
                        risk_score=risk_score, risk_level=risk_level,
                        risk_reasons=risk_reasons, block_reason="Risk score too high")
        return f"BLOCKED (High Risk): Score {risk_score}/100", "BLOCKED_RISK", checks

    # All checks passed
    try:
        executor = EXECUTORS.get(function_name)
        result = executor(arguments) if executor else "Unknown function"
        log_audit_event(function_name, arguments, "ALLOWED",
                        risk_score=risk_score, risk_level=risk_level, risk_reasons=risk_reasons)
        return result, "ALLOWED", checks
    except Exception as e:
        error_msg = f"Execution error: {str(e)}"
        log_audit_event(function_name, arguments, "ERROR",
                        risk_score=risk_score, risk_level=risk_level,
                        risk_reasons=risk_reasons, block_reason=error_msg)
        return error_msg, "ERROR", checks


# ============================================================
# CLAUDE TOOL DEFINITIONS
# ============================================================

tools = [
    {
        "name": "read_file",
        "description": "Read contents of a file",
        "input_schema": {
            "type": "object",
            "properties": {"filename": {"type": "string", "description": "Name of the file to read"}},
            "required": ["filename"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Name of the file to write"},
                "content": {"type": "string", "description": "Content to write"},
            },
            "required": ["filename", "content"],
        },
    },
    {
        "name": "delete_file",
        "description": "Delete a file",
        "input_schema": {
            "type": "object",
            "properties": {"filename": {"type": "string", "description": "Name of the file to delete"}},
            "required": ["filename"],
        },
    },
    {
        "name": "query_database",
        "description": "Execute a SQL query against the database to retrieve information",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "SQL SELECT query to execute"}},
            "required": ["query"],
        },
    },
    {
        "name": "call_api",
        "description": "Make an HTTP request to an external API endpoint",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The full URL to call"},
                "method": {"type": "string", "description": "HTTP method (GET or POST)", "default": "GET"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "execute_shell",
        "description": "Execute a shell command on the system",
        "input_schema": {
            "type": "object",
            "properties": {"command": {"type": "string", "description": "Shell command to execute"}},
            "required": ["command"],
        },
    },
]


def run_agent(user_request):
    response = client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=1024,
        tools=tools,
        messages=[{"role": "user", "content": user_request}],
    )
    claude_thoughts = [block.text for block in response.content if block.type == "text"]
    if response.stop_reason == "tool_use":
        tool_use = next(block for block in response.content if block.type == "tool_use")
        claude_text = " ".join(claude_thoughts) if claude_thoughts else "Claude is calling a function..."
        return tool_use.name, tool_use.input, claude_text
    else:
        claude_text = claude_thoughts[0] if claude_thoughts else "No response"
        return None, None, claude_text


# ============================================================
# STREAMLIT UI
# ============================================================

st.title("🛡️ Zero Trust AI Agent")
st.caption("Security Layers: Input Validation | Rate Limiting | Policy Engine | Risk Scoring | Audit Logging")
st.markdown("---")

# Ensure test file and DB exist
if not os.path.exists(os.path.join(BASE_DIR, "test.txt")):
    with open(os.path.join(BASE_DIR, "test.txt"), "w") as f:
        f.write("CONFIDENTIAL CUSTOMER DATABASE\nCustomer ID: CUST-2024-1847\nName: Sarah Johnson")

if not os.path.exists(DB_PATH):
    from setup_demo_db import setup_database
    setup_database()

# Layout
col1, col2 = st.columns([2, 1])

with col1:
    st.header("💬 AI Agent Interface")

    user_input = st.text_area(
        "Enter your request:",
        height=120,
        placeholder="Examples:\n- Read the file test.txt\n- Query the database to list all employees\n- Call the API at https://httpbin.org/get\n- Delete the file test.txt",
    )

    run_button = st.button("🚀 Run Agent", type="primary", use_container_width=True)

    if run_button and user_input:
        with st.spinner("🤖 Claude is thinking..."):
            function_name, arguments, claude_text = run_agent(user_input)

            if claude_text:
                st.markdown("### 💭 Claude's Response")
                st.info(claude_text)

            if function_name:
                st.markdown("### 🔧 Function Call")
                st.success(f"Claude wants to call: **{function_name}**")
                st.json(arguments)

                # Execute with all security checks
                result, status, checks = execute_function(function_name, arguments)

                # Display security checks
                st.markdown("### 🔍 Security Checks")
                check_cols = st.columns(4)

                with check_cols[0]:
                    st.info("**Input Validation**")
                    if "validation" in checks:
                        if checks["validation"]["passed"]:
                            st.success("✅ Clean")
                        else:
                            st.error("❌ Blocked")
                    else:
                        st.warning("⏭️ Skipped")

                with check_cols[1]:
                    st.info("**Rate Limit**")
                    if "rate_limit" in checks:
                        if checks["rate_limit"]["passed"]:
                            st.success(f"✅ {checks['rate_limit']['count']}/5")
                        else:
                            st.error("❌ Exceeded")
                    else:
                        st.warning("⏭️ Skipped")

                with check_cols[2]:
                    st.info("**Policy**")
                    if "policy" in checks:
                        if checks["policy"]["passed"]:
                            st.success("✅ Allowed")
                        else:
                            st.error("❌ Denied")
                    else:
                        st.warning("⏭️ Skipped")

                with check_cols[3]:
                    st.info("**Risk Score**")
                    if "risk" in checks:
                        score = checks["risk"]["score"]
                        level = checks["risk"]["level"]
                        if level == "LOW":
                            st.success(f"✅ {score}/100")
                        elif level == "MEDIUM":
                            st.warning(f"⚠️ {score}/100")
                        else:
                            st.error(f"🔴 {score}/100")
                    else:
                        st.warning("⏭️ Skipped")

                # Risk breakdown
                if "risk" in checks:
                    st.markdown("### ⚠️ Risk Assessment")
                    r_col1, r_col2 = st.columns([1, 2])
                    with r_col1:
                        st.metric("Risk Score", f"{checks['risk']['score']}/100", checks["risk"]["level"])
                    with r_col2:
                        st.progress(min(checks["risk"]["score"] / 100, 1.0))
                        for reason in checks["risk"]["reasons"]:
                            st.caption(reason)

                # Result
                st.markdown("### 📊 Result")
                if status == "ALLOWED":
                    st.success(result)
                elif status == "BLOCKED_VALIDATION":
                    st.error(f"🚨 INPUT VALIDATION FAILED\n\n{result}")
                elif status == "BLOCKED_RATE_LIMIT":
                    st.error(f"🚫 RATE LIMIT EXCEEDED\n\n{result}")
                elif status == "BLOCKED_POLICY":
                    st.error(f"❌ POLICY VIOLATION\n\n{result}")
                elif status == "BLOCKED_RISK":
                    st.error(f"🔴 HIGH RISK BLOCKED\n\n{result}")
                elif status == "ERROR":
                    st.error(f"⚠️ EXECUTION ERROR\n\n{result}")
            else:
                st.markdown("### 💬 Claude's Response")
                st.info(claude_text)

with col2:
    st.header("🔧 System Status")

    # Current policies
    st.subheader("📋 Policies")
    policies = load_policies()
    for func, policy in policies.items():
        icon = "✅" if policy.get("allowed") else "❌"
        st.text(f"{icon} {func}")

    st.markdown("---")

    # Security features
    st.subheader("🛡️ Security Layers")
    st.success("✅ Input Validation (Blocklist + Allowlist)")
    st.success("✅ Rate Limiting (5 req/min)")
    st.success("✅ Policy Engine (JSON config)")
    st.success("✅ Risk Scoring (0-100)")
    st.success("✅ Session Escalation Detection")
    st.success("✅ Audit Logging (with risk scores)")

    st.markdown("---")

    # Session stats
    st.subheader("📈 Session Stats")
    st.metric("Operations this session", len(st.session_state.session_risk_history))
    if st.session_state.session_risk_history:
        avg_risk = sum(e["score"] for e in st.session_state.session_risk_history) / len(st.session_state.session_risk_history)
        st.metric("Avg risk score", f"{avg_risk:.0f}/100")

    st.markdown("---")

    # Allowlists
    st.subheader("📝 Allowlists")
    with st.expander("File Extensions"):
        st.text(", ".join(sorted(ALLOWED_FILE_EXTENSIONS)))
    with st.expander("Database Tables"):
        st.text(", ".join(sorted(ALLOWED_DB_TABLES)))
    with st.expander("API Domains"):
        st.text(", ".join(sorted(ALLOWED_API_DOMAINS)))
    with st.expander("Shell Commands"):
        st.text(", ".join(sorted(ALLOWED_SHELL_COMMANDS)))

# Footer
st.markdown("---")
st.caption("🛡️ Zero Trust AI Agent | 6 Tool Types | 5 Security Layers | NIST SP 800-207 Aligned")
