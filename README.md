# Zero Trust AI Agent Framework

A multi-layered security enforcement framework that applies Zero Trust principles (NIST SP 800-207) to AI agents with tool-calling capabilities. The framework sits between an AI model's decisions and actual system execution, ensuring every operation is validated, authorized, risk-assessed, and logged before it runs.

## Architecture

```
User Request → Claude AI → Tool Call Decision → Zero Trust Security Gate → Execute or Block → Audit Log
```

The security gate consists of 5 independent layers. All must pass for an operation to execute. If any single layer blocks the operation, it does not run.

### Security Layers

| Layer | What It Does | How It Works |
|-------|-------------|--------------|
| **1. Input Validation** | Blocks malicious inputs | Blocklist (path traversal, injection patterns, encoded attacks) + Allowlist (permitted file extensions, DB tables, shell commands, API domains) + Sandbox enforcement |
| **2. Rate Limiting** | Prevents abuse and exfiltration | Sliding window per function (default: 5 requests per 60 seconds) |
| **3. Policy Engine** | Enforces access control | JSON-configurable per-function allow/deny. Default: deny. Loaded from disk on every check (no caching) |
| **4. Risk Scoring** | Contextual threat assessment | 0-100 score based on 4 factors: operation type, target sensitivity, time anomaly, session escalation. Score >= 70 blocks the operation |
| **5. Audit Logging** | Full forensic trail | Every operation logged with timestamp, arguments, decision, risk score, risk level, risk reasons, and session context |

### Risk Scoring System

The risk scoring engine calculates a 0-100+ threat score using four independent factors:

| Factor | Score Range | What It Detects |
|--------|------------|-----------------|
| **Operation type** | +10 to +40 | Destructive operations (delete: +40, shell: +35, write: +20, DB/API: +15, read: +10) |
| **Target sensitivity** | +60 to +80 | Arguments containing sensitive keywords (credential, password, secret, key, token, api, private, confidential, admin, root). +10 bonus for multiple keywords, +10 for write/delete on sensitive targets |
| **Time anomaly** | +0 or +30 | Operations between 10 PM and 6 AM |
| **Session escalation** | +0 to +25 | Detects patterns of increasing risk across the session (e.g., read → write → delete) or concentration of HIGH-risk operations |

Risk levels:
- **LOW** (GREEN): Score < 40 — operation proceeds
- **MEDIUM** (YELLOW): Score 40-69 — operation proceeds with elevated logging
- **HIGH** (RED): Score >= 70 — operation blocked

## Supported Tool Types

The framework secures 6 different tool types, each with its own dedicated input validator:

| Tool | Description | Default Policy | Validator |
|------|-------------|---------------|-----------|
| `read_file` | Read file contents | Allowed | File blocklist + extension allowlist + sandbox check |
| `write_file` | Write content to file | Allowed | File blocklist + extension allowlist + sandbox check |
| `delete_file` | Delete a file | **Blocked** | File blocklist + extension allowlist + sandbox check |
| `query_database` | SQL query (SQLite) | Allowed | SELECT-only + SQL injection detection + table allowlist |
| `call_api` | HTTP requests | Allowed | Domain allowlist |
| `execute_shell` | Shell commands | **Blocked** | Command allowlist + injection pattern detection |

### Allowlists

- **File extensions**: `.txt`, `.csv`, `.json`, `.log`, `.md`, `.py`
- **Database tables**: `employees`, `projects`, `security_events`
- **API domains**: `api.github.com`, `httpbin.org`, `jsonplaceholder.typicode.com`
- **Shell commands**: `echo`, `date`, `whoami`, `ls`, `cat`, `wc`, `head`, `tail`

All allowlists are configurable in `main.py`.

## Evaluation

The framework includes a structured test suite (`test_suite.py`) with 31 predefined security scenarios across 9 categories. Tests execute directly against the security enforcement pipeline without calling the Claude API.

### Test Categories and Results

| Category | Tests | Pass Rate | What's Tested |
|----------|-------|-----------|---------------|
| Benign Operations | 5 | 100% | Normal file reads, writes, DB queries, API calls |
| Path Traversal | 5 | 100% | `../`, `~/`, `/etc/`, `/root/`, URL-encoded traversal |
| Command Injection | 4 | 100% | Semicolons, pipes, backticks, dollar-paren substitution |
| SQL Injection | 5 | 100% | DROP, UNION SELECT, DELETE, INSERT, non-allowlisted tables |
| Policy Violation | 2 | 100% | Delete file, execute shell (both blocked by policy) |
| Sensitive Data | 3 | 100% | Access to credential/password/token files blocked by risk score |
| API Security | 3 | 100% | Non-allowlisted domains, SSRF via internal IPs, localhost |
| Shell Security | 2 | 100% | `rm`, `curl` (not in command allowlist) |
| File Extension | 2 | 100% | `.exe`, `.sh` (not in extension allowlist) |

### Detection Metrics

| Metric | Value |
|--------|-------|
| True Positives (correctly blocked) | 26 |
| True Negatives (correctly allowed) | 5 |
| False Positives (wrongly blocked) | 0 |
| False Negatives (wrongly allowed) | 0 |
| **Precision** | **1.000** |
| **Recall** | **1.000** |
| **F1 Score** | **1.000** |

Note: These results are against a controlled test suite with predefined attack patterns. Real-world adversarial evaluation against benchmarks like AgentDojo or ASB would provide additional insight into robustness against novel attacks.

## Quick Start

### Installation

```bash
pip install anthropic streamlit python-dotenv
```

### Setup

1. Create a `.env` file with your Anthropic API key:
   ```
   ANTHROPIC_API_KEY=your-key-here
   ```

2. Set up the demo database:
   ```bash
   python setup_demo_db.py
   ```

3. Review `policies.json` to configure access control.

### Run

**Run the test suite (no API key needed):**
```bash
python test_suite.py
```

**Command-line demo (requires API key):**
```bash
python main.py
```

**Interactive web dashboard (requires API key):**
```bash
streamlit run streamlit_app.py
```

## Project Structure

```
zero_trust_project/
├── main.py              # Core framework: security layers, tool implementations, execution engine
├── streamlit_app.py     # Interactive web UI with real-time security visualization
├── test_suite.py        # 31-scenario structured security test suite
├── setup_demo_db.py     # Creates local SQLite database with sample data
├── policies.json        # Access control configuration (per-function allow/deny)
├── demo.db              # SQLite database (auto-generated by setup_demo_db.py)
├── audit_log.txt        # Audit trail (auto-generated at runtime)
├── test_results.json    # Test suite results report (auto-generated)
└── README.md
```

## How It Works: Example Flows

### Allowed Operation
```
User: "List all employees"
→ Claude decides: query_database("SELECT * FROM employees")
→ [1] Input Validation: PASS (SELECT-only, table in allowlist)
→ [2] Rate Limiting: PASS (1/5 requests)
→ [3] Policy Engine: PASS (query_database: allowed)
→ [4] Risk Score: 15/100 (LOW)
→ RESULT: ALLOWED — returns employee data
→ Audit log: {"decision": "ALLOWED", "risk_score": 15, "risk_level": "LOW"}
```

### Blocked Operation (Input Validation)
```
User: "Read the file ../../../etc/passwd"
→ Claude decides: read_file("../../../etc/passwd")
→ [1] Input Validation: FAIL (path traversal detected)
→ RESULT: BLOCKED
→ Audit log: {"decision": "BLOCKED", "block_reason": "Path traversal attempt"}
```

### Blocked Operation (Risk Score)
```
User: "Read credentials.txt"
→ Claude decides: read_file("credentials.txt")
→ [1] Input Validation: PASS
→ [2] Rate Limiting: PASS
→ [3] Policy Engine: PASS
→ [4] Risk Score: 70/100 (HIGH) — operation risk +10, sensitive keyword "credential" +60
→ RESULT: BLOCKED (risk score >= 70)
→ Audit log: {"decision": "BLOCKED", "risk_score": 70, "risk_level": "HIGH"}
```

### Blocked Operation (Policy)
```
User: "Delete test.txt"
→ Claude decides: delete_file("test.txt")
→ [1] Input Validation: PASS
→ [2] Rate Limiting: PASS
→ [3] Policy Engine: FAIL (delete_file: denied)
→ RESULT: BLOCKED
→ Audit log: {"decision": "BLOCKED", "block_reason": "Function 'delete_file' denied by policy"}
```

## Configuration

### Policies (`policies.json`)

Control which tool types are allowed:

```json
{
  "read_file":       { "allowed": true },
  "write_file":      { "allowed": true },
  "delete_file":     { "allowed": false },
  "query_database":  { "allowed": true },
  "call_api":        { "allowed": true },
  "execute_shell":   { "allowed": false }
}
```

Default behavior: if a function is not in the policy file, it is **denied**. This follows Zero Trust's least-privilege principle.

## Technologies

- **AI Model**: Claude (Anthropic) via the Anthropic Python SDK
- **Database**: SQLite (local, no cloud dependencies)
- **Web UI**: Streamlit
- **Security Framework**: Custom implementation aligned with NIST SP 800-207 Zero Trust Architecture

## Security Best Practices

- Never commit `.env` or `credentials.txt` to version control
- Use environment variables for API keys
- Review `audit_log.txt` regularly for suspicious patterns
- Adjust policies and allowlists based on your deployment requirements
- Run the test suite after any changes to security layers

## License

MIT
