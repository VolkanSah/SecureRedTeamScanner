# SecureRedTeamScanner
#### Adaptive Dual-KI Red Team Scanner Documentation
##### [BATMOBILE](https://github.com/VolkanSah/x201-BatConsole) EDITION - AI-Powered Tor Security Testing
**⚠️ For Ethical Security Testing & DevOps Only | Legal Use Required**

### NOTE! API MONEY finished, cant test anymore,later...

[Roadmap ideas](roadmap.md)

---

## 1. Overview

The **Batmobile Edition** is a sophisticated Python-based security testing framework designed for **isolated Tor Hidden Services** in controlled Red Team/ethical testing environments. It combines local scanning capabilities with secure, abstracted AI analysis to perform adaptive, multi-stage attacks while **minimizing data leakage to external APIs**.

### Dual-AI Architecture

| AI Service | Role | Capabilities |
|:-----------|:-----|:------------|
| **Claude (Anthropic)** | Strategic Analyst | Pattern recognition, WAF/IDS detection, security scoring, next-step recommendations |
| **Gemini (Google)** | Offensive Engineer | Adaptive payload generation, obfuscation techniques, filter evasion |

### 🔒 Key Security Feature: Zero-Knowledge AI Integration

**No sensitive data ever leaves your system:**
- ❌ No raw `.onion` URLs (only SHA256 hashes)
- ❌ No response bodies or HTML content
- ❌ No exact payloads or exploitation details
- ✅ Only abstracted metrics: status codes, patterns, anomaly scores

---

## 2. Configuration & Setup

### 2.1 Prerequisites

```bash
# System Requirements
- Python 3.8+
- Tor daemon with multiple SOCKS5 circuits
- Linux/Unix environment (tested on Debian/Ubuntu)

# Install Dependencies
pip install requests anthropic google-genai stem
```

### 2.2 Environment Variables

Set your API keys (retrieve from respective provider dashboards):

```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
export GEMINI_API_KEY="AIzaSy..."
```

### 2.3 Tor Multi-Circuit Setup

The scanner requires **three isolated Tor circuits** for operational security:

```python
TOR_PROXIES = {
    'scan_circuit':   'socks5h://127.0.0.1:9050',  # Aggressive scans (XSS, SQLi)
    'recon_circuit':  'socks5h://127.0.0.1:9051',  # Passive reconnaissance
    'verify_circuit': 'socks5h://127.0.0.1:9052'   # Verification/slow scans
}
```

**Recommended `torrc` configuration:**

```ini
# /etc/tor/instances/scan_circuit/torrc
SocksPort 9050 IsolateDestAddr IsolateDestPort
DataDirectory /var/lib/tor/instances/scan_circuit

# /etc/tor/instances/recon_circuit/torrc
SocksPort 9051 IsolateClientAddr
DataDirectory /var/lib/tor/instances/recon_circuit

# /etc/tor/instances/verify_circuit/torrc
SocksPort 9052 IsolateSOCKSAuth
DataDirectory /var/lib/tor/instances/verify_circuit
```

Refer to the [Tor Multi-Instance Guide](https://github.com/VolkanSah/Multiple-Isolated-Tor-Instances-for-Hidden-Services) for complete setup instructions.

---

## 3. Core Functionality

### 3.1 Adaptive XSS Scan 🔥

**Function:** `adaptive_xss_scan(target_onion_url, max_iterations=3)`

The flagship feature - an AI-driven feedback loop for WAF evasion:

```
┌─────────────────────────────────────────────────────┐
│ [1] Initial Scan (Standard Payloads)               │
│     └─→ Result: SANITIZED (Status 200)            │
├─────────────────────────────────────────────────────┤
│ [2] Gemini Analysis                                 │
│     └─→ Generates: <svg/onload=alert('RedTeamBreak')> │
│     └─→ Result: BLOCKED (Status 403)              │
├─────────────────────────────────────────────────────┤
│ [3] Gemini Adaptation                               │
│     └─→ Generates: <details open ontoggle=alert`RedTeamBreak`> │
│     └─→ Result: REFLECTED ✓✓✓                     │
└─────────────────────────────────────────────────────┘
```

**Flow:**
1. Runs standard XSS tests with common payloads
2. If blocked/sanitized → Sends **abstracted metrics** to Gemini
3. Gemini generates obfuscated payload with detection marker (`RedTeamBreak`)
4. If Gemini fails → Falls back to [XSSpy payload library](https://github.com/VolkanSah/XSSPY-NCF)
5. Re-scans with new payload
6. Repeats until breakthrough or `max_iterations` reached

**Key Parameters:**
- `target_onion_url`: The `.onion` URL to test (validated locally)
- `max_iterations`: Maximum adaptive cycles (default: 3)

### 3.2 Secure Detection Engine

**Function:** `_detect_xss_reflection(payload, response_text)`

Multi-layer detection without sending raw data to APIs:

| Layer | Method | Purpose |
|:------|:-------|:--------|
| 1 | Direct Match | Checks for exact payload reflection |
| 2 | URL Decoding | Handles `%3Cscript%3E` → `<script>` |
| 3 | HTML Entity Decoding | Handles `&#x3C;script&#x3E;` |
| 4 | Marker Detection | Searches for `RedTeamBreak` string |
| 5 | JS Context Validation | Confirms executable context (not just HTML text) |

**Why this matters:**
```python
# Simple check (FAILS on encoding):
if "<script>alert(1)</script>" in response.text:
    return True  # ❌ Misses: &#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;

# Robust check (WORKS):
if self._detect_xss_reflection(payload, response.text):
    return True  # ✅ Catches all encoding variations + marker
```

### 3.3 Strategic Analysis (Claude)

**Function:** `analyze_with_claude(results: List[ScanResult])`

After scan completion, sends **anonymized summary** to Claude:

**Sent Data (Example):**
```json
{
  "total_scans": 3,
  "vulnerabilities_found": 1,
  "severity_distribution": {"critical": 1, "low": 2},
  "response_patterns": {"reflected": 1, "blocked": 1, "sanitized": 1},
  "avg_anomaly_score": 0.67,
  "timing_analysis": {
    "avg_ms": 1247,
    "timeout_rate": 0.0
  }
}
```

**Claude's Output:**
```json
{
  "security_score": 3.5,
  "critical_findings": [
    "XSS filter bypassed after 3 iterations",
    "WAF appears to use pattern-based blocking (Status 403 on <script>)"
  ],
  "recommended_scans": ["sqli", "csrf", "directory_bruteforce"],
  "waf_detected": true,
  "analysis": "Target shows adaptive defense but eventually failed..."
}
```

### 3.4 Additional Features

| Function | Purpose | Circuit |
|:---------|:--------|:--------|
| `run_xss_scan()` | Standard XSS test with basic payloads | scan_circuit |
| `run_reconnaissance()` | Passive tech stack detection | recon_circuit |
| `generate_attack_payload_with_gemini()` | On-demand obfuscated payload generation | N/A |
| `get_xsspy_payload()` | Fetches payload from local library | N/A |

---

## 4. Data Structures (Abstractions)

### `ScanResult`

All scan operations return this **anonymized** structure:

| Field | Type | Description | Example |
|:------|:-----|:------------|:--------|
| `target_hash` | `str` | SHA256(url)[:16] | `a3f5e9d2b1c4...` |
| `scan_type` | `str` | Attack category | `xss_adaptive` |
| `vulnerability_found` | `bool` | Exploitation success | `True` |
| `severity` | `str` | Risk level | `critical` |
| `response_pattern` | `str` | Defense behavior | `reflected` |
| `status_code` | `int` | HTTP response | `200` |
| `timing_ms` | `float` | Response time | `1247.3` |
| `headers_fingerprint` | `str` | Security headers hash | `{"CSP": false, ...}` |
| `anomaly_score` | `float` | Local computed score (0-1) | `0.85` |

### `TargetProfile`

Used for reconnaissance phase:

| Field | Type | Description |
|:------|:-----|:------------|
| `target_hash` | `str` | Anonymized identifier |
| `technology_stack` | `List[str]` | Detected tech (e.g., `["Apache", "PHP"]`) |
| `security_headers` | `Dict[str, bool]` | Header presence status |
| `circuit_stability` | `float` | Tor connection quality (0-1) |
| `avg_response_time` | `float` | Baseline timing |

---

## 5. Usage Examples

### 5.1 Basic Execution

```bash
# Set API keys
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="AIza..."

# Run scanner
python3 batmobile_scanner.py
```

### 5.2 Programmatic Usage

```python
from batmobile_scanner import SecureRedTeamScanner
import os

# Initialize with both AIs
scanner = SecureRedTeamScanner(
    claude_api_key=os.getenv('ANTHROPIC_API_KEY'),
    gemini_api_key=os.getenv('GEMINI_API_KEY')
)

# Target
target = "http://examplehiddenservice123.onion"

# Run adaptive scan
results = scanner.adaptive_xss_scan(target, max_iterations=5)

# Generate report
print(scanner.generate_report(include_ai_analysis=True))
```

### 5.3 Manual Payload Testing

```python
# Test specific payload from XSSpy library
custom_payload = "<iframe src=javascript:alert('RedTeamBreak')>"

result = scanner._run_custom_xss_scan(target, custom_payload)

if result.vulnerability_found:
    print(f"✓ XSS confirmed with payload: {custom_payload}")
```

---

## 6. Safety & Legal Considerations

### ⚠️ Ethical Use Only

This tool is designed **exclusively** for:
- Authorized penetration testing
- Security research in controlled environments
- Educational purposes with explicit permission

### 🚫 Prohibited Use

- Unauthorized access to systems
- Testing production services without consent
- Any illegal activity under your jurisdiction

### 🔒 API Key Security

Your API keys are **identifiable**. Even with data abstraction:
- Don't test illegal `.onion` services (marketplaces, abuse content)
- API providers may log requests for ToS compliance
- Use dedicated testing API keys (not production keys)

---

## 7. Troubleshooting

### Common Issues

**Problem:** `ERROR: Gemini API nicht konfiguriert`
```bash
# Solution: Set environment variable
export GEMINI_API_KEY="your_key_here"
```

**Problem:** `Could not load XSSpy payloads`
```bash
# Solution: Check network/firewall
curl https://raw.githubusercontent.com/VolkanSah/XSSPY-NCF/main/payloads.txt
```

**Problem:** `Tor connection timeout`
```bash
# Solution: Verify Tor is running
systemctl status tor@scan_circuit.service
systemctl status tor@recon_circuit.service
```

---

## 8. Roadmap

- [ ] SQLi adaptive scanner
- [ ] CSRF token extraction & testing
- [ ] Directory bruteforce with rate limiting
- [ ] Custom Gemini prompt templates
- [ ] Local LLM support (Ollama) for offline mode
- [ ] OWASP ZAP integration

---

## 9. Credits & License

**Author:** [Volkan Sah](https://github.com/volkansah)  
**License:** MIT (See LICENSE file)  
**Related Projects:**
- [Multiple Isolated Tor Instances](https://github.com/volkansah/Multiple-Isolated-Tor-Instances-for-Hidden-Services)
- [XSSPY-NCF Payload Library](https://github.com/VolkanSah/XSSPY-NCF)

**Powered by:**
- Claude 4 (Anthropic)
- Gemini 2.0 (Google)
- Tor Project
- Batman's relentless pursuit of justice 🦇

---

## 10. Support

If this tool helps your security research:
- ⭐ Star the repository
- 🐛 Report issues via GitHub
- 💬 Share feedback and improvements
- ☕ [Support via GitHub Sponsors](https://github.com/sponsors/volkansah)

**Questions?** Open an issue or contact via [GitHub Profile](https://github.com/volkansah)

---

**Disclaimer:** This tool is provided "as-is" without warranties. Users are solely responsible for compliance with applicable laws and regulations. GPL3
#### Copyright
[Volkan Kücükbudak](https://github.com/volkansah)
