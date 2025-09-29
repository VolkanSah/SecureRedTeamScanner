#  Adaptive Dual-KI Red Team Scanner Documentation
##### BATMOBILE EDITION - IDEA

## 1. Overview

The Batmobile Edition is a sophisticated Python-based security testing module designed for **isolated Tor Hidden Services** (Red Team/ethical testing environments only). It combines local scanning capabilities with secure, abstracted AI analysis to perform adaptive, multi-stage attacks while minimizing data leakage.

It operates a **Dual-AI Setup**:
* **Claude:** Strategic analysis and high-level pattern recognition from anonymized scan results.
* **Gemini:** Offensive, adaptive payload generation and obfuscation to bypass WAFs/IDR systems.

**Key Security Feature: Data Abstraction.** No raw URLs, payloads, or response bodies are ever sent to the external AI services. Only hashed targets and abstracted metrics are shared.

## 2. Configuration & Setup

### Prerequisites

1.  **Python 3.x**
2.  **Required Libraries:** `requests`, `json`, `hashlib`, `anthropic`, `google-genai` (The script manages the imports, but they must be installed).
3.  **Tor Proxy Setup:** Three distinct SOCKS5 circuits must be running locally for isolation.

### Environment Variables

The script requires API keys to be set in your environment:

| Variable | AI Service | Purpose |
| :--- | :--- | :--- |
| `ANTHROPIC_API_KEY` | Claude | Strategic Analysis |
| `GEMINI_API_KEY` | Gemini | Offensive Payload Generation |

### Tor Proxy Configuration

Ensure your Tor setup provides these three isolated SOCKS5 endpoints:

```python
TOR_PROXIES = {
    'scan_circuit': 'socks5h://127.0.0.1:9050',    # Aggressive Scans (XSS, SQLi)
    'recon_circuit': 'socks5h://127.0.0.1:9051',   # Passive Reconnaissance
    'verify_circuit': 'socks5h://127.0.0.1:9052'   # Future Verification/Slow Scans
}
````

## 3\. Core Functionality

### 3.1 Adaptive XSS Scan (`adaptive_xss_scan`) 🔥

This is the primary function, implementing the KI-driven feedback loop:

1.  **Initial Scan (Standard Payloads):** Runs basic, un-obfuscated XSS tests to check for low-hanging fruit.
2.  **Analysis:** If the initial scan results in a `"blocked"` or `"sanitized"` response pattern, the loop is triggered.
3.  **Gemini Evasion Payload Generation:**
      * The latest **abstracted** `ScanResult` is sent to Gemini.
      * Gemini generates a new, highly **obfuscated** payload tailored to bypass the observed defense mechanism (e.g., Status 403, missing headers).
      * **Crucial:** The payload must contain the unique detection marker: `RedTeamBreak`.
4.  **XSSpy Fallback:** If Gemini fails or is not configured, a payload is pulled from the local XSSpy list.
5.  **Custom Scan Execution:** The new payload is tested using the robust `_run_custom_xss_scan` function.
6.  **Loop Termination:** Stops upon successful exploitation (`vulnerability_found = True`) or after `max_iterations`.

### 3.2 Secure Detection (`_detect_xss_reflection`)

The script uses a multi-layer local detection engine to confirm a reflection without sending raw response data to the AI:

  * **Direct & Decoded Match:** Checks for the original payload and its URL/HTML-decoded forms.
  * **Marker-Based:** Searches specifically for the `RedTeamBreak` marker.
  * **JS Context Validation:** Heuristically checks if critical indicators (`<script`, `onerror=`) are reflected in an executable JavaScript context, confirming exploitability.

### 3.3 Strategic Analysis (`analyze_with_claude`) 🤖

After the adaptive scan concludes, an abstracted summary report (total scans, severity distribution, anomaly scores, timing) is sent to Claude.

  * **Output:** Claude provides a strategic analysis, including a **Security Score (0-10)**, identification of WAF/IDS patterns, and recommendations for the next steps (e.g., try SQLi, brute-force admin panel).

## 4\. Data Structures (Abstractions)

To ensure privacy and security, only these anonymized structures are used for data handling and KI communication:

### `ScanResult`

| Field | Description | Type |
| :--- | :--- | :--- |
| `target_hash` | SHA256 of the URL (**NOT** the URL itself) | `str` |
| `scan_type` | e.g., "xss", "sqli", "xss\_adaptive" | `str` |
| `vulnerability_found` | `True`/`False` | `bool` |
| `response_pattern` | "reflected", "blocked", "sanitized", "timeout" | `str` |
| `anomaly_score` | Local score (0.0-1.0) based on unexpected response changes. | `float` |
| `headers_fingerprint` | Hash of security headers (CSP, XFO, HSTS status) | `str` |

### `TargetProfile`

Used during passive reconnaissance (`run_reconnaissance`) for general system profiling.

| Field | Description | Type |
| :--- | :--- | :--- |
| `target_hash` | Anonymized target identifier. | `str` |
| `technology_stack` | Detected technologies (e.g., "Apache", "Nginx", "PHP"). | `List[str]` |
| `security_headers` | Status of major security headers. | `Dict` |

## 5\. Usage Example

```bash
# Set your API keys
export ANTHROPIC_API_KEY="sk-..."
export GEMINI_API_KEY="AIza..."

# Execute the script
python3 batmobile_scanner.py
```

