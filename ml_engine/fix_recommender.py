"""
CodeVigil — Fix Recommender
==============================
Maps vulnerability types and CVEs to remediation patterns.
Uses keyword-based matching + CVE database fix patterns.
"""

import json
import re


# Generic remediation patterns by vulnerability type
GENERIC_FIXES = {
    "Remote Code Execution": [
        "Apply vendor security patches immediately",
        "Disable unnecessary services and endpoints",
        "Implement input validation and sanitization",
        "Use Web Application Firewall (WAF) rules",
        "Enable network segmentation and least-privilege access",
        "Monitor for suspicious command execution patterns",
    ],
    "SQL Injection": [
        "Use parameterized queries / prepared statements",
        "Implement input validation with whitelist approach",
        "Apply least-privilege database permissions",
        "Use an ORM (Object-Relational Mapping) library",
        "Deploy WAF with SQL injection detection rules",
        "Regularly audit database queries for injection points",
    ],
    "Path Traversal": [
        "Validate and sanitize all file path inputs",
        "Use allowlists for file access paths",
        "Implement chroot jails or sandboxing",
        "Reject requests containing '..' or encoded variants",
        "Apply OS-level file permissions",
        "Use canonical path resolution before file access",
    ],
    "Buffer Overflow": [
        "Upgrade to patched software version",
        "Enable ASLR (Address Space Layout Randomization)",
        "Compile with stack canaries and DEP/NX bit",
        "Use memory-safe languages where possible",
        "Apply bounds checking on all buffer operations",
        "Implement fuzzing in development/testing",
    ],
    "Deserialization": [
        "Avoid deserializing untrusted data",
        "Use type-checking on deserialized objects",
        "Implement allowlists for acceptable classes",
        "Upgrade libraries with known deserialization patches",
        "Use serialization formats without code execution (JSON over pickle)",
        "Monitor for suspicious serialized object patterns",
    ],
    "Authentication Bypass": [
        "Apply security patches for authentication modules",
        "Implement multi-factor authentication (MFA)",
        "Review and harden authentication logic",
        "Rotate all credentials and session tokens",
        "Implement rate limiting on authentication endpoints",
        "Monitor for unusual authentication patterns",
    ],
    "Privilege Escalation": [
        "Apply OS and application patches",
        "Implement least-privilege access controls",
        "Review and restrict sudo/admin permissions",
        "Monitor for privilege escalation attempts",
        "Use SELinux/AppArmor for mandatory access control",
        "Audit user permissions regularly",
    ],
    "Command Injection": [
        "Never pass user input directly to shell commands",
        "Use subprocess with argument lists (not shell=True)",
        "Implement strict input validation and sanitization",
        "Use allowlists for acceptable commands",
        "Run services with minimum required privileges",
        "Deploy WAF with command injection detection",
    ],
    "Cross-Site Scripting": [
        "Encode all user output (HTML entity encoding)",
        "Implement Content Security Policy (CSP) headers",
        "Use framework auto-escaping features",
        "Validate and sanitize all user inputs",
        "Set HttpOnly and Secure flags on cookies",
        "Use DOMPurify for rich text inputs",
    ],
    "Information Disclosure": [
        "Restrict access to sensitive endpoints",
        "Remove debug modes in production",
        "Implement proper error handling (no stack traces to users)",
        "Encrypt sensitive data at rest and in transit",
        "Rotate exposed credentials immediately",
        "Review access control policies",
    ],
    "Denial of Service": [
        "Implement rate limiting and throttling",
        "Deploy CDN/load balancer for traffic absorption",
        "Apply vendor patches for protocol vulnerabilities",
        "Configure connection timeouts and limits",
        "Monitor traffic patterns for anomalies",
        "Implement auto-scaling for critical services",
    ],
    "SSRF": [
        "Validate and restrict outbound request URLs",
        "Implement allowlists for acceptable domains/IPs",
        "Block requests to internal/private IP ranges",
        "Use network segmentation to limit server connectivity",
        "Disable unnecessary URL scheme handlers",
    ],
    "File Inclusion": [
        "Validate and whitelist file path inputs",
        "Disable remote file inclusion in configuration",
        "Use allowlists for includable files",
        "Apply strict directory permissions",
        "Implement input validation before file operations",
    ],
    "Server-Side Template Injection": [
        "Avoid passing user input to template engines",
        "Use sandboxed template environments",
        "Implement strict input validation",
        "Apply security patches for template engines",
        "Monitor for template injection patterns in logs",
    ],
    "Cryptographic Vulnerability": [
        "Upgrade to patched cryptographic libraries",
        "Regenerate keys and certificates",
        "Revoke compromised certificates",
        "Use modern cipher suites (TLS 1.2+/1.3)",
        "Implement certificate pinning where applicable",
        "Audit all cryptographic implementations",
    ],
    "Arbitrary File Upload": [
        "Validate file types with allowlists (not just extensions)",
        "Scan uploads for malware",
        "Store uploads outside web root",
        "Disable execution permissions in upload directories",
        "Implement file size limits",
    ],
}


class FixRecommender:
    """
    Recommends remediation steps for vulnerabilities.
    
    Combines:
    1. CVE-specific fix patterns from database
    2. Generic fix patterns based on vulnerability type
    """

    def __init__(self, cve_entries: list[dict]):
        """Initialize with CVE database."""
        self.cve_lookup = {e["cve_id"]: e for e in cve_entries}
        self.generic_fixes = GENERIC_FIXES

    def get_fix(self, cve_id: str = None, vuln_type: str = None, description: str = None) -> dict:
        """
        Get remediation recommendations.
        
        Args:
            cve_id: Specific CVE ID (if known)
            vuln_type: Vulnerability type (if classified)
            description: Vulnerability description (for keyword matching)
            
        Returns:
            Dict with specific_fix, generic_fixes, priority, and actions
        """
        result = {
            "specific_fix": None,
            "generic_fixes": [],
            "priority": "Medium",
            "immediate_actions": [],
        }

        # 1. CVE-specific fix from database
        if cve_id and cve_id in self.cve_lookup:
            cve = self.cve_lookup[cve_id]
            result["specific_fix"] = cve.get("fix_pattern", None)
            if not vuln_type:
                vuln_type = cve.get("type", "")
            
            # Set priority based on severity
            severity = cve.get("severity", "Medium")
            if severity == "Critical":
                result["priority"] = "CRITICAL — Patch Immediately"
                result["immediate_actions"] = [
                    "Isolate affected systems from network",
                    "Apply vendor security patch within 24 hours",
                    "Check for signs of active exploitation",
                    "Rotate all credentials on affected systems",
                ]
            elif severity == "High":
                result["priority"] = "HIGH — Patch Within 72 Hours"
                result["immediate_actions"] = [
                    "Schedule patching within 72 hours",
                    "Implement compensating controls (WAF, network rules)",
                    "Monitor for exploitation attempts",
                ]
            elif severity == "Medium":
                result["priority"] = "MEDIUM — Patch Within 2 Weeks"
                result["immediate_actions"] = [
                    "Add to patching queue",
                    "Implement temporary mitigations",
                ]
            else:
                result["priority"] = "LOW — Patch in Next Cycle"

        # 2. Generic fixes based on vulnerability type
        if vuln_type:
            result["generic_fixes"] = self.generic_fixes.get(vuln_type, [])

        # 3. If no type, try keyword matching from description
        if not result["generic_fixes"] and description:
            matched_type = self._match_type_from_description(description)
            if matched_type:
                result["generic_fixes"] = self.generic_fixes.get(matched_type, [])

        return result

    def _match_type_from_description(self, description: str) -> str:
        """Simple keyword matching to determine vulnerability type."""
        keywords = {
            "Remote Code Execution": ["rce", "remote code", "code execution", "arbitrary code", "execute"],
            "SQL Injection": ["sql injection", "sql query", "database", "sqli", "union select"],
            "Path Traversal": ["path traversal", "directory traversal", "file read", "file access", "../"],
            "Buffer Overflow": ["buffer overflow", "heap overflow", "stack overflow", "memory corruption"],
            "Deserialization": ["deserialization", "unserialize", "pickle", "marshal", "java object"],
            "Command Injection": ["command injection", "shell injection", "os command", "exec("],
            "Authentication Bypass": ["authentication bypass", "auth bypass", "login bypass", "unauthorized"],
            "Privilege Escalation": ["privilege escalation", "elevated", "root access", "admin"],
        }

        desc_lower = description.lower()
        best_match = None
        best_count = 0

        for vuln_type, kws in keywords.items():
            count = sum(1 for kw in kws if kw in desc_lower)
            if count > best_count:
                best_count = count
                best_match = vuln_type

        return best_match


# ─────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    with open("data/cve_database.json", "r") as f:
        cves = json.load(f)

    recommender = FixRecommender(cves)

    print("🔧 FIX RECOMMENDATION DEMO:")
    print("=" * 60)

    # Test with specific CVE
    fix = recommender.get_fix(cve_id="CVE-2021-44228")
    print(f"\n  CVE: CVE-2021-44228 (Log4Shell)")
    print(f"  Priority: {fix['priority']}")
    print(f"  Specific Fix: {fix['specific_fix']}")
    print(f"  Immediate Actions:")
    for action in fix["immediate_actions"]:
        print(f"    → {action}")
    print(f"  Generic Fixes:")
    for f_item in fix["generic_fixes"][:3]:
        print(f"    • {f_item}")

    # Test with type only
    fix2 = recommender.get_fix(vuln_type="SQL Injection")
    print(f"\n  Type: SQL Injection (no specific CVE)")
    print(f"  Generic Fixes:")
    for f_item in fix2["generic_fixes"][:3]:
        print(f"    • {f_item}")
