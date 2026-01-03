import re
import os
from typing import Dict, Tuple, List

# ==================== SQL INJECTION PATTERNS ====================
SQLI_PATTERNS = [
    r"\b(select|union|insert|update|delete|drop)\b",
    r"--",
    r"/\*.*\*/",
    r"\bor\b\s+\d+\s*=",
    r"'.*or.*'.*'.*=.*'",  # NEW: Détecte 1' OR '1'='1
    r"\bsleep\s*\(",  # NEW: Time-based blind SLEEP(5)
    r"\bbenchmark\s*\(",  # NEW: Time-based blind BENCHMARK
    r"\bwaitfor\b.*\bdelay\b",  # NEW: MSSQL WAITFOR DELAY
    r"\bexec\b|\bexecute\b",  # NEW: EXEC/EXECUTE commands
]

# ==================== XSS PATTERNS ====================
XSS_PATTERNS = [
    r"<script.*?>",
    r"onerror\s*=",
    r"javascript:\s*",
    r"<img\s+src=",
    r"<svg[^>]*onload",  # NEW: <svg/onload=alert(1)>
    r"<iframe[^>]*src",  # NEW: <iframe src=...>
    r"<object[^>]*data",  # NEW: <object data=...>
    r"<embed[^>]*src",  # NEW: <embed src=...>
    r"on\w+\s*=",  # NEW: All event handlers (onclick, onerror, etc.)
]

# ==================== COMMAND INJECTION PATTERNS ====================
CMDI_PATTERNS = [
    r"[;|&]\s*(whoami|id|ls|cat|wget|curl|nc|bash|sh|cmd|uname|pwd)",
    r"`.*`",  # Backticks: `whoami`
    r"\$\(.*\)",  # Command substitution: $(whoami)
    r"%0a|%0d",  # Newline injection
    r"\|\s*(grep|awk|sed|sort|uniq|head|tail|cut)",  # Pipe with Unix commands
]

# ==================== PATH TRAVERSAL / LFI PATTERNS ====================
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./|\.\.\\/",  # ../ or ..\
    r"%2e%2e%2f|%2e%2e/|%2e%2e%5c",  # Encoded ../
    r"\.\.%2f|\.\.%5c",  # Partially encoded
    r"\.\.\.\./+|\.\.\.\.\\+",  # Double slash evasion: ....//
    r"/etc/passwd|/etc/shadow|/etc/hosts",  # Unix sensitive files
    r"c:\\windows\\|c:/windows/",  # Windows paths
]

# ==================== SSRF PATTERNS ====================
SSRF_PATTERNS = [
    r"169\.254\.169\.254",  # AWS metadata
    r"metadata\.google\.internal",  # GCP metadata
    r"(url|target|redirect|proxy|host|src|href).*?(localhost|127\.0\.0\.1)",  # Loopback in parameters
    r"file:///",  # File protocol
    r"(gopher|dict|ftp)://",  # Alternative protocols
]

# ==================== XXE PATTERNS ====================
XXE_PATTERNS = [
    r"<!ENTITY",  # XML Entity declaration
    r"<!DOCTYPE.*\[",  # DOCTYPE with DTD
    r"SYSTEM\s+[\"']file://",  # External entity: file://
]

# ==================== LDAP INJECTION PATTERNS ====================
LDAP_PATTERNS = [
    r"\(\|\(",  # (|( LDAP OR injection
    r"\)\(\|",  # )(| LDAP injection
    r"\*\)\(",  # *)( LDAP wildcard injection
    r"\(&\(",  # (&( LDAP AND injection
]

# ==================== NOSQL INJECTION PATTERNS ====================
NOSQL_PATTERNS = [
    r"\{\s*\$\w+\s*:",  # {$ne:, {$gt:, etc.
    r"\[\s*\$\w+\s*\]",  # [$ne], [$regex], etc.
    r"\{\s*['\"]?\$where['\"]?\s*:",  # $where queries
    r"sleep\s*\(\s*\d+\s*\)",  # sleep(5000)
]

# ==================== LOG4SHELL/JNDI INJECTION PATTERNS ====================
JNDI_PATTERNS = [
    r"\$\{jndi:",  # ${jndi:ldap://
    r"\$\{jndi:ldap://",
    r"\$\{jndi:rmi://",
    r"\$\{jndi:dns://",
]

# ==================== PHP FILTER/WRAPPER PATTERNS ====================
PHP_FILTER_PATTERNS = [
    r"php://filter",
    r"php://input",
    r"php://output",
    r"data://text/plain",
    r"expect://",
    r"phar://",
]

# ==================== SERVER-SIDE TEMPLATE INJECTION (SSTI) PATTERNS ====================
SSTI_PATTERNS = [
    r"\{\{.*\*.*\}\}",  # {{7*7}}
    r"\$\{.*\*.*\}",  # ${7*7}
    r"\{\%.*\%\}",  # {%...%}
    r"<\%.*\%>",  # <%...%>
    r"\{\{.*config.*\}\}",  # {{config}}
    r"\{\{.*self.*\}\}",  # {{self}}
]

# ==================== JSP CODE INJECTION PATTERNS ====================
JSP_PATTERNS = [
    r"<\%\s*eval\s*\(",  # <% eval(
    r"<\%=.*request\.getParameter",  # <%= request.getParameter
    r"<jsp:include",
    r"<jsp:forward",
]

# ==================== ADVANCED LFI PATTERNS ====================
ADVANCED_LFI_PATTERNS = [
    r"/proc/self/",
    r"/proc/\d+/",
    r"/var/log/",
    r"/var/mail/",
    r"\.\./\.\./proc/",
]

# ==================== PYTHON CODE INJECTION PATTERNS ====================
PYTHON_INJECTION_PATTERNS = [
    r"__import__\s*\(",  # __import__('os')
    r"\bexec\s*\(",  # exec(code)
    r"\beval\s*\(",  # eval(code)
    r"\bcompile\s*\(",  # compile(code)
    r"os\.system",  # os.system('cmd')
    r"subprocess\.",  # subprocess.call, subprocess.Popen
    r"commands\.",  # commands.getoutput
]

# ==================== JAVA/JAR PROTOCOL PATTERNS ====================
JAR_PROTOCOL_PATTERNS = [
    r"jar:http://",  # JAR URL remote class loading
    r"jar:https://",
    r"jar:ftp://",
    r"jar:file://",
]

# ==================== GRAPHQL INJECTION PATTERNS ====================
GRAPHQL_PATTERNS = [
    r"__schema\s*\{",  # GraphQL introspection
    r"__type\s*\(",  # Type introspection
    r"__typename",  # Type name introspection
    r"query\s+IntrospectionQuery",  # Full introspection
]

# ==================== DESERIALIZATION PATTERNS ====================
DESERIALIZATION_PATTERNS = [
    r"!!python/object",  # YAML Python object deserialization
    r"O:\d+:",  # PHP serialized object: O:8:"stdClass"
    r"a:\d+:",  # PHP serialized array: a:2:{...}
    r"rO0AB",  # Java serialized (base64 encoded)
    r"\xac\xed\x00\x05",  # Java serialization magic bytes
]

# ==================== BRUTE FORCE PATTERNS ====================
BRUTE_PATTERNS = [
    r"(login|password).*(\d{6,})",
]

# Combine and compile
_default_compiled = []
for p in SQLI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'sqli'))
for p in XSS_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'xss'))
for p in CMDI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'cmdi'))
for p in PATH_TRAVERSAL_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'path-traversal'))
for p in SSRF_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'ssrf'))
for p in XXE_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'xxe'))
for p in LDAP_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'ldap'))
for p in NOSQL_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'nosql'))
for p in JNDI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'jndi'))
for p in PHP_FILTER_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'php-filter'))
for p in SSTI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'ssti'))
for p in JSP_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'jsp'))
for p in ADVANCED_LFI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'lfi'))
for p in PYTHON_INJECTION_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'python-injection'))
for p in JAR_PROTOCOL_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'jar-protocol'))
for p in GRAPHQL_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'graphql'))
for p in DESERIALIZATION_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'deserialization'))
for p in BRUTE_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'brute'))

# Allow an environment-specified additional rules file (one regex per line prefixed by kind: e.g. sqli:regex)
COMPILED_RULES = list(_default_compiled)
_rules_file = os.environ.get('BEEWAF_RULES_FILE')
if _rules_file and os.path.exists(_rules_file):
    try:
        with open(_rules_file, 'r') as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln or ln.startswith('#'):
                    continue
                if ':' in ln:
                    kind, rx = ln.split(':', 1)
                    try:
                        COMPILED_RULES.append((re.compile(rx, re.IGNORECASE), kind.strip()))
                    except re.error:
                        continue
    except Exception:
        pass

# Simple allowlist (paths that should never be blocked)
ALLOW_PATHS = os.environ.get('BEEWAF_ALLOW_PATHS', '/health,/metrics').split(',')
ALLOW_PATHS = [p.strip() for p in ALLOW_PATHS if p.strip()]


def _headers_to_text(headers: Dict[str, str]) -> str:
    # Exclude Host header to avoid false positives with 127.0.0.1:port
    return ' '.join(f"{k}:{v}" for k, v in headers.items() if k.lower() != 'host')


def check_regex_rules(path: str, body: str, headers: Dict[str, str]) -> Tuple[bool, str]:
    """Return (blocked:bool, reason:str_or_None).

    Checks request path+body+headers against compiled regex rules.
    Respects `ALLOW_PATHS`.
    """
    import urllib.parse
    
    if path in ALLOW_PATHS:
        return False, None

    # Decode URL encoding to detect obfuscated attacks
    decoded_path = urllib.parse.unquote(path or '') if path else ''
    decoded_body = urllib.parse.unquote(body or '') if body else ''
    
    # Check both original and decoded versions
    target = ' '.join([path or '', body or '', _headers_to_text(headers or {})])
    decoded_target = ' '.join([decoded_path, decoded_body, _headers_to_text(headers or {})])
    
    for pat, kind in COMPILED_RULES:
        if pat.search(target) or pat.search(decoded_target):
            return True, f"regex-{kind}"
    return False, None


def list_rules() -> List[Tuple[str, str]]:
    """Return list of (pattern, kind) for debugging/monitoring."""
    return [(p.pattern, k) for p, k in COMPILED_RULES]

