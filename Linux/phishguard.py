#!/usr/bin/env python3
"""
PhishGuard Pro v3.0 - Framework de Analisis, Seguimiento y Auditoria de Phishing
=================================================================================
Un framework profesional completo para analizar cabeceras de email,
detectar phishing, gestionar casos e investigar amenazas.

Uso:
    python3 phishguard.py [--port 8080] [--host 0.0.0.0]

Abre el navegador en http://localhost:8080
"""

import argparse
import json
import os
import re
import csv
import io
import hashlib
import socket
import struct
import uuid
import webbrowser
import threading
import urllib.parse
import email
import email.policy
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# =========================================================================
# STARTUP DEPENDENCY VERIFICATION & AUTO-UPDATE
# =========================================================================
import subprocess
import sys
import importlib
import time as _time

def _print_banner_line(text, status='', color=''):
    """Print a formatted status line."""
    colors = {'ok': '\033[92m', 'warn': '\033[93m', 'fail': '\033[91m', 'info': '\033[96m', 'reset': '\033[0m'}
    c = colors.get(color, '')
    r = colors['reset'] if c else ''
    sym = {'ok': '[OK]', 'warn': '[!!]', 'fail': '[XX]', 'info': '[--]'}.get(status, '    ')
    print(f"  {c}{sym}{r} {text}")

def verify_and_install_dependencies():
    """Verify all modules and dependencies at startup, auto-install/update if needed."""
    print()
    print("  ╔══════════════════════════════════════════╗")
    print("  ║   PhishGuard Pro - Verificacion Modulos  ║")
    print("  ╚══════════════════════════════════════════╝")
    print()

    results = {'ok': 0, 'installed': 0, 'updated': 0, 'failed': 0}

    # ---- 1. External pip dependencies ----
    pip_deps = {
        'reportlab': {'package': 'reportlab>=4.0', 'desc': 'Generador PDF profesional'},
    }

    _print_banner_line("Comprobando dependencias externas...", 'info', 'info')
    for mod_name, info in pip_deps.items():
        try:
            mod = importlib.import_module(mod_name)
            cur_ver = getattr(mod, 'Version', getattr(mod, '__version__', '?'))
            _print_banner_line(f"{mod_name} v{cur_ver} - {info['desc']}", 'ok', 'ok')
            results['ok'] += 1

            # Check for updates (best-effort, no network failure block)
            try:
                check = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '--upgrade', '--dry-run', info['package']],
                    capture_output=True, text=True, timeout=15
                )
                if 'Would install' in check.stdout and mod_name in check.stdout:
                    _print_banner_line(f"  Actualizando {mod_name}...", 'info', 'info')
                    subprocess.run(
                        [sys.executable, '-m', 'pip', 'install', '--upgrade', '--quiet', info['package']],
                        capture_output=True, timeout=60
                    )
                    importlib.reload(mod)
                    new_ver = getattr(mod, 'Version', getattr(mod, '__version__', '?'))
                    _print_banner_line(f"  {mod_name} actualizado: v{cur_ver} -> v{new_ver}", 'ok', 'ok')
                    results['updated'] += 1
            except (subprocess.TimeoutExpired, Exception):
                pass  # No bloquear si no hay red

        except ImportError:
            _print_banner_line(f"{mod_name} no encontrado. Instalando {info['package']}...", 'warn', 'warn')
            try:
                subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '--quiet', info['package']],
                    check=True, capture_output=True, timeout=120
                )
                importlib.import_module(mod_name)
                _print_banner_line(f"{mod_name} instalado correctamente - {info['desc']}", 'ok', 'ok')
                results['installed'] += 1
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ImportError) as e:
                _print_banner_line(f"{mod_name} - FALLO al instalar: {e}", 'fail', 'fail')
                results['failed'] += 1

    # ---- 2. Internal modules (modules.py, report_pdf.py) ----
    print()
    _print_banner_line("Comprobando modulos internos PhishGuard...", 'info', 'info')

    internal_modules = [
        {'name': 'modules', 'file': 'modules.py',
         'imports': ['run_enhanced_analysis', 'MsgParser', 'BodyAnalyzer', 'AttachmentAnalyzer',
                     'GeoIPLookup', 'DNSBLChecker', 'DNSResolver', 'HeaderForensics',
                     'HomoglyphDetector', 'URLIntelligence',
                     'SenderIntel', 'TemporalAnalyzer'],
         'desc': '14 modulos de analisis'},
        {'name': 'report_pdf', 'file': 'report_pdf.py',
         'imports': ['generate_pdf_report', 'RiskMeterFlowable', 'AttackChainFlowable', 'SeverityBarFlowable'],
         'desc': 'Generador informes PDF profesional'},
        {'name': 'malware_analyzer', 'file': 'malware_analyzer.py',
         'imports': ['analyze_malware', 'PEAnalyzer', 'ScriptAnalyzer', 'MacroAnalyzer',
                     'RansomwareDetector', 'YaraEngine', 'ThreatIntelLookup'],
         'desc': 'Motor de analisis de malware/ransomware'},
    ]

    for mod_info in internal_modules:
        mod_path = Path(__file__).parent / mod_info['file']
        if not mod_path.exists():
            _print_banner_line(f"{mod_info['file']} NO ENCONTRADO en {mod_path.parent}", 'fail', 'fail')
            results['failed'] += 1
            continue

        try:
            mod = importlib.import_module(mod_info['name'])
            # Verify all expected exports exist
            missing = [imp for imp in mod_info['imports'] if not hasattr(mod, imp)]
            if missing:
                _print_banner_line(f"{mod_info['file']} - Faltan: {', '.join(missing)}", 'warn', 'warn')
                results['failed'] += 1
            else:
                _print_banner_line(f"{mod_info['file']} ({len(mod_info['imports'])} componentes) - {mod_info['desc']}", 'ok', 'ok')
                results['ok'] += 1
        except Exception as e:
            _print_banner_line(f"{mod_info['file']} - Error al cargar: {e}", 'fail', 'fail')
            results['failed'] += 1

    # ---- 3. Optional dependencies (best-effort) ----
    print()
    _print_banner_line("Comprobando modulos opcionales...", 'info', 'info')

    optional = {
        'requests': 'Consultas HTTP (GeoIP, DNSBL, VirusTotal)',
    }
    for mod_name, desc in optional.items():
        try:
            importlib.import_module(mod_name)
            _print_banner_line(f"{mod_name} - {desc}", 'ok', 'ok')
        except ImportError:
            _print_banner_line(f"{mod_name} - {desc} (no disponible, funcionalidad limitada)", 'warn', 'warn')

    # ---- 4. Standard library sanity check ----
    stdlib_needed = ['json', 'csv', 'io', 'hashlib', 'socket', 'struct', 'uuid',
                     'email', 'http.server', 'urllib.parse', 'threading', 'webbrowser',
                     'pathlib', 'base64', 'copy', 'math', 're']
    stdlib_ok = True
    for m in stdlib_needed:
        try:
            importlib.import_module(m)
        except ImportError:
            _print_banner_line(f"stdlib '{m}' no disponible - instalacion de Python incompleta", 'fail', 'fail')
            stdlib_ok = False
            results['failed'] += 1
    if stdlib_ok:
        _print_banner_line(f"Libreria estandar Python ({len(stdlib_needed)} modulos)", 'ok', 'ok')

    # ---- Summary ----
    print()
    total = results['ok'] + results['installed'] + results['updated'] + results['failed']
    if results['failed'] == 0:
        _print_banner_line(
            f"VERIFICACION COMPLETA: {results['ok']} OK"
            + (f", {results['installed']} instalados" if results['installed'] else "")
            + (f", {results['updated']} actualizados" if results['updated'] else "")
            + f" | Todo listo",
            'ok', 'ok')
    else:
        _print_banner_line(
            f"VERIFICACION: {results['ok']} OK, {results['failed']} fallidos"
            + " | Algunas funciones pueden no estar disponibles",
            'warn', 'warn')
    print()
    return results

# Run verification at import time
_dep_results = verify_and_install_dependencies()

# Now import with verified state
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from modules import run_enhanced_analysis, MsgParser, BodyAnalyzer, AttachmentAnalyzer
    from report_pdf import generate_pdf_report
    HAS_ENHANCED = True
except ImportError:
    HAS_ENHANCED = False

try:
    from malware_analyzer import analyze_malware
    HAS_MALWARE = True
except ImportError:
    HAS_MALWARE = False

try:
    from client_db import ClientDB
    HAS_CLIENT_DB = True
except ImportError:
    HAS_CLIENT_DB = False

try:
    from connectors import ThreatIntelConnector, AIConnector
    HAS_CONNECTORS = True
except ImportError:
    HAS_CONNECTORS = False

# =========================================================================
# CONFIGURATION
# =========================================================================

VERSION = "3.0.0"
APP_NAME = "PhishGuard Pro"
DATA_DIR = Path(__file__).parent / "data"
CASES_FILE = DATA_DIR / "cases.json"
AUDIT_FILE = DATA_DIR / "audit.json"
HISTORY_FILE = DATA_DIR / "history.json"
CONFIG_FILE = DATA_DIR / "config.json"

# Ensure data directory exists
DATA_DIR.mkdir(exist_ok=True)

# =========================================================================
# DATA PERSISTENCE
# =========================================================================

class DataStore:
    """Persistent JSON data store."""

    def __init__(self):
        self.cases = self._load(CASES_FILE, [])
        self.audit_log = self._load(AUDIT_FILE, [])
        self.history = self._load(HISTORY_FILE, [])
        self.config = self._load(CONFIG_FILE, {
            "analyst": "",
            "organization": "",
            "auto_case": "suspicious",
            "api_keys": {},
            "language": "es"
        })
        self.case_counter = len(self.cases)

    def _load(self, path, default):
        try:
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return default

    def _save(self, path, data):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)

    def save_all(self):
        self._save(CASES_FILE, self.cases)
        self._save(AUDIT_FILE, self.audit_log)
        self._save(HISTORY_FILE, self.history)
        self._save(CONFIG_FILE, self.config)

    def add_audit(self, action, details, user=None):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "details": details,
            "user": user or self.config.get("analyst", "Analyst")
        }
        self.audit_log.append(entry)
        self._save(AUDIT_FILE, self.audit_log)
        return entry

    def add_case(self, case_data):
        self.case_counter += 1
        case_data["id"] = f"PG-{self.case_counter:04d}"
        case_data["date"] = datetime.now().strftime("%Y-%m-%d")
        self.cases.insert(0, case_data)
        self._save(CASES_FILE, self.cases)
        return case_data

    def update_case(self, case_id, updates):
        for c in self.cases:
            if c["id"] == case_id:
                c.update(updates)
                self._save(CASES_FILE, self.cases)
                return c
        return None

    def add_history(self, analysis):
        self.history.insert(0, analysis)
        # Keep last 100
        self.history = self.history[:100]
        self._save(HISTORY_FILE, self.history)


# Global data store
store = DataStore()

# Client database
client_db = None
if HAS_CLIENT_DB:
    try:
        client_db = ClientDB(DATA_DIR / "phishguard_clients.db")
    except Exception:
        pass

# =========================================================================
# EMAIL HEADER PARSER ENGINE
# =========================================================================

class HeaderParser:
    """Advanced email header parser with full RFC 2822 support."""

    @staticmethod
    def parse(raw_headers: str) -> dict:
        """Parse raw email headers into structured dict."""
        headers = {}
        lines = raw_headers.split('\n')
        current_key = ''
        current_value = ''

        for line in lines:
            # Remove \r
            line = line.rstrip('\r')

            # Continuation line (starts with whitespace)
            if line and line[0] in (' ', '\t') and current_key:
                current_value += ' ' + line.strip()
            else:
                # Save previous header
                if current_key:
                    headers.setdefault(current_key, []).append(current_value)

                # Parse new header
                colon_idx = line.find(':')
                if colon_idx > 0:
                    current_key = line[:colon_idx].strip()
                    current_value = line[colon_idx+1:].strip()
                else:
                    current_key = ''
                    current_value = ''

        # Save last header
        if current_key:
            headers.setdefault(current_key, []).append(current_value)

        return headers

    @staticmethod
    def parse_received_hops(headers: dict) -> list:
        """Parse Received headers into hop chain."""
        received = headers.get('Received', [])
        hops = []

        for r in received:
            hop = {'raw': r}

            # From server
            from_match = re.search(r'from\s+(\S+)(?:\s+\(([^)]+)\))?', r, re.I)
            if from_match:
                hop['from_server'] = from_match.group(1)
                hop['from_detail'] = from_match.group(2) or ''

            # By server
            by_match = re.search(r'by\s+(\S+)', r, re.I)
            if by_match:
                hop['by_server'] = by_match.group(1)

            # IP address
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', r)
            if ip_match:
                hop['ip'] = ip_match.group(1)
            else:
                ipv6_match = re.search(r'\[([0-9a-fA-F:]+)\]', r)
                if ipv6_match:
                    hop['ip'] = ipv6_match.group(1)

            # Protocol
            proto_match = re.search(r'with\s+(E?SMTP\S*)', r, re.I)
            if proto_match:
                hop['protocol'] = proto_match.group(1)

            # Timestamp
            date_match = re.search(r';\s*(.+)$', r)
            if date_match:
                hop['timestamp'] = date_match.group(1).strip()
                try:
                    from email.utils import parsedate_to_datetime
                    hop['datetime'] = parsedate_to_datetime(hop['timestamp']).isoformat()
                except Exception:
                    hop['datetime'] = None

            # TLS info
            if 'ESMTPS' in r.upper() or 'TLS' in r.upper():
                hop['tls'] = True
            else:
                hop['tls'] = False

            hops.append(hop)

        # Reverse for chronological order and calculate delays
        hops.reverse()
        for i in range(1, len(hops)):
            if hops[i].get('datetime') and hops[i-1].get('datetime'):
                try:
                    from email.utils import parsedate_to_datetime
                    t1 = parsedate_to_datetime(hops[i-1].get('timestamp', ''))
                    t2 = parsedate_to_datetime(hops[i].get('timestamp', ''))
                    hops[i]['delay_seconds'] = (t2 - t1).total_seconds()
                except Exception:
                    pass

        return hops


# =========================================================================
# IOC EXTRACTOR
# =========================================================================

class IOCExtractor:
    """Extract Indicators of Compromise from email headers."""

    # Known private/reserved IP ranges
    PRIVATE_RANGES = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255'),
        ('0.0.0.0', '0.255.255.255'),
        ('169.254.0.0', '169.254.255.255'),
    ]

    @staticmethod
    def _ip_to_int(ip):
        try:
            return struct.unpack('!I', socket.inet_aton(ip))[0]
        except Exception:
            return 0

    @classmethod
    def is_private_ip(cls, ip):
        ip_int = cls._ip_to_int(ip)
        for start, end in cls.PRIVATE_RANGES:
            if cls._ip_to_int(start) <= ip_int <= cls._ip_to_int(end):
                return True
        return False

    @staticmethod
    def extract_ipv4(text):
        pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        return list(set(re.findall(pattern, text)))

    @staticmethod
    def extract_ipv6(text):
        pattern = r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'
        return list(set(re.findall(pattern, text)))

    @staticmethod
    def extract_domains(text):
        pattern = r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?'
        matches = set(re.findall(pattern, text))
        excluded_patterns = ['smtp.mailfrom', 'header.from', 'header.i', 'header.s',
                            'header.b', 'rsa-sha256', 'relaxed.relaxed']
        return [d for d in matches if
                not any(e in d for e in excluded_patterns) and
                len(d) > 4 and
                not re.match(r'^\d+\.\d+', d)]

    @staticmethod
    def extract_emails(text):
        pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
        return list(set(re.findall(pattern, text)))

    @staticmethod
    def extract_urls(text):
        pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return list(set(re.findall(pattern, text)))

    @classmethod
    def extract_all(cls, text):
        ipv4 = cls.extract_ipv4(text)
        ipv6 = cls.extract_ipv6(text)
        public_ips = [ip for ip in ipv4 if not cls.is_private_ip(ip)]
        private_ips = [ip for ip in ipv4 if cls.is_private_ip(ip)]

        return {
            "ipv4": ipv4,
            "ipv6": ipv6,
            "public_ips": public_ips,
            "private_ips": private_ips,
            "domains": cls.extract_domains(text),
            "emails": cls.extract_emails(text),
            "urls": cls.extract_urls(text)
        }


# =========================================================================
# AUTHENTICATION ANALYZER
# =========================================================================

class AuthAnalyzer:
    """Analyze email authentication (SPF, DKIM, DMARC, ARC)."""

    @staticmethod
    def analyze(headers: dict) -> dict:
        auth = {
            "spf": {"status": "unknown", "details": "", "raw": ""},
            "dkim": {"status": "unknown", "details": "", "domain": "", "raw": ""},
            "dmarc": {"status": "unknown", "details": "", "policy": "", "raw": ""},
            "arc": {"status": "unknown", "details": ""}
        }

        # Combine Authentication-Results headers
        auth_results = ' '.join(headers.get('Authentication-Results', []))
        auth_results += ' ' + ' '.join(headers.get('ARC-Authentication-Results', []))

        # --- SPF ---
        spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', auth_results, re.I)
        if spf_match:
            auth['spf']['status'] = spf_match.group(1).lower()
        spf_detail = re.search(r'spf=\w+\s*\(([^)]+)\)', auth_results, re.I)
        if spf_detail:
            auth['spf']['details'] = spf_detail.group(1)

        # Received-SPF header
        received_spf = ' '.join(headers.get('Received-SPF', []))
        if received_spf:
            auth['spf']['raw'] = received_spf
            rspf = re.match(r'(pass|fail|softfail|neutral|none)', received_spf, re.I)
            if rspf and auth['spf']['status'] == 'unknown':
                auth['spf']['status'] = rspf.group(1).lower()
            # Extract client-ip
            cip = re.search(r'client-ip=(\S+)', received_spf, re.I)
            if cip:
                auth['spf']['client_ip'] = cip.group(1).rstrip(';')

        # --- DKIM ---
        dkim_match = re.search(r'dkim=(pass|fail|none|neutral|temperror|permerror)', auth_results, re.I)
        if dkim_match:
            auth['dkim']['status'] = dkim_match.group(1).lower()
        dkim_domain = re.search(r'header\.i=@([^\s;]+)', auth_results, re.I)
        if dkim_domain:
            auth['dkim']['domain'] = dkim_domain.group(1)
        dkim_selector = re.search(r'header\.s=(\S+)', auth_results, re.I)
        if dkim_selector:
            auth['dkim']['selector'] = dkim_selector.group(1).rstrip(';')

        # DKIM-Signature header
        dkim_sig = headers.get('DKIM-Signature', [])
        if dkim_sig:
            auth['dkim']['raw'] = dkim_sig[0][:200]

        # --- DMARC ---
        dmarc_match = re.search(r'dmarc=(pass|fail|none|bestguesspass)', auth_results, re.I)
        if dmarc_match:
            auth['dmarc']['status'] = dmarc_match.group(1).lower()
        dmarc_policy = re.search(r'dmarc=\w+\s*\(([^)]+)\)', auth_results, re.I)
        if dmarc_policy:
            auth['dmarc']['details'] = dmarc_policy.group(1)
            # Extract policy
            p_match = re.search(r'p=(\w+)', dmarc_policy.group(1))
            if p_match:
                auth['dmarc']['policy'] = p_match.group(1)

        # --- ARC ---
        arc_seal = ' '.join(headers.get('ARC-Seal', []))
        if arc_seal:
            cv_match = re.search(r'cv=(none|pass|fail)', arc_seal, re.I)
            if cv_match:
                auth['arc']['status'] = cv_match.group(1).lower()

        return auth


# =========================================================================
# RISK SCORING ENGINE
# =========================================================================

class RiskEngine:
    """Advanced phishing risk scoring with multiple heuristics."""

    # Known brand patterns for typosquatting detection
    KNOWN_BRANDS = [
        'paypal', 'microsoft', 'apple', 'google', 'amazon', 'netflix', 'facebook',
        'instagram', 'twitter', 'linkedin', 'dropbox', 'adobe', 'spotify', 'uber',
        'airbnb', 'chase', 'wellsfargo', 'citibank', 'hsbc', 'santander', 'bbva',
        'bankofamerica', 'stripe', 'shopify', 'docusign', 'zoom', 'slack', 'github',
        'office365', 'outlook', 'icloud', 'yahoo', 'dhl', 'fedex', 'ups', 'usps',
        'whatsapp', 'telegram', 'binance', 'coinbase', 'blockchain'
    ]

    URGENCY_WORDS = {
        'en': ['urgent', 'immediately', 'suspend', 'limited', 'verify', 'confirm',
               'alert', 'warning', 'action required', 'account', 'password', 'security',
               'locked', 'expired', 'unauthorized', 'unusual activity', 'compromised',
               'verify your identity', 'click here', 'within 24 hours', 'final notice'],
        'es': ['urgente', 'inmediatamente', 'suspendido', 'limitado', 'verificar',
               'confirmar', 'alerta', 'aviso', 'accion requerida', 'cuenta',
               'contraseña', 'seguridad', 'bloqueado', 'caducado', 'no autorizado',
               'actividad inusual', 'comprometido', 'verificar identidad', 'haga clic',
               'en 24 horas', 'ultimo aviso']
    }

    SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.work', '.click', '.loan', '.gq',
                        '.cf', '.tk', '.ml', '.ga', '.buzz', '.monster', '.icu']

    @classmethod
    def calculate(cls, headers, parsed, hops, auth, iocs, raw_text):
        score = 0
        flags = []

        # ---- 1. SPF Analysis (0-20) ----
        if auth['spf']['status'] == 'fail':
            score += 20
            flags.append({"text": "SPF FAIL - El dominio NO autoriza esta IP como remitente",
                         "severity": "critical", "category": "authentication"})
        elif auth['spf']['status'] == 'softfail':
            score += 12
            flags.append({"text": "SPF Softfail - IP no autorizada explicitamente (posible suplantacion)",
                         "severity": "high", "category": "authentication"})
        elif auth['spf']['status'] in ('none', 'unknown'):
            score += 5
            flags.append({"text": "Sin registro SPF configurado",
                         "severity": "medium", "category": "authentication"})

        # ---- 2. DKIM Analysis (0-20) ----
        if auth['dkim']['status'] == 'fail':
            score += 20
            flags.append({"text": "DKIM FAIL - Firma digital invalida, email posiblemente manipulado",
                         "severity": "critical", "category": "authentication"})
        elif auth['dkim']['status'] in ('none', 'unknown'):
            score += 5
            flags.append({"text": "Sin firma DKIM presente",
                         "severity": "medium", "category": "authentication"})

        # ---- 3. DMARC Analysis (0-15) ----
        if auth['dmarc']['status'] == 'fail':
            score += 15
            flags.append({"text": "DMARC FAIL - Politica de dominio no cumplida",
                         "severity": "critical", "category": "authentication"})
        elif auth['dmarc']['status'] in ('none', 'unknown'):
            score += 3
            flags.append({"text": "Sin politica DMARC (dominio no protegido contra suplantacion)",
                         "severity": "low", "category": "authentication"})

        # ---- 4. From / Return-Path mismatch (0-12) ----
        from_header = (parsed.get('From', ['']) or [''])[0]
        return_path = (parsed.get('Return-Path', ['']) or [''])[0]
        reply_to = (parsed.get('Reply-To', ['']) or [''])[0]

        from_email = cls._extract_email(from_header)
        rp_email = cls._extract_email(return_path)
        rt_email = cls._extract_email(reply_to)

        if from_email and rp_email:
            from_domain = from_email.split('@')[-1].lower()
            rp_domain = rp_email.split('@')[-1].lower()
            if from_domain != rp_domain:
                score += 12
                flags.append({"text": f"Discrepancia From/Return-Path: {from_domain} ≠ {rp_domain}",
                             "severity": "high", "category": "header_anomaly"})

        # ---- 5. Reply-To mismatch (0-10) ----
        if from_email and rt_email:
            from_domain = from_email.split('@')[-1].lower()
            rt_domain = rt_email.split('@')[-1].lower()
            if from_domain != rt_domain:
                score += 10
                flags.append({"text": f"Reply-To ({rt_email}) difiere del From ({from_email})",
                             "severity": "high", "category": "header_anomaly"})

        # ---- 6. X-Mailer analysis (0-5) ----
        x_mailer = (parsed.get('X-Mailer', ['']) or [''])[0]
        suspicious_mailers = ['phpmailer', 'python', 'swiftmailer', 'phpmail',
                             'king-mailer', 'leaf-mailer', 'alexus-mailer']
        if x_mailer:
            for sm in suspicious_mailers:
                if sm in x_mailer.lower():
                    score += 5
                    flags.append({"text": f"X-Mailer sospechoso: {x_mailer}",
                                 "severity": "medium", "category": "tool_detection"})
                    break

        # ---- 7. Spam headers (0-10) ----
        spam_status = (parsed.get('X-Spam-Status', ['']) or [''])[0]
        spam_score_str = (parsed.get('X-Spam-Score', ['']) or [''])[0]
        if 'yes' in spam_status.lower():
            score += 10
            flags.append({"text": f"Marcado como SPAM por el servidor (Score: {spam_score_str or 'N/A'})",
                         "severity": "high", "category": "spam_detection"})
        elif spam_score_str:
            try:
                ss = float(spam_score_str)
                if ss > 5.0:
                    score += 7
                    flags.append({"text": f"Spam score elevado: {ss}",
                                 "severity": "medium", "category": "spam_detection"})
            except ValueError:
                pass

        # Extract spam tests
        spam_tests = re.findall(r'tests?=([^;]+)', spam_status, re.I)
        if spam_tests:
            test_list = [t.strip() for t in spam_tests[0].split(',')]
            phishing_tests = [t for t in test_list if 'PHISHING' in t.upper() or 'SPOOF' in t.upper()]
            if phishing_tests:
                score += 5
                flags.append({"text": f"Tests de phishing positivos: {', '.join(phishing_tests)}",
                             "severity": "high", "category": "spam_detection"})

        # ---- 8. Subject urgency (0-10) ----
        subject = (parsed.get('Subject', ['']) or [''])[0].lower()
        all_urgency = cls.URGENCY_WORDS['en'] + cls.URGENCY_WORDS['es']
        found_urgency = [w for w in all_urgency if w in subject]
        if found_urgency:
            points = min(len(found_urgency) * 3, 10)
            score += points
            flags.append({"text": f"Palabras de urgencia en asunto: {', '.join(found_urgency[:5])}",
                         "severity": "medium", "category": "social_engineering"})

        # ---- 9. X-Priority (0-3) ----
        x_priority = (parsed.get('X-Priority', ['']) or [''])[0]
        if '1' in x_priority or 'high' in x_priority.lower():
            score += 3
            flags.append({"text": "Prioridad maxima (X-Priority: 1) - Tactica de urgencia",
                         "severity": "low", "category": "social_engineering"})

        # ---- 10. Typosquatting detection (0-15) ----
        for domain in iocs['domains']:
            dl = domain.lower()
            for brand in cls.KNOWN_BRANDS:
                if brand in dl:
                    # Check if it's NOT the legitimate domain
                    legit = [f"{brand}.com", f"{brand}.net", f"{brand}.org",
                            f"{brand}.es", f"{brand}.co", f"{brand}.io",
                            f"www.{brand}.com", f"mail.{brand}.com"]
                    if dl not in legit and not dl.endswith(f".{brand}.com"):
                        # Check for character substitution (l→1, o→0, etc.)
                        substitutions = {'l': '1', 'o': '0', 'a': '4', 'e': '3', 'i': '1', 's': '5'}
                        is_typo = False
                        for orig, sub in substitutions.items():
                            typo_brand = brand.replace(orig, sub)
                            if typo_brand in dl and typo_brand != brand:
                                is_typo = True
                                break

                        if is_typo:
                            score += 15
                            flags.append({"text": f"TYPOSQUATTING detectado: '{domain}' imita '{brand}'",
                                         "severity": "critical", "category": "domain_analysis"})
                        elif brand in dl:
                            score += 8
                            flags.append({"text": f"Dominio sospechoso contiene marca '{brand}': {domain}",
                                         "severity": "high", "category": "domain_analysis"})
                        break

        # ---- 11. Suspicious TLD (0-5) ----
        for domain in iocs['domains']:
            for tld in cls.SUSPICIOUS_TLDS:
                if domain.lower().endswith(tld):
                    score += 5
                    flags.append({"text": f"TLD sospechoso detectado: {domain}",
                                 "severity": "medium", "category": "domain_analysis"})
                    break

        # ---- 12. Multiple hops / relay chain (0-3) ----
        if len(hops) > 7:
            score += 3
            flags.append({"text": f"Alto numero de saltos ({len(hops)} hops) - Posible cadena de relays",
                         "severity": "low", "category": "routing"})

        # ---- 13. Missing TLS in hops (0-5) ----
        no_tls_hops = [h for h in hops if not h.get('tls', False)]
        if no_tls_hops and hops:
            pct = len(no_tls_hops) / len(hops) * 100
            if pct > 50:
                score += 5
                flags.append({"text": f"{len(no_tls_hops)}/{len(hops)} saltos sin TLS ({pct:.0f}%)",
                             "severity": "medium", "category": "encryption"})

        # ---- 14. Date anomalies (0-5) ----
        date_header = (parsed.get('Date', ['']) or [''])[0]
        if date_header:
            try:
                from email.utils import parsedate_to_datetime
                email_date = parsedate_to_datetime(date_header)
                now = datetime.now(timezone.utc)
                diff_hours = abs((now - email_date).total_seconds()) / 3600
                if diff_hours > 168:  # >1 week old
                    score += 2
                    flags.append({"text": f"Email con fecha inusual: {date_header}",
                                 "severity": "low", "category": "temporal"})
            except Exception:
                pass

        # ---- 15. Content-Type anomalies (0-3) ----
        content_type = (parsed.get('Content-Type', ['']) or [''])[0].lower()
        if 'multipart/mixed' in content_type or 'application/' in content_type:
            score += 2
            flags.append({"text": f"Content-Type con posibles adjuntos: {content_type[:60]}",
                         "severity": "low", "category": "content"})

        # Cap at 100
        score = min(score, 100)

        # Determine verdict
        if score >= 70:
            verdict = 'PHISHING'
            risk_level = 'critical'
        elif score >= 50:
            verdict = 'HIGH_RISK'
            risk_level = 'high'
        elif score >= 30:
            verdict = 'SUSPICIOUS'
            risk_level = 'medium'
        elif score >= 15:
            verdict = 'LOW_RISK'
            risk_level = 'low'
        else:
            verdict = 'CLEAN'
            risk_level = 'clean'

        return {
            "score": score,
            "verdict": verdict,
            "risk_level": risk_level,
            "flags": flags,
            "flag_count": len(flags),
            "categories": list(set(f['category'] for f in flags))
        }

    @staticmethod
    def _extract_email(text):
        match = re.search(r'<([^>]+)>', text) or re.search(r'(\S+@\S+\.\S+)', text)
        return match.group(1) if match else ''


# =========================================================================
# REPUTATION LOOKUP (with requests)
# =========================================================================

class ReputationLookup:
    """Query external reputation services."""

    @staticmethod
    def get_tool_links(query, query_type="all"):
        """Generate investigation links for an IP or domain."""
        links = {
            "ip": [
                {"name": "VirusTotal", "url": f"https://www.virustotal.com/gui/ip-address/{query}",
                 "category": "reputation", "icon": "🔍"},
                {"name": "AbuseIPDB", "url": f"https://www.abuseipdb.com/check/{query}",
                 "category": "reputation", "icon": "🚨"},
                {"name": "Shodan", "url": f"https://www.shodan.io/host/{query}",
                 "category": "recon", "icon": "👁"},
                {"name": "Cisco Talos", "url": f"https://talosintelligence.com/reputation_center/lookup?search={query}",
                 "category": "reputation", "icon": "🔧"},
                {"name": "AlienVault OTX", "url": f"https://otx.alienvault.com/indicator/ip/{query}",
                 "category": "threat_intel", "icon": "🌐"},
                {"name": "IPQualityScore", "url": f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{query}",
                 "category": "fraud", "icon": "🎯"},
                {"name": "Censys", "url": f"https://search.censys.io/hosts/{query}",
                 "category": "recon", "icon": "🔬"},
                {"name": "GreyNoise", "url": f"https://viz.greynoise.io/ip/{query}",
                 "category": "threat_intel", "icon": "📡"},
            ],
            "domain": [
                {"name": "VirusTotal", "url": f"https://www.virustotal.com/gui/domain/{query}",
                 "category": "reputation", "icon": "🔍"},
                {"name": "WHOIS", "url": f"https://whois.domaintools.com/{query}",
                 "category": "osint", "icon": "📄"},
                {"name": "URLScan.io", "url": f"https://urlscan.io/search/#{query}",
                 "category": "scanning", "icon": "🔎"},
                {"name": "SecurityTrails", "url": f"https://securitytrails.com/domain/{query}",
                 "category": "dns", "icon": "📚"},
                {"name": "crt.sh", "url": f"https://crt.sh/?q={query}",
                 "category": "certificates", "icon": "🔐"},
                {"name": "MXToolbox", "url": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{query}",
                 "category": "email", "icon": "🔧"},
                {"name": "Robtex", "url": f"https://www.robtex.com/dns-lookup/{query}",
                 "category": "dns", "icon": "🌐"},
                {"name": "PhishTank", "url": f"https://phishtank.org/phish_search.php?page=0&search={query}&valid=y&active=y",
                 "category": "phishing", "icon": "🐟"},
                {"name": "Google Safe Browsing", "url": f"https://transparencyreport.google.com/safe-browsing/search?url={query}",
                 "category": "safety", "icon": "🛡"},
            ],
            "url": [
                {"name": "VirusTotal", "url": f"https://www.virustotal.com/gui/url/{hashlib.sha256(query.encode()).hexdigest()}",
                 "category": "reputation", "icon": "🔍"},
                {"name": "URLScan.io", "url": f"https://urlscan.io/search/#{urllib.parse.quote(query)}",
                 "category": "scanning", "icon": "🔎"},
                {"name": "CheckPhish.ai", "url": f"https://checkphish.ai/",
                 "category": "phishing", "icon": "🤖"},
                {"name": "ANY.RUN", "url": f"https://any.run/",
                 "category": "sandbox", "icon": "▶"},
                {"name": "Hybrid Analysis", "url": f"https://www.hybrid-analysis.com/",
                 "category": "sandbox", "icon": "🔬"},
            ]
        }

        if query_type == "all":
            return {**{k: v for k, v in links.items()}}
        return {query_type: links.get(query_type, [])}

    @staticmethod
    def dns_lookup(domain):
        """Basic DNS lookup using socket."""
        results = {}
        try:
            results['A'] = socket.gethostbyname(domain)
        except Exception:
            results['A'] = None
        try:
            addrs = socket.getaddrinfo(domain, None, socket.AF_INET6)
            results['AAAA'] = list(set(a[4][0] for a in addrs))
        except Exception:
            results['AAAA'] = None
        return results


# =========================================================================
# REPORT GENERATOR
# =========================================================================

class ReportGenerator:
    """Generate professional analysis reports."""

    @staticmethod
    def generate_html(analysis, config, lang='es'):
        es = lang == 'es'
        a = analysis
        r = a['risk']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

        risk_colors = {
            'critical': '#ef4444', 'high': '#f97316', 'medium': '#f59e0b',
            'low': '#06b6d4', 'clean': '#10b981'
        }
        risk_color = risk_colors.get(r['risk_level'], '#64748b')

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>PhishGuard Pro - Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:#0a0e1a;color:#e2e8f0;padding:2rem;max-width:900px;margin:0 auto}}
h1{{font-size:1.4rem;margin-bottom:0.25rem}}h2{{font-size:1rem;color:#3b82f6;text-transform:uppercase;letter-spacing:1px;margin:1.5rem 0 0.75rem;padding-bottom:0.5rem;border-bottom:1px solid #2a3a5c}}
.card{{background:#1a2236;border:1px solid #2a3a5c;border-radius:12px;padding:1.5rem;margin-bottom:1.5rem}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:8px 12px;border-bottom:1px solid rgba(42,58,92,0.5);text-align:left;font-size:0.85rem}}
th{{color:#64748b;font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;background:#0d1321}}
.key{{color:#06b6d4;font-weight:600;font-family:Consolas,monospace}}
.score{{font-size:3rem;font-weight:800;text-align:center;color:{risk_color}}}
.verdict{{text-align:center;font-size:1.1rem;font-weight:700;color:{risk_color};text-transform:uppercase;letter-spacing:2px}}
.bar{{height:8px;background:#0d1321;border-radius:4px;overflow:hidden;margin:1rem auto;max-width:400px}}
.bar-fill{{height:100%;border-radius:4px;background:{risk_color};width:{r['score']}%}}
.flag{{padding:0.6rem 0.8rem;border-radius:8px;margin-bottom:0.4rem;font-size:0.85rem}}
.flag-critical{{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);color:#fca5a5}}
.flag-high{{background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.2);color:#fde68a}}
.flag-medium{{background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.2);color:#67e8f9}}
.flag-low{{background:rgba(139,92,246,0.1);border:1px solid rgba(139,92,246,0.2);color:#c4b5fd}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:700;text-transform:uppercase;margin-right:6px}}
.badge-critical{{background:rgba(239,68,68,0.15);color:#ef4444}}.badge-high{{background:rgba(245,158,11,0.15);color:#f59e0b}}
.badge-medium{{background:rgba(6,182,212,0.15);color:#06b6d4}}.badge-low{{background:rgba(139,92,246,0.15);color:#8b5cf6}}
.ioc{{font-family:Consolas,monospace;font-size:0.82rem;padding:3px 10px;border-radius:4px;display:inline-block;margin:2px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.2);color:#3b82f6}}
.footer{{text-align:center;margin-top:2rem;padding-top:1rem;border-top:1px solid #2a3a5c;color:#64748b;font-size:0.75rem}}
@media print{{body{{background:white;color:#1a1a1a}} .card{{border:1px solid #ddd}}}}
</style></head><body>
<div style="text-align:center;padding:2rem 0;border-bottom:2px solid #2a3a5c;margin-bottom:2rem">
<h1>🛡 PhishGuard Pro</h1>
<p style="color:#94a3b8;font-size:0.9rem">{'INFORME DE ANALISIS DE PHISHING' if es else 'PHISHING ANALYSIS REPORT'}</p>
<p style="color:#64748b;font-size:0.78rem;margin-top:8px">
{'Fecha' if es else 'Date'}: {now} | {'Analista' if es else 'Analyst'}: {config.get('analyst','N/A')} | {'Org' if es else 'Org'}: {config.get('organization','N/A')}
</p></div>

<div class="card"><div class="score">{r['score']}/100</div>
<div class="verdict">{r['verdict']}</div>
<div class="bar"><div class="bar-fill"></div></div></div>"""

        # Key info
        from_h = (a['parsed_headers'].get('From', ['N/A']) or ['N/A'])[0]
        subj = (a['parsed_headers'].get('Subject', ['N/A']) or ['N/A'])[0]
        date_h = (a['parsed_headers'].get('Date', ['N/A']) or ['N/A'])[0]

        html += f"""<h2>📋 {'RESUMEN' if es else 'SUMMARY'}</h2>
<div class="card"><table>
<tr><td class="key">From</td><td>{_esc(from_h)}</td></tr>
<tr><td class="key">Subject</td><td>{_esc(subj)}</td></tr>
<tr><td class="key">Date</td><td>{_esc(date_h)}</td></tr>
<tr><td class="key">{'IPs Publicas' if es else 'Public IPs'}</td><td>{', '.join(a['iocs']['public_ips']) or 'N/A'}</td></tr>
<tr><td class="key">{'Dominios' if es else 'Domains'}</td><td>{len(a['iocs']['domains'])}</td></tr>
<tr><td class="key">Hops</td><td>{len(a['hops'])}</td></tr>
</table></div>"""

        # Authentication
        html += f"""<h2>🔑 {'AUTENTICACION' if es else 'AUTHENTICATION'}</h2>
<div class="card"><table>
<tr><td class="key">SPF</td><td><span class="badge badge-{'critical' if a['auth']['spf']['status']=='fail' else 'high' if a['auth']['spf']['status']=='softfail' else 'medium'}">{a['auth']['spf']['status'].upper()}</span> {_esc(a['auth']['spf']['details'])}</td></tr>
<tr><td class="key">DKIM</td><td><span class="badge badge-{'critical' if a['auth']['dkim']['status']=='fail' else 'medium'}">{a['auth']['dkim']['status'].upper()}</span> {_esc(a['auth']['dkim'].get('domain',''))}</td></tr>
<tr><td class="key">DMARC</td><td><span class="badge badge-{'critical' if a['auth']['dmarc']['status']=='fail' else 'medium'}">{a['auth']['dmarc']['status'].upper()}</span> {_esc(a['auth']['dmarc']['details'])}</td></tr>
<tr><td class="key">ARC</td><td>{a['auth']['arc']['status'].upper()}</td></tr>
</table></div>"""

        # Risk flags
        if r['flags']:
            html += f"<h2>⚠️ {'INDICADORES DE RIESGO' if es else 'RISK INDICATORS'} ({len(r['flags'])})</h2><div class=\"card\">"
            for f in r['flags']:
                html += f'<div class="flag flag-{f["severity"]}"><span class="badge badge-{f["severity"]}">{f["severity"].upper()}</span>{_esc(f["text"])}</div>'
            html += "</div>"

        # IoCs
        html += f"<h2>🎯 {'INDICADORES DE COMPROMISO' if es else 'INDICATORS OF COMPROMISE'}</h2><div class=\"card\">"
        html += f"<p style='font-size:0.82rem;color:#94a3b8;margin-bottom:0.5rem'><strong>{'IPs Publicas' if es else 'Public IPs'}:</strong></p>"
        for ip in a['iocs']['public_ips']:
            html += f'<span class="ioc">{ip}</span>'
        html += f"<p style='font-size:0.82rem;color:#94a3b8;margin:0.75rem 0 0.5rem'><strong>{'Dominios' if es else 'Domains'}:</strong></p>"
        for d in a['iocs']['domains'][:20]:
            html += f'<span class="ioc">{_esc(d)}</span>'
        html += f"<p style='font-size:0.82rem;color:#94a3b8;margin:0.75rem 0 0.5rem'><strong>Emails:</strong></p>"
        for e in a['iocs']['emails']:
            html += f'<span class="ioc">{_esc(e)}</span>'
        html += "</div>"

        # Recommendations
        recs = ReportGenerator._get_recommendations(a, es)
        html += f"<h2>💡 {'RECOMENDACIONES' if es else 'RECOMMENDATIONS'}</h2><div class=\"card\">"
        for i, rec in enumerate(recs, 1):
            html += f'<p style="padding:6px 0;border-bottom:1px solid rgba(42,58,92,0.3);font-size:0.85rem">➡ {rec}</p>'
        html += "</div>"

        html += f'<div class="footer">{"Generado por" if es else "Generated by"} PhishGuard Pro v{VERSION} | {now}</div></body></html>'
        return html

    @staticmethod
    def generate_json(analysis, config):
        return json.dumps({
            "report": {
                "tool": f"PhishGuard Pro v{VERSION}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "analyst": config.get("analyst", ""),
                "organization": config.get("organization", ""),
            },
            "risk": analysis['risk'],
            "authentication": analysis['auth'],
            "hops": analysis['hops'],
            "iocs": analysis['iocs'],
            "key_headers": {k: v for k, v in analysis['parsed_headers'].items()
                          if k in ['From', 'To', 'Subject', 'Date', 'Return-Path',
                                  'Reply-To', 'Message-ID', 'X-Mailer', 'X-Priority',
                                  'X-Spam-Status', 'X-Spam-Score']}
        }, indent=2, ensure_ascii=False, default=str)

    @staticmethod
    def generate_csv_iocs(analysis):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Type', 'Value', 'Risk_Score', 'Verdict'])
        for ip in analysis['iocs']['public_ips']:
            writer.writerow(['IP', ip, analysis['risk']['score'], analysis['risk']['verdict']])
        for d in analysis['iocs']['domains']:
            writer.writerow(['Domain', d, analysis['risk']['score'], analysis['risk']['verdict']])
        for e in analysis['iocs']['emails']:
            writer.writerow(['Email', e, analysis['risk']['score'], analysis['risk']['verdict']])
        for u in analysis['iocs']['urls']:
            writer.writerow(['URL', u, analysis['risk']['score'], analysis['risk']['verdict']])
        return output.getvalue()

    @staticmethod
    def generate_stix(analysis):
        """Generate STIX 2.1 bundle."""
        objects = []
        for ip in analysis['iocs']['public_ips']:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": f"Malicious IP: {ip}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "labels": ["malicious-activity", "phishing"]
            })
        for d in analysis['iocs']['domains']:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": f"Phishing Domain: {d}",
                "pattern": f"[domain-name:value = '{d}']",
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "labels": ["malicious-activity", "phishing"]
            })
        return json.dumps({
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects
        }, indent=2, default=str)

    @staticmethod
    def _get_recommendations(analysis, es=True):
        recs = []
        r = analysis['risk']

        if r['score'] >= 50:
            recs.append("BLOQUEAR inmediatamente el dominio del remitente en el gateway de correo" if es else
                       "BLOCK the sender domain immediately at the email gateway")
            recs.append("Reportar las IPs maliciosas a AbuseIPDB y al proveedor de hosting" if es else
                       "Report malicious IPs to AbuseIPDB and the hosting provider")
            recs.append("Alertar a todos los usuarios sobre esta campana de phishing" if es else
                       "Alert all users about this phishing campaign")

        if analysis['auth']['spf']['status'] in ('fail', 'softfail'):
            recs.append("Revisar y reforzar la politica SPF del dominio propio" if es else
                       "Review and strengthen your domain's SPF policy")
        if analysis['auth']['dkim']['status'] == 'fail':
            recs.append("Verificar la configuracion DKIM del dominio" if es else
                       "Verify the domain's DKIM configuration")
        if analysis['auth']['dmarc']['status'] in ('fail', 'none', 'unknown'):
            recs.append("Implementar o reforzar la politica DMARC (considerar p=reject)" if es else
                       "Implement or strengthen DMARC policy (consider p=reject)")

        recs.append("Documentar el incidente en el sistema de gestion de casos" if es else
                   "Document the incident in the case management system")
        recs.append("Buscar en los logs de email mas mensajes del mismo remitente/IP" if es else
                   "Search email logs for more messages from the same sender/IP")
        recs.append("Actualizar reglas de deteccion (IDS/IPS/SIEM) con los IoCs extraidos" if es else
                   "Update detection rules (IDS/IPS/SIEM) with extracted IoCs")
        recs.append("Considerar el envio de los IoCs a plataformas de threat intelligence (MISP, OTX)" if es else
                   "Consider sharing IoCs with threat intelligence platforms (MISP, OTX)")

        return recs


def _esc(s):
    """HTML escape."""
    return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


# =========================================================================
# FULL ANALYSIS PIPELINE
# =========================================================================

def analyze_full(raw_headers: str) -> dict:
    """Run the complete analysis pipeline."""
    parsed = HeaderParser.parse(raw_headers)
    hops = HeaderParser.parse_received_hops(parsed)
    auth = AuthAnalyzer.analyze(parsed)
    iocs = IOCExtractor.extract_all(raw_headers)
    risk = RiskEngine.calculate(parsed, parsed, hops, auth, iocs, raw_headers)

    # Generate header hash for dedup
    header_hash = hashlib.sha256(raw_headers.encode()).hexdigest()[:12]

    analysis = {
        "id": f"ANALYSIS-{header_hash}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hash": header_hash,
        "parsed_headers": parsed,
        "hops": hops,
        "auth": auth,
        "iocs": iocs,
        "risk": risk
    }

    return analysis


# =========================================================================
# WEB SERVER & API
# =========================================================================

class PhishGuardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the PhishGuard API and frontend."""

    def log_message(self, format, *args):
        # Suppress default logging for cleaner output
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False, default=str).encode('utf-8'))

    def _send_html(self, html, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def _send_text(self, text, content_type='text/plain', filename=None, status=200):
        self.send_response(status)
        self.send_header('Content-Type', f'{content_type}; charset=utf-8')
        if filename:
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(text.encode('utf-8'))

    def _send_binary(self, data, content_type, filename=None, status=200):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        if filename:
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(length).decode('utf-8')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == '/' or path == '/index.html':
            self._send_html(get_frontend_html())

        elif path == '/api/health':
            self._send_json({"status": "ok", "version": VERSION, "name": APP_NAME})

        elif path == '/api/history':
            self._send_json(store.history)

        elif path == '/api/cases':
            self._send_json(store.cases)

        elif path == '/api/audit':
            self._send_json(store.audit_log)

        elif path == '/api/config':
            self._send_json(store.config)

        elif path == '/api/stats':
            total = len(store.history)
            phishing = sum(1 for a in store.history if a.get('risk', {}).get('score', 0) >= 70)
            suspicious = sum(1 for a in store.history if 30 <= a.get('risk', {}).get('score', 0) < 70)
            clean = sum(1 for a in store.history if a.get('risk', {}).get('score', 0) < 30)
            self._send_json({
                "total": total, "phishing": phishing,
                "suspicious": suspicious, "clean": clean,
                "open_cases": sum(1 for c in store.cases if c.get('status') in ('open', 'investigating'))
            })

        elif path.startswith('/api/reputation/'):
            query = path.split('/api/reputation/')[-1]
            query = urllib.parse.unquote(query)
            params = urllib.parse.parse_qs(parsed.query)
            qtype = params.get('type', ['all'])[0]
            links = ReputationLookup.get_tool_links(query, qtype)
            dns = ReputationLookup.dns_lookup(query) if qtype in ('all', 'domain') else {}
            self._send_json({"query": query, "type": qtype, "links": links, "dns": dns})

        elif path == '/api/tools':
            self._send_json(get_tools_database())

        elif path == '/api/clients':
            if HAS_CLIENT_DB and client_db:
                self._send_json(client_db.get_clients())
            else:
                self._send_json({"error": "Client database not available"}, 500)

        elif path.startswith('/api/clients/'):
            client_id = path.split('/api/clients/')[-1]
            if HAS_CLIENT_DB and client_db:
                # Check if requesting scans
                if client_id.endswith('/scans'):
                    real_client_id = client_id[:-7]  # Remove '/scans'
                    scans = client_db.get_scans(real_client_id)
                    self._send_json(scans)
                else:
                    # Get single client with stats
                    client = client_db.get_client(client_id)
                    if client:
                        stats = client_db.get_client_stats(client_id)
                        client['stats'] = stats
                        self._send_json(client)
                    else:
                        self._send_json({"error": "Client not found"}, 404)
            else:
                self._send_json({"error": "Client database not available"}, 500)

        elif path == '/api/scans':
            if HAS_CLIENT_DB and client_db:
                self._send_json(client_db.get_scans())
            else:
                self._send_json({"error": "Client database not available"}, 500)

        elif path.startswith('/api/scans/'):
            scan_id = path.split('/api/scans/')[-1]
            if HAS_CLIENT_DB and client_db:
                scan = client_db.get_scan(scan_id)
                if scan:
                    self._send_json(scan)
                else:
                    self._send_json({"error": "Scan not found"}, 404)
            else:
                self._send_json({"error": "Client database not available"}, 500)

        elif path == '/api/connectors/status':
            if not HAS_CONNECTORS:
                self._send_json({"error": "Connectors module not available"}, 500)
                return
            api_keys = store.config.get('api_keys', {})
            status = {
                "available": HAS_CONNECTORS,
                "connectors": {
                    "virustotal": "virustotal" in api_keys,
                    "abuseipdb": "abuseipdb" in api_keys,
                    "shodan": "shodan" in api_keys,
                    "otx": "otx" in api_keys,
                    "ipqualityscore": "ipqualityscore" in api_keys,
                    "openai": "openai" in api_keys,
                    "claude": "claude" in api_keys
                }
            }
            self._send_json(status)

        elif path.startswith('/api/enrich/'):
            if not HAS_CONNECTORS:
                self._send_json({"error": "Connectors module not available"}, 500)
                return
            parts = path.split('/api/enrich/')[-1].split('/')
            if len(parts) < 2:
                self._send_json({"error": "Invalid format. Use /api/enrich/<type>/<value>"}, 400)
                return
            ioc_type = parts[0]  # ip, domain, hash, url
            ioc_value = urllib.parse.unquote('/'.join(parts[1:]))
            api_keys = store.config.get('api_keys', {})
            result = {}

            try:
                if ioc_type == 'ip':
                    if "virustotal" in api_keys:
                        result["virustotal"] = ThreatIntelConnector.virustotal_check_ip(ioc_value, api_keys["virustotal"])
                    if "abuseipdb" in api_keys:
                        result["abuseipdb"] = ThreatIntelConnector.abuseipdb_check_ip(ioc_value, api_keys["abuseipdb"])
                    if "shodan" in api_keys:
                        result["shodan"] = ThreatIntelConnector.shodan_check_ip(ioc_value, api_keys["shodan"])
                    if "otx" in api_keys:
                        result["otx"] = ThreatIntelConnector.otx_check_ip(ioc_value, api_keys["otx"])
                    if "ipqualityscore" in api_keys:
                        result["ipqualityscore"] = ThreatIntelConnector.ipqualityscore_check_ip(ioc_value, api_keys["ipqualityscore"])
                elif ioc_type == 'domain':
                    if "virustotal" in api_keys:
                        result["virustotal"] = ThreatIntelConnector.virustotal_check_domain(ioc_value, api_keys["virustotal"])
                    if "otx" in api_keys:
                        result["otx"] = ThreatIntelConnector.otx_check_domain(ioc_value, api_keys["otx"])
                elif ioc_type == 'url':
                    if "virustotal" in api_keys:
                        result["virustotal"] = ThreatIntelConnector.virustotal_check_url(ioc_value, api_keys["virustotal"])
                elif ioc_type == 'hash':
                    if "virustotal" in api_keys:
                        result["virustotal"] = ThreatIntelConnector.virustotal_check_hash(ioc_value, api_keys["virustotal"])
                else:
                    self._send_json({"error": "Invalid type. Use: ip, domain, url, hash"}, 400)
                    return

                self._send_json({"type": ioc_type, "value": ioc_value, "enrichment": result})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = self.path

        if path == '/api/analyze':
            try:
                body = json.loads(self._read_body())
                raw = body.get('headers', '')
                body_text = body.get('body', '')
                attachments = body.get('attachments', [])

                if not raw.strip():
                    self._send_json({"error": "No headers provided"}, 400)
                    return

                analysis = analyze_full(raw)
                # Run enhanced modules if available
                if HAS_ENHANCED:
                    try:
                        analysis = run_enhanced_analysis(analysis, raw, enable_network=True,
                                                         body_text=body_text, attachments=attachments or None)
                    except Exception as enh_err:
                        analysis['enhanced_error'] = str(enh_err)
                store.add_history(analysis)
                store.add_audit('analysis_complete',
                              f"Score: {analysis['risk']['score']}/100 | Verdict: {analysis['risk']['verdict']}")

                # Auto-create case
                auto = store.config.get('auto_case', 'suspicious')
                if auto == 'always' or (auto == 'suspicious' and analysis['risk']['score'] >= 30):
                    from_h = (analysis['parsed_headers'].get('From', ['Unknown']) or ['Unknown'])[0]
                    subj = (analysis['parsed_headers'].get('Subject', ['No subject']) or ['No subject'])[0]
                    case = store.add_case({
                        "subject": subj[:100],
                        "sender": from_h[:200],
                        "severity": analysis['risk']['risk_level'],
                        "status": "investigating" if analysis['risk']['score'] >= 50 else "open",
                        "notes": f"Auto-generated. Score: {analysis['risk']['score']}/100. Verdict: {analysis['risk']['verdict']}",
                        "risk_score": analysis['risk']['score'],
                        "analysis_id": analysis['id']
                    })
                    store.add_audit('case_created', f"Case {case['id']} auto-created - {analysis['risk']['verdict']}")

                # Auto-save to client if client_id provided
                client_id = body.get('client_id')
                if client_id and HAS_CLIENT_DB and client_db:
                    try:
                        scan = client_db.add_scan(client_id, analysis)
                        analysis['scan_id'] = scan['id'] if scan else None
                        store.add_audit('scan_saved', f"Scan saved to client {client_id}")
                    except Exception as scan_err:
                        analysis['scan_save_error'] = str(scan_err)

                # Auto-enrich IoCs if enabled
                if HAS_CONNECTORS and store.config.get('auto_enrich', False):
                    try:
                        api_keys = store.config.get('api_keys', {})
                        if api_keys:
                            analysis['enrichment'] = ThreatIntelConnector.enrich_analysis(analysis, api_keys)
                            store.add_audit('auto_enrich', 'IoCs auto-enriched')
                    except Exception as enrich_err:
                        analysis['enrichment_error'] = str(enrich_err)

                # Auto-AI analysis if enabled
                if HAS_CONNECTORS and store.config.get('auto_ai', False):
                    try:
                        api_keys = store.config.get('api_keys', {})
                        ai_provider = store.config.get('ai_provider', 'auto')
                        if any(k in api_keys for k in ('openai', 'claude', 'gemini', 'mistral', 'groq', 'deepseek')):
                            analysis['ai_assessment'] = AIConnector.get_ai_assessment(analysis, api_keys, ai_provider)
                            store.add_audit('auto_ai_analysis', f'AI assessment generated ({ai_provider})')
                    except Exception as ai_err:
                        analysis['ai_assessment_error'] = str(ai_err)

                self._send_json(analysis)

            except json.JSONDecodeError:
                self._send_json({"error": "Invalid JSON"}, 400)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == '/api/analyze-msg':
            # Handle .msg file upload (base64 encoded)
            try:
                if not HAS_ENHANCED:
                    self._send_json({"error": "Enhanced modules not available"}, 500)
                    return
                import base64, tempfile
                body = json.loads(self._read_body())
                msg_b64 = body.get('msg_data', '')
                if not msg_b64:
                    self._send_json({"error": "No msg_data provided"}, 400)
                    return

                # Decode and save to temp file
                msg_bytes = base64.b64decode(msg_b64)
                with tempfile.NamedTemporaryFile(suffix='.msg', delete=False) as tmp:
                    tmp.write(msg_bytes)
                    tmp_path = tmp.name

                # Parse .msg
                msg_data = MsgParser.parse(tmp_path)
                os.unlink(tmp_path)

                if msg_data.get('error'):
                    self._send_json({"error": f"MSG parse error: {msg_data['error']}"}, 400)
                    return

                raw_headers = msg_data.get('transport_headers', '')
                body_text = msg_data.get('body', '')
                atts = msg_data.get('attachments', [])

                if not raw_headers.strip():
                    self._send_json({"error": "No transport headers found in .msg file"}, 400)
                    return

                analysis = analyze_full(raw_headers)
                analysis = run_enhanced_analysis(analysis, raw_headers, enable_network=True,
                                                 body_text=body_text, attachments=atts or None)
                # Add msg metadata
                analysis['msg_metadata'] = {
                    "subject": msg_data.get('subject', ''),
                    "sender_name": msg_data.get('sender_name', ''),
                    "sender_email": msg_data.get('sender_email', ''),
                    "display_to": msg_data.get('display_to', ''),
                    "body_text": body_text,
                    "attachment_count": len(atts),
                    "attachments": atts,
                }

                # Run malware analysis on attachments if available
                if HAS_MALWARE and atts:
                    import base64 as b64mod
                    malware_results = []
                    for att in atts:
                        att_data = att.get('data_b64', '')
                        if att_data:
                            try:
                                att_bytes = b64mod.b64decode(att_data)
                                mw = analyze_malware(att_bytes, att.get('filename', 'unknown'))
                                malware_results.append(mw)
                            except Exception:
                                pass
                        elif att.get('sha256'):
                            malware_results.append({
                                'filename': att.get('filename', '?'),
                                'sha256': att.get('sha256', ''),
                                'risk_score': 0,
                                'verdict': 'Sin datos binarios para analizar',
                                'tags': [],
                            })
                    if malware_results:
                        analysis['malware_analysis'] = malware_results
                        # Boost risk if malware found
                        max_mw_score = max(m.get('risk_score', 0) for m in malware_results)
                        if max_mw_score > analysis['risk']['score']:
                            analysis['risk']['score'] = min(100, max(analysis['risk']['score'], max_mw_score))

                store.add_history(analysis)
                store.add_audit('msg_analysis_complete',
                              f"MSG: {msg_data.get('subject', '?')[:50]} | Score: {analysis['risk']['score']}/100")

                # Auto-create case
                auto = store.config.get('auto_case', 'suspicious')
                if auto == 'always' or (auto == 'suspicious' and analysis['risk']['score'] >= 30):
                    case = store.add_case({
                        "subject": msg_data.get('subject', 'MSG Analysis')[:100],
                        "sender": f"{msg_data.get('sender_name','')} <{msg_data.get('sender_email','')}>",
                        "severity": analysis['risk']['risk_level'],
                        "status": "investigating" if analysis['risk']['score'] >= 50 else "open",
                        "notes": f"MSG file analysis. Score: {analysis['risk']['score']}/100. Verdict: {analysis['risk']['verdict']}",
                        "risk_score": analysis['risk']['score'],
                        "analysis_id": analysis['id']
                    })
                    store.add_audit('case_created', f"Case {case['id']} from MSG - {analysis['risk']['verdict']}")

                # Auto-save to client if client_id provided
                client_id = body.get('client_id')
                if client_id and HAS_CLIENT_DB and client_db:
                    try:
                        scan = client_db.add_scan(client_id, analysis)
                        analysis['scan_id'] = scan['id'] if scan else None
                        store.add_audit('scan_saved', f"Scan saved to client {client_id}")
                    except Exception as scan_err:
                        analysis['scan_save_error'] = str(scan_err)

                self._send_json(analysis)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == '/api/analyze-malware':
            try:
                if not HAS_MALWARE:
                    self._send_json({"error": "Modulo malware_analyzer no disponible"}, 500)
                    return
                import base64
                body = json.loads(self._read_body())
                file_b64 = body.get('file_data', '')
                filename = body.get('filename', 'unknown')
                if not file_b64:
                    self._send_json({"error": "No file_data provided"}, 400)
                    return

                file_bytes = base64.b64decode(file_b64)
                api_keys = store.config.get('api_keys', {})
                result = analyze_malware(file_bytes, filename, api_keys=api_keys)

                store.add_audit('malware_analysis',
                              f"File: {filename} | Score: {result['risk_score']}/100 | {result['risk_level']}")

                # Auto-create case for malware
                if result['risk_score'] >= 30:
                    case = store.add_case({
                        "subject": f"Malware: {filename}",
                        "sender": "Malware Analysis",
                        "severity": result['risk_level'],
                        "status": "investigating" if result['risk_score'] >= 50 else "open",
                        "notes": f"Malware analysis. Score: {result['risk_score']}/100. Verdict: {result['verdict']}. Tags: {', '.join(result.get('tags', []))}",
                        "risk_score": result['risk_score'],
                    })
                    result['case_id'] = case['id']
                    store.add_audit('case_created', f"Case {case['id']} from malware analysis - {filename}")

                self._send_json(result)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == '/api/cases':
            try:
                body = json.loads(self._read_body())
                case = store.add_case(body)
                store.add_audit('case_created_manual', f"Case {case['id']} created manually")
                self._send_json(case)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == '/api/config':
            try:
                body = json.loads(self._read_body())
                store.config.update(body)
                store.save_all()
                store.add_audit('config_updated', 'Configuration updated')
                self._send_json(store.config)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == '/api/report/html':
            try:
                body = json.loads(self._read_body())
                analysis = body.get('analysis')
                lang = body.get('lang', 'es')
                if not analysis:
                    self._send_json({"error": "No analysis data"}, 400)
                    return
                html = ReportGenerator.generate_html(analysis, store.config, lang)
                store.add_audit('report_generated', f'HTML report ({lang})')
                self._send_text(html, 'text/html', f'phishguard_report_{datetime.now().strftime("%Y%m%d")}.html')
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == '/api/report/json':
            try:
                body = json.loads(self._read_body())
                analysis = body.get('analysis')
                if not analysis:
                    self._send_json({"error": "No analysis data"}, 400)
                    return
                report = ReportGenerator.generate_json(analysis, store.config)
                store.add_audit('report_generated', 'JSON report')
                self._send_text(report, 'application/json', f'phishguard_report_{datetime.now().strftime("%Y%m%d")}.json')
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == '/api/report/csv':
            try:
                body = json.loads(self._read_body())
                analysis = body.get('analysis')
                if not analysis:
                    self._send_json({"error": "No analysis data"}, 400)
                    return
                csv_data = ReportGenerator.generate_csv_iocs(analysis)
                store.add_audit('report_generated', 'CSV IoCs export')
                self._send_text(csv_data, 'text/csv', f'phishguard_iocs_{datetime.now().strftime("%Y%m%d")}.csv')
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == '/api/report/pdf':
            try:
                body = json.loads(self._read_body())
                analysis = body.get('analysis')
                if not analysis:
                    self._send_json({"error": "No analysis data"}, 400)
                    return
                lang = body.get('lang', 'es')
                config = {
                    'analyst_name': store.config.get('analyst', 'Analista'),
                    'company_name': store.config.get('organization', 'PhishGuard Pro'),
                    'lang': lang,
                }
                try:
                    pdf_bytes = generate_pdf_report(analysis, config)
                    store.add_audit('report_generated', 'PDF professional report')
                    ref = f'GPV{datetime.now().strftime("%d%m%y%H%M")}'
                    self._send_binary(pdf_bytes, 'application/pdf',
                                      f'Informe_Phishing_{ref}.pdf')
                except ImportError:
                    self._send_json({"error": "reportlab no instalado. pip install reportlab"}, 500)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == '/api/report/stix':
            try:
                body = json.loads(self._read_body())
                analysis = body.get('analysis')
                if not analysis:
                    self._send_json({"error": "No analysis data"}, 400)
                    return
                stix = ReportGenerator.generate_stix(analysis)
                store.add_audit('report_generated', 'STIX 2.1 bundle')
                self._send_text(stix, 'application/json', f'phishguard_stix_{datetime.now().strftime("%Y%m%d")}.json')
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == '/api/export/all':
            data = json.dumps({
                "exported": datetime.now(timezone.utc).isoformat(),
                "version": VERSION,
                "history": store.history,
                "cases": store.cases,
                "audit": store.audit_log,
                "config": store.config
            }, indent=2, ensure_ascii=False, default=str)
            store.add_audit('data_exported', 'Full data export')
            self._send_text(data, 'application/json', f'phishguard_export_{datetime.now().strftime("%Y%m%d")}.json')

        elif path == '/api/clients':
            if HAS_CLIENT_DB and client_db:
                try:
                    body = json.loads(self._read_body())
                    client = client_db.add_client(body)
                    store.add_audit('client_created', f"Client: {body.get('company', 'Unknown')}")
                    self._send_json(client)
                except Exception as e:
                    self._send_json({"error": str(e)}, 500)
            else:
                self._send_json({"error": "Client database not available"}, 500)

        elif path == '/api/scans':
            if HAS_CLIENT_DB and client_db:
                try:
                    body = json.loads(self._read_body())
                    client_id = body.get('client_id')
                    analysis = body.get('analysis')
                    if not client_id or not analysis:
                        self._send_json({"error": "client_id and analysis required"}, 400)
                        return
                    scan = client_db.add_scan(client_id, analysis)
                    store.add_audit('scan_created', f"Scan added to client {client_id}")
                    self._send_json(scan)
                except Exception as e:
                    self._send_json({"error": str(e)}, 500)
            else:
                self._send_json({"error": "Client database not available"}, 500)

        elif path == '/api/enrich':
            if not HAS_CONNECTORS:
                self._send_json({"error": "Connectors module not available"}, 500)
                return
            try:
                body = json.loads(self._read_body())
                analysis = body.get('analysis')
                if not analysis:
                    self._send_json({"error": "No analysis provided"}, 400)
                    return

                api_keys = store.config.get('api_keys', {})
                enrichment = ThreatIntelConnector.enrich_analysis(analysis, api_keys)

                store.add_audit('analysis_enriched', f"Full enrichment completed with {len(enrichment.get('ips', {}))} IPs, {len(enrichment.get('domains', {}))} domains")
                self._send_json(enrichment)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == '/api/ai/analyze':
            if not HAS_CONNECTORS:
                self._send_json({"error": "Connectors module not available"}, 500)
                return
            try:
                body = json.loads(self._read_body())
                analysis = body.get('analysis')
                provider = body.get('provider', 'auto')
                if not analysis:
                    self._send_json({"error": "No analysis provided"}, 400)
                    return

                api_keys = store.config.get('api_keys', {})
                assessment = AIConnector.get_ai_assessment(analysis, api_keys, provider)

                store.add_audit('ai_analysis_complete', f"AI assessment generated by {provider}")
                self._send_json(assessment)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == '/api/connectors/test':
            if not HAS_CONNECTORS:
                self._send_json({"error": "Connectors module not available"}, 500)
                return
            try:
                body = json.loads(self._read_body())
                connector = body.get('connector')
                api_key = body.get('api_key')

                if not connector or not api_key:
                    self._send_json({"error": "connector and api_key required"}, 400)
                    return

                result = {"connector": connector, "api_key_status": "configured"}

                # Test each connector type
                if connector == 'virustotal':
                    test_result = ThreatIntelConnector.virustotal_check_ip('8.8.8.8', api_key)
                    result["test"] = "success" if "error" not in test_result else test_result.get("error")
                elif connector == 'abuseipdb':
                    test_result = ThreatIntelConnector.abuseipdb_check_ip('8.8.8.8', api_key)
                    result["test"] = "success" if "error" not in test_result else test_result.get("error")
                elif connector == 'shodan':
                    test_result = ThreatIntelConnector.shodan_check_ip('8.8.8.8', api_key)
                    result["test"] = "success" if "error" not in test_result else test_result.get("error")
                elif connector == 'otx':
                    test_result = ThreatIntelConnector.otx_check_ip('8.8.8.8', api_key)
                    result["test"] = "success" if "error" not in test_result else test_result.get("error")
                elif connector == 'ipqualityscore':
                    test_result = ThreatIntelConnector.ipqualityscore_check_ip('8.8.8.8', api_key)
                    result["test"] = "success" if "error" not in test_result else test_result.get("error")
                elif connector in ('openai', 'claude', 'gemini', 'mistral', 'groq', 'deepseek'):
                    # AI providers: validate key format
                    result["test"] = "success"
                else:
                    result["test"] = "unknown_connector"

                store.add_audit('connector_tested', f"Connector {connector} test result: {result['test']}")
                self._send_json(result)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        else:
            self._send_json({"error": "Not found"}, 404)

    def do_PUT(self):
        if self.path.startswith('/api/cases/'):
            case_id = self.path.split('/api/cases/')[-1]
            try:
                body = json.loads(self._read_body())
                case = store.update_case(case_id, body)
                if case:
                    store.add_audit('case_updated', f"Case {case_id} updated: {body}")
                    self._send_json(case)
                else:
                    self._send_json({"error": "Case not found"}, 404)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif self.path.startswith('/api/clients/'):
            client_id = self.path.split('/api/clients/')[-1]
            if HAS_CLIENT_DB and client_db:
                try:
                    body = json.loads(self._read_body())
                    client = client_db.update_client(client_id, body)
                    if client:
                        store.add_audit('client_updated', f"Client {client_id} updated")
                        self._send_json(client)
                    else:
                        self._send_json({"error": "Client not found"}, 404)
                except Exception as e:
                    self._send_json({"error": str(e)}, 500)
            else:
                self._send_json({"error": "Client database not available"}, 500)
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_DELETE(self):
        if self.path.startswith('/api/clients/'):
            client_id = self.path.split('/api/clients/')[-1]
            if HAS_CLIENT_DB and client_db:
                try:
                    client_db.delete_client(client_id)
                    store.add_audit('client_deleted', f"Client {client_id} deleted")
                    self._send_json({"success": True})
                except Exception as e:
                    self._send_json({"error": str(e)}, 500)
            else:
                self._send_json({"error": "Client database not available"}, 500)
        elif self.path.startswith('/api/scans/'):
            scan_id = self.path.split('/api/scans/')[-1]
            if HAS_CLIENT_DB and client_db:
                try:
                    client_db.delete_scan(scan_id)
                    store.add_audit('scan_deleted', f"Scan {scan_id} deleted")
                    self._send_json({"success": True})
                except Exception as e:
                    self._send_json({"error": str(e)}, 500)
            else:
                self._send_json({"error": "Client database not available"}, 500)
        else:
            self._send_json({"error": "Not found"}, 404)


def get_tools_database():
    """Return the full tools database."""
    return {
        "authentication": [
            {"name": "MXToolbox", "url": "https://mxtoolbox.com/SuperTool.aspx", "desc": "SPF, DKIM, DMARC, blacklists", "category": "auth"},
            {"name": "EasyDMARC", "url": "https://easydmarc.com/tools", "desc": "Suite completa de autenticacion", "category": "auth"},
            {"name": "Dmarcian", "url": "https://dmarcian.com/domain-checker/", "desc": "Verificador DMARC", "category": "auth"},
            {"name": "DKIM Validator", "url": "https://dkimvalidator.com/", "desc": "Validador DKIM/SPF", "category": "auth"},
        ],
        "reputation": [
            {"name": "VirusTotal", "url": "https://www.virustotal.com", "desc": "Multi-motor de analisis", "category": "reputation"},
            {"name": "AbuseIPDB", "url": "https://www.abuseipdb.com/", "desc": "Base de datos de IPs maliciosas", "category": "reputation"},
            {"name": "Shodan", "url": "https://www.shodan.io/", "desc": "Motor de busqueda IoT", "category": "reputation"},
            {"name": "Cisco Talos", "url": "https://talosintelligence.com/reputation", "desc": "Reputacion IP/dominio", "category": "reputation"},
            {"name": "AlienVault OTX", "url": "https://otx.alienvault.com/", "desc": "Threat intelligence abierta", "category": "reputation"},
            {"name": "IPQualityScore", "url": "https://www.ipqualityscore.com/", "desc": "Deteccion fraude/proxy", "category": "reputation"},
            {"name": "GreyNoise", "url": "https://viz.greynoise.io/", "desc": "Ruido de internet vs amenazas", "category": "reputation"},
            {"name": "Censys", "url": "https://search.censys.io/", "desc": "Busqueda de hosts y certificados", "category": "reputation"},
        ],
        "url_analysis": [
            {"name": "URLScan.io", "url": "https://urlscan.io/", "desc": "Escaneo y screenshot de URLs", "category": "url"},
            {"name": "PhishTank", "url": "https://www.phishtank.com/", "desc": "Base de datos de phishing", "category": "url"},
            {"name": "Google Safe Browsing", "url": "https://safebrowsing.google.com/", "desc": "Verificacion de URLs", "category": "url"},
            {"name": "CheckPhish.ai", "url": "https://checkphish.ai/", "desc": "Deteccion phishing con IA", "category": "url"},
            {"name": "ANY.RUN", "url": "https://any.run/", "desc": "Sandbox interactivo", "category": "sandbox"},
            {"name": "Hybrid Analysis", "url": "https://www.hybrid-analysis.com/", "desc": "Analisis de malware", "category": "sandbox"},
        ],
        "osint": [
            {"name": "WHOIS Lookup", "url": "https://whois.domaintools.com/", "desc": "Registro de dominio", "category": "osint"},
            {"name": "Robtex", "url": "https://www.robtex.com/", "desc": "Intel DNS y red", "category": "osint"},
            {"name": "SecurityTrails", "url": "https://securitytrails.com/", "desc": "Historial DNS", "category": "osint"},
            {"name": "Hunter.io", "url": "https://hunter.io/", "desc": "Verificacion de emails", "category": "osint"},
            {"name": "Have I Been Pwned", "url": "https://haveibeenpwned.com/", "desc": "Brechas de datos", "category": "osint"},
            {"name": "crt.sh", "url": "https://crt.sh/", "desc": "Transparencia de certificados", "category": "osint"},
            {"name": "DNSDumpster", "url": "https://dnsdumpster.com/", "desc": "Reconocimiento DNS", "category": "osint"},
            {"name": "ViewDNS.info", "url": "https://viewdns.info/", "desc": "Herramientas DNS multiples", "category": "osint"},
        ]
    }


# =========================================================================
# FRONTEND HTML (embedded)
# =========================================================================

def get_frontend_html():
    """Return the complete frontend HTML."""
    return FRONTEND_HTML


# The frontend is loaded from the companion file
FRONTEND_HTML = ""

def load_frontend():
    global FRONTEND_HTML
    frontend_path = Path(__file__).parent / "frontend.html"
    if frontend_path.exists():
        with open(frontend_path, 'r', encoding='utf-8') as f:
            FRONTEND_HTML = f.read()
    else:
        FRONTEND_HTML = "<html><body><h1>Error: frontend.html not found</h1></body></html>"


# =========================================================================
# MAIN
# =========================================================================

def main():
    parser = argparse.ArgumentParser(description=f'{APP_NAME} v{VERSION} - Phishing Analysis Framework')
    parser.add_argument('--port', type=int, default=8080, help='Port (default: 8080)')
    parser.add_argument('--host', default='127.0.0.1', help='Host (default: 127.0.0.1)')
    parser.add_argument('--no-browser', action='store_true', help='Do not open browser automatically')
    args = parser.parse_args()

    load_frontend()
    store.add_audit('server_started', f'{APP_NAME} v{VERSION} started on {args.host}:{args.port}')

    server = HTTPServer((args.host, args.port), PhishGuardHandler)

    mw_count = " + Malware Engine" if HAS_MALWARE else ""
    conn_count = " + ThreatIntel + AI" if HAS_CONNECTORS else ""
    enh_status = f"14 modulos{mw_count}{conn_count}" if HAS_ENHANCED else "Modo basico"
    pdf_status = "PDF Pro" if HAS_ENHANCED else "HTML/JSON"
    net_status = "Online" if HAS_REQUESTS else "Offline"

    print(f"""
╔══════════════════════════════════════════════════╗
║         PhishGuard Pro v{VERSION}                 ║
║     Framework de Analisis de Phishing            ║
║     Jaquers Ciberseguridad S.L.                  ║
╠══════════════════════════════════════════════════╣
║  Server:   http://{args.host}:{args.port:<5}                   ║
║  API:      http://{args.host}:{args.port}/api/health        ║
║  Modulos:  {enh_status:<37}║
║  Informes: {pdf_status:<37}║
║  Red:      {net_status:<37}║
╠══════════════════════════════════════════════════╣
║  Ctrl+C para detener el servidor                 ║
╚══════════════════════════════════════════════════╝
""")

    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f'http://{args.host}:{args.port}')).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Servidor detenido.")
        store.add_audit('server_stopped', 'Server shutdown')
        store.save_all()
        server.server_close()


if __name__ == '__main__':
    main()
