"""
PhishGuard Pro v3.0 - Advanced Analysis Modules
================================================
Modulos adicionales de analisis forense:
  1. DNSResolver       - Resolucion DNS (MX, SPF record, NS, PTR)
  2. DNSBLChecker      - Consulta de blacklists DNSBL
  3. GeoIPLookup       - Geolocalizacion de IPs (ip-api.com, sin API key)
  4. HomoglyphDetector  - Deteccion de ataques homoglifos/IDN
  5. HeaderForensics    - Analisis forense avanzado de cabeceras
  6. URLIntelligence    - Deteccion de shorteners, defanging, categorizacion
  7. SenderIntel        - Inteligencia sobre el remitente
  8. TemporalAnalyzer   - Analisis temporal y de zonas horarias
  9. BodyAnalyzer       - Analisis del cuerpo del mensaje (URLs, ingenieria social, scripts)
 10. AttachmentAnalyzer - Analisis de adjuntos (hashes, extensiones peligrosas, doble extension)
 11. MsgParser          - Parser de archivos .msg (OLE2 Compound Binary)
"""

import re
import socket
import struct
import hashlib
import unicodedata
from datetime import datetime, timezone, timedelta
from typing import Optional

# Try importing requests
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# =========================================================================
# MODULE 1: DNS RESOLVER
# =========================================================================

class DNSResolver:
    """
    Resolve DNS records using socket for basic lookups
    and raw UDP queries for MX/TXT/NS records.
    """

    @staticmethod
    def resolve_a(domain: str) -> dict:
        """Resolve A record."""
        result = {"domain": domain, "A": None, "error": None}
        try:
            result["A"] = socket.gethostbyname(domain)
        except socket.gaierror as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def resolve_all(domain: str) -> dict:
        """Resolve all available records using getaddrinfo."""
        result = {"domain": domain, "ipv4": [], "ipv6": [], "error": None}
        try:
            infos = socket.getaddrinfo(domain, None)
            for info in infos:
                family, _, _, _, addr = info
                ip = addr[0]
                if family == socket.AF_INET and ip not in result["ipv4"]:
                    result["ipv4"].append(ip)
                elif family == socket.AF_INET6 and ip not in result["ipv6"]:
                    result["ipv6"].append(ip)
        except socket.gaierror as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def reverse_dns(ip: str) -> dict:
        """Perform reverse DNS lookup (PTR record)."""
        result = {"ip": ip, "hostname": None, "error": None}
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            result["hostname"] = hostname
        except (socket.herror, socket.gaierror, OSError) as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def query_txt_via_dns(domain: str) -> dict:
        """
        Query TXT records using raw DNS UDP query.
        This allows us to get SPF records without external libraries.
        """
        result = {"domain": domain, "txt_records": [], "spf_record": None, "error": None}
        try:
            # Build DNS query packet for TXT record
            query = DNSResolver._build_dns_query(domain, qtype=16)  # TXT = 16
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            # Use Google DNS
            sock.sendto(query, ('8.8.8.8', 53))
            response, _ = sock.recvfrom(4096)
            sock.close()

            records = DNSResolver._parse_dns_txt_response(response)
            result["txt_records"] = records

            # Find SPF record
            for rec in records:
                if rec.startswith('v=spf1'):
                    result["spf_record"] = rec
                    break

        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def query_mx_via_dns(domain: str) -> dict:
        """Query MX records using raw DNS UDP."""
        result = {"domain": domain, "mx_records": [], "error": None}
        try:
            query = DNSResolver._build_dns_query(domain, qtype=15)  # MX = 15
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(query, ('8.8.8.8', 53))
            response, _ = sock.recvfrom(4096)
            sock.close()

            records = DNSResolver._parse_dns_mx_response(response)
            result["mx_records"] = records

        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def _build_dns_query(domain: str, qtype: int = 1) -> bytes:
        """Build a raw DNS query packet."""
        import random
        tid = random.randint(0, 65535)
        # Header: ID, flags (standard query), QDCOUNT=1
        header = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
        # Question section
        question = b''
        for part in domain.split('.'):
            question += bytes([len(part)]) + part.encode()
        question += b'\x00'  # End of name
        question += struct.pack('!HH', qtype, 1)  # QTYPE, QCLASS (IN)
        return header + question

    @staticmethod
    def _parse_dns_txt_response(data: bytes) -> list:
        """Parse TXT records from DNS response."""
        records = []
        try:
            # Skip header (12 bytes)
            offset = 12
            # Skip question section
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 5  # null byte + QTYPE + QCLASS

            # Parse answer section
            ancount = struct.unpack('!H', data[6:8])[0]
            for _ in range(ancount):
                # Skip name (may be compressed)
                if data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while data[offset] != 0:
                        offset += data[offset] + 1
                    offset += 1

                rtype = struct.unpack('!H', data[offset:offset+2])[0]
                rdlength = struct.unpack('!H', data[offset+8:offset+10])[0]
                offset += 10

                if rtype == 16:  # TXT
                    txt = ''
                    end = offset + rdlength
                    pos = offset
                    while pos < end:
                        tlen = data[pos]
                        pos += 1
                        txt += data[pos:pos+tlen].decode('utf-8', errors='replace')
                        pos += tlen
                    records.append(txt)

                offset += rdlength
        except Exception:
            pass
        return records

    @staticmethod
    def _parse_dns_mx_response(data: bytes) -> list:
        """Parse MX records from DNS response."""
        records = []
        try:
            offset = 12
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 5

            ancount = struct.unpack('!H', data[6:8])[0]
            for _ in range(ancount):
                if data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while data[offset] != 0:
                        offset += data[offset] + 1
                    offset += 1

                rtype = struct.unpack('!H', data[offset:offset+2])[0]
                rdlength = struct.unpack('!H', data[offset+8:offset+10])[0]
                offset += 10

                if rtype == 15:  # MX
                    priority = struct.unpack('!H', data[offset:offset+2])[0]
                    # Parse domain name
                    name = DNSResolver._parse_dns_name(data, offset + 2)
                    records.append({"priority": priority, "exchange": name})

                offset += rdlength
        except Exception:
            pass
        return records

    @staticmethod
    def _parse_dns_name(data: bytes, offset: int) -> str:
        """Parse a DNS domain name (handling compression)."""
        parts = []
        seen = set()
        while True:
            if offset in seen or offset >= len(data):
                break
            seen.add(offset)
            length = data[offset]
            if length == 0:
                break
            if length & 0xC0 == 0xC0:
                pointer = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
                parts.append(DNSResolver._parse_dns_name(data, pointer))
                break
            else:
                offset += 1
                parts.append(data[offset:offset+length].decode('utf-8', errors='replace'))
                offset += length
        return '.'.join(parts)


# =========================================================================
# MODULE 2: DNSBL CHECKER
# =========================================================================

class DNSBLChecker:
    """
    Check IPs against DNS-based blackhole lists (DNSBL).
    Uses reverse IP + DNSBL domain DNS query technique.
    """

    BLACKLISTS = [
        {"name": "Spamhaus ZEN", "zone": "zen.spamhaus.org", "url": "https://www.spamhaus.org/lookup/"},
        {"name": "Barracuda", "zone": "b.barracudacentral.org", "url": "https://www.barracudacentral.org/lookups"},
        {"name": "SpamCop", "zone": "bl.spamcop.net", "url": "https://www.spamcop.net/bl.shtml"},
        {"name": "SORBS", "zone": "dnsbl.sorbs.net", "url": "http://www.sorbs.net/lookup.shtml"},
        {"name": "CBL", "zone": "cbl.abuseat.org", "url": "https://www.abuseat.org/lookup.html"},
        {"name": "UCEPROTECT L1", "zone": "dnsbl-1.uceprotect.net", "url": "https://www.uceprotect.net/en/"},
        {"name": "PSBL", "zone": "psbl.surriel.com", "url": "https://psbl.org/"},
        {"name": "DRONE", "zone": "drone.abuse.ch", "url": "https://abuse.ch/"},
        {"name": "WPBL", "zone": "db.wpbl.info", "url": "http://www.wpbl.info/"},
        {"name": "Invaluement", "zone": "dnsbl.invaluement.com", "url": "https://www.invaluement.com/"},
        {"name": "Truncate", "zone": "truncate.gbudb.net", "url": "https://www.gbudb.com/"},
        {"name": "JustSpam", "zone": "dnsbl.justspam.org", "url": "http://www.justspam.org/"},
    ]

    @classmethod
    def check_ip(cls, ip: str) -> dict:
        """Check an IP against all configured DNSBLs."""
        result = {
            "ip": ip,
            "listed_on": [],
            "clean_on": [],
            "errors": [],
            "total_checked": len(cls.BLACKLISTS),
            "listed_count": 0,
            "is_blacklisted": False
        }

        # Reverse the IP for DNSBL query
        reversed_ip = '.'.join(reversed(ip.split('.')))

        for bl in cls.BLACKLISTS:
            query = f"{reversed_ip}.{bl['zone']}"
            try:
                socket.setdefaulttimeout(2)
                answer = socket.gethostbyname(query)
                # If we get a response, the IP is listed
                result["listed_on"].append({
                    "name": bl["name"],
                    "zone": bl["zone"],
                    "response": answer,
                    "url": bl["url"]
                })
            except socket.gaierror:
                # NXDOMAIN = not listed (this is good)
                result["clean_on"].append(bl["name"])
            except socket.timeout:
                result["errors"].append(f"{bl['name']}: timeout")
            except Exception as e:
                result["errors"].append(f"{bl['name']}: {str(e)}")

        result["listed_count"] = len(result["listed_on"])
        result["is_blacklisted"] = result["listed_count"] > 0
        socket.setdefaulttimeout(None)

        return result


# =========================================================================
# MODULE 3: GEOIP LOOKUP
# =========================================================================

class GeoIPLookup:
    """
    IP Geolocation using free APIs (ip-api.com - no key required).
    Rate limited to 45 requests/minute.
    """

    API_URL = "http://ip-api.com/json/{ip}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"

    @classmethod
    def lookup(cls, ip: str) -> dict:
        """Lookup geolocation for an IP address."""
        result = {
            "ip": ip,
            "success": False,
            "country": None,
            "country_code": None,
            "city": None,
            "region": None,
            "lat": None,
            "lon": None,
            "timezone": None,
            "isp": None,
            "org": None,
            "as_number": None,
            "as_name": None,
            "reverse": None,
            "is_proxy": False,
            "is_hosting": False,
            "is_mobile": False,
            "error": None
        }

        if not HAS_REQUESTS:
            result["error"] = "requests library not available"
            return result

        try:
            resp = requests.get(
                cls.API_URL.format(ip=ip),
                timeout=5,
                headers={"User-Agent": "PhishGuard-Pro/2.1"}
            )
            data = resp.json()

            if data.get("status") == "success":
                result["success"] = True
                result["country"] = data.get("country")
                result["country_code"] = data.get("countryCode")
                result["city"] = data.get("city")
                result["region"] = data.get("regionName")
                result["lat"] = data.get("lat")
                result["lon"] = data.get("lon")
                result["timezone"] = data.get("timezone")
                result["isp"] = data.get("isp")
                result["org"] = data.get("org")
                result["as_number"] = data.get("as")
                result["as_name"] = data.get("asname")
                result["reverse"] = data.get("reverse")
                result["is_proxy"] = data.get("proxy", False)
                result["is_hosting"] = data.get("hosting", False)
                result["is_mobile"] = data.get("mobile", False)
            else:
                result["error"] = data.get("message", "Unknown error")

        except requests.exceptions.Timeout:
            result["error"] = "Request timeout"
        except requests.exceptions.ConnectionError:
            result["error"] = "Connection error"
        except Exception as e:
            result["error"] = str(e)

        return result

    @classmethod
    def batch_lookup(cls, ips: list) -> list:
        """Lookup multiple IPs. Respects rate limiting."""
        results = []
        for ip in ips[:10]:  # Limit to 10 to avoid rate limiting
            results.append(cls.lookup(ip))
        return results


# =========================================================================
# MODULE 4: HOMOGLYPH / IDN DETECTOR
# =========================================================================

class HomoglyphDetector:
    """
    Detect homoglyph attacks (lookalike characters) in domains and email addresses.
    Detects Unicode confusables, Cyrillic/Greek substitutions, and IDN attacks.
    """

    # Map of common homoglyphs: unicode char -> ascii equivalent
    CONFUSABLES = {
        '\u0430': 'a',  # Cyrillic а
        '\u0435': 'e',  # Cyrillic е
        '\u043e': 'o',  # Cyrillic о
        '\u0440': 'p',  # Cyrillic р
        '\u0441': 'c',  # Cyrillic с
        '\u0443': 'y',  # Cyrillic у
        '\u0445': 'x',  # Cyrillic х
        '\u0456': 'i',  # Ukrainian і
        '\u0458': 'j',  # Cyrillic ј
        '\u04bb': 'h',  # Cyrillic һ
        '\u04cf': 'l',  # Cyrillic ӏ
        '\u0501': 'd',  # Cyrillic ԁ
        '\u051b': 'q',  # Cyrillic ԛ
        '\u051d': 'w',  # Cyrillic ԝ
        '\u0391': 'A',  # Greek Alpha
        '\u0392': 'B',  # Greek Beta
        '\u0395': 'E',  # Greek Epsilon
        '\u0397': 'H',  # Greek Eta
        '\u0399': 'I',  # Greek Iota
        '\u039a': 'K',  # Greek Kappa
        '\u039c': 'M',  # Greek Mu
        '\u039d': 'N',  # Greek Nu
        '\u039f': 'O',  # Greek Omicron
        '\u03a1': 'P',  # Greek Rho
        '\u03a4': 'T',  # Greek Tau
        '\u03a5': 'Y',  # Greek Upsilon
        '\u03a7': 'X',  # Greek Chi
        '\u03b1': 'a',  # Greek alpha
        '\u03b5': 'e',  # Greek epsilon
        '\u03bf': 'o',  # Greek omicron
        '\u03c1': 'p',  # Greek rho
        '\u0261': 'g',  # Latin g
        '\u026a': 'i',  # Latin small I
        '\u1d00': 'a',  # Small capital A
        '\u1d04': 'c',  # Small capital C
        '\u1d07': 'e',  # Small capital E
        '\u2010': '-',  # Hyphen
        '\u2011': '-',  # Non-breaking hyphen
        '\u2012': '-',  # Figure dash
        '\u2013': '-',  # En dash
        '\u2014': '-',  # Em dash
        '\u2024': '.',  # One dot leader
        '\u2025': '..',  # Two dot leader
        '\uff0e': '.',  # Fullwidth full stop
        '\u2215': '/',  # Division slash
        '\u2044': '/',  # Fraction slash
    }

    # ASCII substitutions commonly used
    ASCII_SUBS = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
        '7': 't', '8': 'b', '9': 'g', '!': 'i', '|': 'l',
        '$': 's', '@': 'a',
    }

    @classmethod
    def analyze_domain(cls, domain: str) -> dict:
        """Analyze a domain for homoglyph attacks."""
        result = {
            "domain": domain,
            "has_unicode": False,
            "has_homoglyphs": False,
            "has_mixed_scripts": False,
            "has_ascii_substitution": False,
            "is_idn": False,
            "punycode": None,
            "detected_confusables": [],
            "ascii_equivalent": "",
            "scripts_detected": [],
            "risk_indicators": [],
            "risk_score": 0
        }

        # Check for non-ASCII characters
        if any(ord(c) > 127 for c in domain):
            result["has_unicode"] = True
            result["risk_score"] += 30
            result["risk_indicators"].append("Contains non-ASCII characters")

            # Convert to punycode
            try:
                result["punycode"] = domain.encode('idna').decode('ascii')
                result["is_idn"] = True
            except Exception:
                try:
                    parts = domain.split('.')
                    encoded_parts = []
                    for part in parts:
                        try:
                            encoded_parts.append(part.encode('idna').decode('ascii'))
                        except:
                            encoded_parts.append(part)
                    result["punycode"] = '.'.join(encoded_parts)
                    result["is_idn"] = True
                except:
                    pass

        # Detect confusable characters
        ascii_eq = ""
        for char in domain:
            if char in cls.CONFUSABLES:
                result["has_homoglyphs"] = True
                result["detected_confusables"].append({
                    "char": char,
                    "unicode_name": unicodedata.name(char, 'UNKNOWN'),
                    "looks_like": cls.CONFUSABLES[char],
                    "codepoint": f"U+{ord(char):04X}"
                })
                ascii_eq += cls.CONFUSABLES[char]
                result["risk_score"] += 15
            else:
                ascii_eq += char
        result["ascii_equivalent"] = ascii_eq

        # Detect mixed scripts
        scripts = set()
        for char in domain:
            if char in '.-':
                continue
            try:
                script = unicodedata.name(char, '').split()[0] if ord(char) > 127 else 'LATIN'
                scripts.add(script)
            except:
                pass
        result["scripts_detected"] = list(scripts)
        if len(scripts) > 1:
            result["has_mixed_scripts"] = True
            result["risk_score"] += 25
            result["risk_indicators"].append(f"Mixed scripts detected: {', '.join(scripts)}")

        # Check for ASCII-based substitutions (l33tspeak)
        domain_lower = domain.lower()
        for char, replacement in cls.ASCII_SUBS.items():
            if char in domain_lower:
                result["has_ascii_substitution"] = True
                result["risk_indicators"].append(f"ASCII substitution: '{char}' -> '{replacement}'")
                result["risk_score"] += 5

        return result

    @classmethod
    def analyze_all_domains(cls, domains: list) -> list:
        """Analyze multiple domains."""
        return [cls.analyze_domain(d) for d in domains]

    @classmethod
    def levenshtein_distance(cls, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return cls.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1 != c2)))
            prev = curr
        return prev[-1]

    @classmethod
    def find_brand_similarity(cls, domain: str, brands: list) -> list:
        """Find brands similar to the given domain using Levenshtein distance."""
        results = []
        # Extract the main part (before TLD)
        parts = domain.lower().split('.')
        main = parts[0] if parts else domain
        # Also check hyphenated sub-parts
        sub_parts = [main] + main.split('-')

        for brand in brands:
            best_sim = 0
            best_dist = 999
            for sp in sub_parts:
                if not sp:
                    continue
                dist = cls.levenshtein_distance(sp, brand)
                similarity = 1 - (dist / max(len(sp), len(brand)))
                if similarity > best_sim:
                    best_sim = similarity
                    best_dist = dist
            if best_sim >= 0.6:
                is_exact = main == brand or brand in sub_parts
                results.append({
                    "brand": brand,
                    "domain": domain,
                    "distance": best_dist,
                    "similarity": round(best_sim * 100, 1),
                    "is_exact": is_exact
                })

        return sorted(results, key=lambda x: x["similarity"], reverse=True)


# =========================================================================
# MODULE 5: HEADER FORENSICS
# =========================================================================

class HeaderForensics:
    """Advanced email header forensic analysis."""

    # Expected header ordering (simplified RFC 5322)
    EXPECTED_ORDER = [
        'Return-Path', 'Received', 'Authentication-Results',
        'DKIM-Signature', 'From', 'To', 'Subject', 'Date',
        'Message-ID', 'MIME-Version', 'Content-Type'
    ]

    @classmethod
    def analyze(cls, headers: dict, raw: str) -> dict:
        """Perform comprehensive header forensic analysis."""
        result = {
            "header_count": sum(len(v) for v in headers.values()),
            "unique_headers": len(headers),
            "anomalies": [],
            "message_id_analysis": cls._analyze_message_id(headers),
            "date_analysis": cls._analyze_dates(headers),
            "encoding_analysis": cls._analyze_encoding(headers, raw),
            "header_order_score": cls._check_header_order(headers),
            "x_headers": cls._analyze_x_headers(headers),
            "duplicate_detection": cls._detect_duplicates(headers),
            "empty_headers": cls._find_empty_headers(headers),
            "header_injection": cls._detect_header_injection(raw),
            "content_analysis": cls._analyze_content_headers(headers),
        }

        # Aggregate anomalies
        for key, sub in result.items():
            if isinstance(sub, dict) and "anomalies" in sub:
                result["anomalies"].extend(sub["anomalies"])

        return result

    @staticmethod
    def _analyze_message_id(headers: dict) -> dict:
        """Analyze Message-ID for anomalies."""
        result = {"value": None, "domain": None, "anomalies": [], "format_valid": True}
        msg_ids = headers.get('Message-ID', [])
        if not msg_ids:
            result["anomalies"].append({"text": "Falta cabecera Message-ID (sospechoso)", "severity": "medium"})
            return result

        msg_id = msg_ids[0]
        result["value"] = msg_id

        # Extract domain from Message-ID
        match = re.search(r'@([^>]+)', msg_id)
        if match:
            result["domain"] = match.group(1)
        else:
            result["format_valid"] = False
            result["anomalies"].append({"text": f"Message-ID con formato invalido: {msg_id[:60]}", "severity": "medium"})

        # Compare with From domain
        from_header = (headers.get('From', ['']) or [''])[0]
        from_match = re.search(r'@([^>\s]+)', from_header)
        if from_match and result["domain"]:
            from_domain = from_match.group(1).lower()
            mid_domain = result["domain"].lower()
            if from_domain != mid_domain and not mid_domain.endswith('.' + from_domain):
                result["anomalies"].append({
                    "text": f"Message-ID domain ({mid_domain}) no coincide con From ({from_domain})",
                    "severity": "high"
                })

        # Check for common forged patterns
        if result["domain"]:
            forged_patterns = ['localhost', '127.0.0.1', 'example.com', 'local']
            for fp in forged_patterns:
                if fp in result["domain"].lower():
                    result["anomalies"].append({
                        "text": f"Message-ID contiene patron generico: {fp}",
                        "severity": "medium"
                    })

        return result

    @staticmethod
    def _analyze_dates(headers: dict) -> dict:
        """Analyze date consistency across headers."""
        result = {"anomalies": [], "date_header": None, "hop_dates": [], "timezone_info": None}

        # Parse Date header
        date_str = (headers.get('Date', ['']) or [''])[0]
        if date_str:
            result["date_header"] = date_str
            try:
                from email.utils import parsedate_to_datetime
                email_dt = parsedate_to_datetime(date_str)
                result["timezone_info"] = str(email_dt.tzinfo)

                # Check if date is in the future
                now = datetime.now(timezone.utc)
                if email_dt > now + timedelta(hours=1):
                    result["anomalies"].append({
                        "text": f"Fecha del email en el futuro: {date_str}",
                        "severity": "high"
                    })

                # Check if date is very old (>30 days)
                if (now - email_dt).days > 30:
                    result["anomalies"].append({
                        "text": f"Email con mas de 30 dias de antiguedad: {date_str}",
                        "severity": "low"
                    })

                # Check weekend sending for corporate phishing
                if email_dt.weekday() >= 5:  # Saturday or Sunday
                    result["anomalies"].append({
                        "text": f"Enviado en fin de semana ({email_dt.strftime('%A')})",
                        "severity": "low"
                    })

                # Check unusual hours (before 6am, after 11pm)
                hour = email_dt.hour
                if hour < 6 or hour > 23:
                    result["anomalies"].append({
                        "text": f"Enviado a hora inusual ({email_dt.strftime('%H:%M')} local)",
                        "severity": "low"
                    })

            except Exception:
                result["anomalies"].append({
                    "text": f"No se puede parsear la fecha: {date_str[:60]}",
                    "severity": "medium"
                })
        else:
            result["anomalies"].append({
                "text": "Falta cabecera Date",
                "severity": "medium"
            })

        return result

    @staticmethod
    def _analyze_encoding(headers: dict, raw: str) -> dict:
        """Analyze encoding for suspicious patterns."""
        result = {"anomalies": [], "encodings_found": []}

        # Check Content-Transfer-Encoding
        cte = headers.get('Content-Transfer-Encoding', [])
        for enc in cte:
            result["encodings_found"].append(enc.strip())

        # Check for Base64 encoded subjects (common in spam/phishing)
        subject = (headers.get('Subject', ['']) or [''])[0]
        if '=?utf-8?b?' in subject.lower() or '=?iso' in subject.lower():
            result["anomalies"].append({
                "text": f"Asunto con codificacion MIME (posible evasion de filtros)",
                "severity": "low"
            })

        # Check for unusual character sets
        content_type = (headers.get('Content-Type', ['']) or [''])[0]
        unusual_charsets = ['windows-1251', 'koi8-r', 'gb2312', 'big5', 'euc-kr']
        for cs in unusual_charsets:
            if cs in content_type.lower():
                result["anomalies"].append({
                    "text": f"Charset inusual detectado: {cs}",
                    "severity": "low"
                })

        return result

    @classmethod
    def _check_header_order(cls, headers: dict) -> dict:
        """Check if header order matches expected RFC order."""
        result = {"score": 100, "anomalies": [], "order_analysis": "normal"}

        # Get actual order of headers
        actual_order = list(headers.keys())
        expected_present = [h for h in cls.EXPECTED_ORDER if h in headers]

        # Check if order makes sense
        if actual_order:
            # Received should be before From
            received_idx = None
            from_idx = None
            for i, h in enumerate(actual_order):
                if h == 'Received' and received_idx is None:
                    received_idx = i
                if h == 'From' and from_idx is None:
                    from_idx = i

            if received_idx is not None and from_idx is not None:
                if from_idx < received_idx:
                    result["anomalies"].append({
                        "text": "From aparece antes de Received (orden inusual, posible inyeccion)",
                        "severity": "medium"
                    })
                    result["score"] -= 20

        return result

    @staticmethod
    def _analyze_x_headers(headers: dict) -> dict:
        """Analyze X- custom headers for intelligence."""
        result = {"x_headers": [], "anomalies": [], "mailer_info": None, "originating_ip": None}

        for key, values in headers.items():
            if key.startswith('X-'):
                for v in values:
                    result["x_headers"].append({"header": key, "value": v[:200]})

                    # Extract useful info
                    if key == 'X-Originating-IP':
                        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', v)
                        if ip_match:
                            result["originating_ip"] = ip_match.group(1)

                    if key in ('X-Mailer', 'X-MimeOLE', 'User-Agent'):
                        result["mailer_info"] = v

        return result

    @staticmethod
    def _detect_duplicates(headers: dict) -> dict:
        """Detect suspicious duplicate headers."""
        result = {"duplicates": [], "anomalies": []}
        # Headers that should NOT be duplicated
        unique_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID', 'Reply-To']
        for h in unique_headers:
            if h in headers and len(headers[h]) > 1:
                result["duplicates"].append(h)
                result["anomalies"].append({
                    "text": f"Cabecera duplicada: {h} ({len(headers[h])} veces)",
                    "severity": "high"
                })
        return result

    @staticmethod
    def _find_empty_headers(headers: dict) -> dict:
        """Find headers with empty values."""
        result = {"empty": [], "anomalies": []}
        for key, values in headers.items():
            for v in values:
                if not v.strip():
                    result["empty"].append(key)
                    result["anomalies"].append({
                        "text": f"Cabecera vacia: {key}",
                        "severity": "low"
                    })
        return result

    @staticmethod
    def _detect_header_injection(raw: str) -> dict:
        """Detect potential header injection attacks."""
        result = {"anomalies": []}
        # Look for CRLF injection patterns
        if '\r\n\r\n' in raw.split('\n\n')[0] if '\n\n' in raw else False:
            result["anomalies"].append({
                "text": "Posible inyeccion CRLF detectada en cabeceras",
                "severity": "critical"
            })
        # Look for null bytes
        if '\x00' in raw:
            result["anomalies"].append({
                "text": "Null bytes detectados en cabeceras (posible ataque de inyeccion)",
                "severity": "critical"
            })
        return result

    @staticmethod
    def _analyze_content_headers(headers: dict) -> dict:
        """Analyze content-related headers."""
        result = {"anomalies": [], "has_html": False, "has_attachments": False, "multipart": False}

        content_type = (headers.get('Content-Type', ['']) or [''])[0].lower()
        if 'multipart' in content_type:
            result["multipart"] = True
        if 'text/html' in content_type:
            result["has_html"] = True
        if 'application/' in content_type or 'multipart/mixed' in content_type:
            result["has_attachments"] = True
            result["anomalies"].append({
                "text": "Email contiene adjuntos (verificar archivos)",
                "severity": "medium"
            })

        return result


# =========================================================================
# MODULE 6: URL INTELLIGENCE
# =========================================================================

class URLIntelligence:
    """Advanced URL analysis and categorization."""

    SHORTENERS = [
        'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'ow.ly',
        'buff.ly', 'adf.ly', 'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae',
        'rebrand.ly', 'bl.ink', 'short.io', 'cutt.ly', 'rb.gy', 'clck.ru',
        'shorturl.at', 'v.gd', 'x.co', 'yourls.org', 'mcaf.ee',
        'surl.li', 'shortcm.li', 'dub.sh'
    ]

    SUSPICIOUS_PATTERNS = [
        (r'login|signin|log-in|sign-in', 'Login/Signin page'),
        (r'verify|confirm|validate', 'Verification page'),
        (r'update.*account|account.*update', 'Account update'),
        (r'secure|security', 'Security-related'),
        (r'password|passwd|pwd', 'Password-related'),
        (r'bank|payment|pay|invoice', 'Financial'),
        (r'\.php\?.*=', 'PHP with parameters'),
        (r'\.exe|\.scr|\.bat|\.cmd|\.ps1', 'Executable file'),
        (r'\.zip|\.rar|\.7z|\.tar', 'Archive file'),
        (r'data:text/html', 'Data URI (inline HTML)'),
        (r'javascript:', 'JavaScript URI'),
        (r'@', 'Contains @ symbol (possible credential theft)'),
    ]

    @classmethod
    def analyze_url(cls, url: str) -> dict:
        """Analyze a single URL for threats."""
        result = {
            "url": url,
            "is_shortened": False,
            "shortener_service": None,
            "suspicious_patterns": [],
            "has_ip_address": False,
            "uses_https": url.lower().startswith('https://'),
            "domain": None,
            "path_depth": 0,
            "has_port": False,
            "defanged": cls.defang(url),
            "risk_score": 0
        }

        # Extract domain
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            result["domain"] = parsed.hostname
            result["has_port"] = parsed.port is not None and parsed.port not in (80, 443)
            result["path_depth"] = len([p for p in parsed.path.split('/') if p])
        except:
            pass

        # Check shortener
        if result["domain"]:
            for short in cls.SHORTENERS:
                if result["domain"].lower() == short or result["domain"].lower().endswith('.' + short):
                    result["is_shortened"] = True
                    result["shortener_service"] = short
                    result["risk_score"] += 10
                    break

        # Check for IP address in URL
        if result["domain"] and re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', result["domain"]):
            result["has_ip_address"] = True
            result["risk_score"] += 15

        # Check suspicious patterns
        url_lower = url.lower()
        for pattern, description in cls.SUSPICIOUS_PATTERNS:
            if re.search(pattern, url_lower):
                result["suspicious_patterns"].append(description)
                result["risk_score"] += 5

        # Non-HTTPS
        if not result["uses_https"]:
            result["risk_score"] += 5

        # Unusual port
        if result["has_port"]:
            result["risk_score"] += 10

        return result

    @classmethod
    def analyze_all(cls, urls: list) -> list:
        """Analyze multiple URLs."""
        return [cls.analyze_url(u) for u in urls]

    @staticmethod
    def defang(url: str) -> str:
        """Defang a URL for safe sharing."""
        return url.replace('http://', 'hXXp://').replace('https://', 'hXXps://').replace('.', '[.]')

    @staticmethod
    def defang_ip(ip: str) -> str:
        """Defang an IP address."""
        return ip.replace('.', '[.]')


# =========================================================================
# MODULE 7: SENDER INTELLIGENCE
# =========================================================================

class SenderIntel:
    """Intelligence analysis on email sender."""

    FREE_EMAIL_PROVIDERS = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
        'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com',
        'gmx.com', 'gmx.net', 'mail.ru', 'inbox.com', 'fastmail.com',
        'tutanota.com', 'guerrillamail.com', 'tempmail.com', 'throwaway.email',
        'dispostable.com', 'sharklasers.com', 'guerrillamailblock.com',
        'grr.la', 'mailinator.com', 'temp-mail.org', '10minutemail.com',
        'yopmail.com', 'trashmail.com', 'maildrop.cc'
    ]

    DISPOSABLE_PATTERNS = [
        'temp', 'throw', 'disposable', 'guerrilla', 'trash', 'junk',
        'fake', 'spam', 'burner', '10minute', 'mailinator', 'yopmail',
        'sharklasers', 'grr.la'
    ]

    @classmethod
    def analyze(cls, headers: dict) -> dict:
        """Comprehensive sender analysis."""
        result = {
            "from_header": None,
            "from_display_name": None,
            "from_email": None,
            "from_domain": None,
            "reply_to_email": None,
            "reply_to_domain": None,
            "return_path_email": None,
            "return_path_domain": None,
            "envelope_sender": None,
            "is_free_provider": False,
            "is_disposable": False,
            "display_name_spoofing": False,
            "domain_mismatches": [],
            "anomalies": [],
            "risk_indicators": []
        }

        # Parse From header
        from_h = (headers.get('From', ['']) or [''])[0]
        result["from_header"] = from_h

        # Extract display name and email
        dn_match = re.match(r'"?([^"<]+)"?\s*<([^>]+)>', from_h)
        if dn_match:
            result["from_display_name"] = dn_match.group(1).strip()
            result["from_email"] = dn_match.group(2).strip()
        else:
            email_match = re.search(r'(\S+@\S+)', from_h)
            if email_match:
                result["from_email"] = email_match.group(1)

        if result["from_email"]:
            result["from_domain"] = result["from_email"].split('@')[-1].lower()

        # Reply-To
        rt = (headers.get('Reply-To', ['']) or [''])[0]
        rt_match = re.search(r'<([^>]+)>', rt) or re.search(r'(\S+@\S+)', rt)
        if rt_match:
            result["reply_to_email"] = rt_match.group(1)
            result["reply_to_domain"] = rt_match.group(1).split('@')[-1].lower()

        # Return-Path
        rp = (headers.get('Return-Path', ['']) or [''])[0]
        rp_match = re.search(r'<([^>]+)>', rp) or re.search(r'(\S+@\S+)', rp)
        if rp_match:
            result["return_path_email"] = rp_match.group(1)
            result["return_path_domain"] = rp_match.group(1).split('@')[-1].lower()

        # Check free email provider
        if result["from_domain"] and result["from_domain"] in cls.FREE_EMAIL_PROVIDERS:
            result["is_free_provider"] = True
            result["risk_indicators"].append(f"Proveedor de email gratuito: {result['from_domain']}")

        # Check disposable email
        if result["from_domain"]:
            for pattern in cls.DISPOSABLE_PATTERNS:
                if pattern in result["from_domain"].lower():
                    result["is_disposable"] = True
                    result["risk_indicators"].append(f"Posible email desechable: {result['from_domain']}")
                    break

        # Display name spoofing: name contains an email address
        if result["from_display_name"]:
            if '@' in result["from_display_name"]:
                result["display_name_spoofing"] = True
                result["anomalies"].append({
                    "text": f"Display name contiene email (spoofing): {result['from_display_name'][:60]}",
                    "severity": "high"
                })

            # Display name mimics known brands but email is different
            brand_words = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'bank', 'security']
            dn_lower = result["from_display_name"].lower()
            for brand in brand_words:
                if brand in dn_lower and result["from_domain"] and brand not in result["from_domain"]:
                    result["display_name_spoofing"] = True
                    result["anomalies"].append({
                        "text": f"Display name menciona '{brand}' pero dominio es {result['from_domain']}",
                        "severity": "high"
                    })

        # Domain mismatches
        domains = set()
        if result["from_domain"]:
            domains.add(("From", result["from_domain"]))
        if result["reply_to_domain"]:
            domains.add(("Reply-To", result["reply_to_domain"]))
        if result["return_path_domain"]:
            domains.add(("Return-Path", result["return_path_domain"]))

        unique_domains = set(d[1] for d in domains)
        if len(unique_domains) > 1:
            for header_name, domain in domains:
                result["domain_mismatches"].append({"header": header_name, "domain": domain})
            result["anomalies"].append({
                "text": f"Multiples dominios detectados: {', '.join(f'{h}={d}' for h, d in domains)}",
                "severity": "high"
            })

        return result


# =========================================================================
# MODULE 8: TEMPORAL ANALYZER
# =========================================================================

class TemporalAnalyzer:
    """Analyze timing patterns and timezone consistency."""

    # Common timezone offsets for regions
    TIMEZONE_REGIONS = {
        range(-12, -9): "Pacific/Hawaii",
        range(-9, -6): "Americas/West",
        range(-6, -3): "Americas/Central-East",
        range(-3, 0): "Americas/Atlantic-Brazil",
        range(0, 2): "Europe/West-Africa",
        range(2, 4): "Europe/East-Africa",
        range(4, 6): "Middle East/Central Asia",
        range(6, 9): "South/East Asia",
        range(9, 12): "East Asia/Oceania",
        range(12, 15): "Pacific/NZ",
    }

    @classmethod
    def analyze(cls, headers: dict, hops: list) -> dict:
        """Analyze temporal aspects of the email."""
        result = {
            "date_header": None,
            "date_parsed": None,
            "timezone_offset": None,
            "timezone_region": None,
            "delivery_time": None,
            "hop_analysis": [],
            "suspicious_delays": [],
            "anomalies": [],
            "total_transit_time": None
        }

        # Parse main Date header
        date_str = (headers.get('Date', ['']) or [''])[0]
        if date_str:
            result["date_header"] = date_str
            try:
                from email.utils import parsedate_to_datetime
                dt = parsedate_to_datetime(date_str)
                result["date_parsed"] = dt.isoformat()

                # Timezone offset
                if dt.tzinfo:
                    offset = dt.utcoffset()
                    if offset:
                        hours = offset.total_seconds() / 3600
                        result["timezone_offset"] = hours
                        for offset_range, region in cls.TIMEZONE_REGIONS.items():
                            if int(hours) in offset_range:
                                result["timezone_region"] = region
                                break
            except Exception:
                pass

        # Analyze hops timing
        if hops and len(hops) >= 2:
            for i, hop in enumerate(hops):
                hop_info = {
                    "hop_number": i + 1,
                    "server": hop.get('from_server') or hop.get('by_server', '?'),
                    "timestamp": hop.get('timestamp'),
                    "delay": hop.get('delay_seconds')
                }
                result["hop_analysis"].append(hop_info)

                # Flag suspicious delays
                if hop.get('delay_seconds') is not None:
                    delay = hop['delay_seconds']
                    if delay > 300:  # >5 minutes
                        result["suspicious_delays"].append({
                            "hop": i + 1,
                            "delay_seconds": delay,
                            "text": f"Retraso de {delay:.0f}s en hop {i+1} (posible queuing o relay)",
                            "severity": "medium" if delay < 3600 else "high"
                        })
                    if delay < -60:  # Negative delay >1min (clock skew or manipulation)
                        result["anomalies"].append({
                            "text": f"Retraso negativo en hop {i+1}: {delay:.0f}s (desfase de reloj o manipulacion)",
                            "severity": "high"
                        })

            # Total transit time
            if hops[0].get('datetime') and hops[-1].get('datetime'):
                try:
                    from email.utils import parsedate_to_datetime
                    first = parsedate_to_datetime(hops[0].get('timestamp', ''))
                    last = parsedate_to_datetime(hops[-1].get('timestamp', ''))
                    total = (last - first).total_seconds()
                    result["total_transit_time"] = total
                    if total > 600:  # >10 minutes
                        result["anomalies"].append({
                            "text": f"Tiempo total de transito elevado: {total:.0f}s ({total/60:.1f} min)",
                            "severity": "low"
                        })
                except Exception:
                    pass

        return result


# =========================================================================
# MODULE 9: BODY ANALYZER
# =========================================================================

class BodyAnalyzer:
    """Analyze email body text for malicious content, social engineering, and threats."""

    # Malware hosting CDNs and platforms commonly abused
    MALICIOUS_CDNS = [
        'cdn.discordapp.com', 'cdn.discord.com', 'media.discordapp.net',
        'paste.ee', 'pastebin.com', 'hastebin.com', 'ghostbin.com',
        'transfer.sh', 'file.io', 'anonfiles.com', 'mega.nz',
        'mediafire.com', 'sendspace.com', 'catbox.moe', 'litterbox.catbox.moe',
        'temp.sh', 'gofile.io', 'pixeldrain.com', 'bayfiles.com',
        'raw.githubusercontent.com',
    ]

    # Dangerous file extensions in URLs
    DANGEROUS_EXTENSIONS = [
        '.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse',
        '.wsf', '.wsh', '.hta', '.msi', '.dll', '.com', '.pif',
        '.docm', '.xlsm', '.pptm', '.dotm', '.xltm',
        '.iso', '.img', '.vhd', '.vhdx',
        '.lnk', '.url', '.reg', '.inf',
        '.jar', '.py', '.rb', '.sh',
    ]

    # Social engineering patterns (ES + EN)
    SE_PATTERNS = {
        'urgency': [
            r'urgente|inmediata(?:mente)?|lo antes posible|cuanto antes|de inmediato|sin demora',
            r'urgent|immediate(?:ly)?|asap|right away|without delay|time.sensitive',
            r'en las pr[oó]ximas \d+ horas|within \d+ hours',
        ],
        'action_request': [
            r'confirma[r]?|verificar?|revis[ae]|comprueb[ae]|descarg[ae]|abr[aei]|ejecut[ae]|haz click|haga click|pinch[ae]',
            r'confirm|verify|review|check|download|open|execute|click here|click below',
        ],
        'financial': [
            r'pedido|factura|pago|transferencia|env[ií]o|albar[aá]n|presupuesto|cobro|recibo|liquidaci[oó]n',
            r'invoice|payment|transfer|order|shipment|receipt|billing|wire transfer',
        ],
        'threat': [
            r'suspend|bloque|cancel|restrict|cierr[ae]|desactiv|limit',
            r'suspend|block|cancel|restrict|close|deactivat|limit|terminat',
        ],
        'credential_request': [
            r'contrase[nñ]a|credencial|usuario|login|acceso|iniciar sesi[oó]n|datos de acceso',
            r'password|credential|username|log.?in|access|sign.?in|account detail',
        ],
        'attachment_lure': [
            r'adjunto|archivo adjunto|documento adjunto|ver adjunto|abrir adjunto',
            r'attach(?:ed|ment)|enclosed|see attached|open the file|view document',
        ],
        'impersonation': [
            r'departamento de seguridad|soporte t[eé]cnico|equipo de|servicio de atenci[oó]n',
            r'security department|technical support|team of|customer service|help desk',
        ],
    }

    # Thread hijacking indicators
    THREAD_HIJACK_PATTERNS = [
        r'In-Reply-To:.*?@([^\s>]+)',
        r'References:.*?@([^\s>]+)',
    ]

    @classmethod
    def analyze(cls, body_text: str, headers: dict = None, raw_headers: str = '') -> dict:
        """Full body content analysis."""
        result = {
            "urls_found": [],
            "malicious_urls": [],
            "dangerous_downloads": [],
            "social_engineering": {},
            "se_score": 0,
            "thread_hijacking": None,
            "server_mismatch": None,
            "undisclosed_recipients": False,
            "spam_flagged": False,
            "anomalies": [],
            "risk_flags": [],
        }

        if not body_text:
            return result

        # --- URL Extraction ---
        url_pattern = r'https?://[^\s<>"\'\]\)>]+'
        found_urls = list(set(re.findall(url_pattern, body_text)))
        result["urls_found"] = found_urls

        for url in found_urls:
            url_lower = url.lower()
            issues = []

            # Check malicious CDN hosting
            for cdn in cls.MALICIOUS_CDNS:
                if cdn in url_lower:
                    issues.append(f"URL alojada en plataforma abusada: {cdn}")
                    result["risk_flags"].append({
                        "text": f"URL en CDN sospechoso ({cdn}): {url[:80]}",
                        "severity": "critical", "category": "body_url"
                    })

            # Check dangerous file extensions
            for ext in cls.DANGEROUS_EXTENSIONS:
                if url_lower.endswith(ext) or f'{ext}?' in url_lower or f'{ext}&' in url_lower:
                    issues.append(f"Descarga de archivo peligroso ({ext})")
                    result["dangerous_downloads"].append({
                        "url": url, "extension": ext,
                        "defanged": url.replace('https://', 'hxxps://').replace('http://', 'hxxp://').replace('.', '[.]')
                    })
                    result["risk_flags"].append({
                        "text": f"URL descarga archivo peligroso ({ext}): {url[:80]}",
                        "severity": "critical", "category": "body_download"
                    })

            if issues:
                result["malicious_urls"].append({"url": url, "issues": issues})

        # --- Social Engineering Detection ---
        body_lower = body_text.lower()
        total_se = 0
        for category, patterns in cls.SE_PATTERNS.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, body_lower)
                matches.extend(found)
            if matches:
                result["social_engineering"][category] = list(set(matches))
                weight = {'urgency': 8, 'threat': 10, 'credential_request': 15,
                          'financial': 5, 'action_request': 5, 'attachment_lure': 5,
                          'impersonation': 8}.get(category, 3)
                total_se += weight
                result["risk_flags"].append({
                    "text": f"Ingenieria social [{category}]: {', '.join(list(set(matches))[:3])}",
                    "severity": "high" if weight >= 8 else "medium",
                    "category": "social_engineering"
                })
        result["se_score"] = min(total_se, 30)

        # --- Thread Hijacking Detection ---
        if raw_headers:
            from_match = re.search(r'From:.*?@([^\s>]+)', raw_headers)
            from_domain = from_match.group(1).lower().rstrip('>') if from_match else ''

            for pattern in cls.THREAD_HIJACK_PATTERNS:
                m = re.search(pattern, raw_headers)
                if m:
                    ref_domain = m.group(1).lower().rstrip('>')
                    if ref_domain and from_domain and ref_domain != from_domain:
                        result["thread_hijacking"] = {
                            "from_domain": from_domain,
                            "reference_domain": ref_domain,
                            "description": f"Email responde a hilo de @{ref_domain} pero viene de @{from_domain}"
                        }
                        result["risk_flags"].append({
                            "text": f"Thread hijacking: responde a @{ref_domain} desde @{from_domain}",
                            "severity": "critical", "category": "thread_hijacking"
                        })
                        break

            # Server vs From mismatch
            received_servers = re.findall(r'from\s+(\S+)', raw_headers, re.IGNORECASE)
            if from_domain and received_servers:
                for srv in received_servers:
                    srv_domain = srv.lower().strip('([])')
                    if '.' in srv_domain and from_domain not in srv_domain and srv_domain not in from_domain:
                        # Exclude well-known relay servers
                        if not any(x in srv_domain for x in ['google.com', 'outlook.com', 'microsoft.com', 'amazonses.com']):
                            result["server_mismatch"] = {
                                "server": srv_domain, "from_domain": from_domain
                            }
                            result["risk_flags"].append({
                                "text": f"Servidor de envio ({srv_domain}) no coincide con remitente ({from_domain})",
                                "severity": "high", "category": "server_mismatch"
                            })
                            break

            # Undisclosed recipients
            if 'undisclosed-recipients' in raw_headers.lower():
                result["undisclosed_recipients"] = True
                result["risk_flags"].append({
                    "text": "To: undisclosed-recipients (envio masivo oculto)",
                    "severity": "high", "category": "mass_send"
                })

            # X-Spam-Flag
            spam_match = re.search(r'X-Spam-Flag:\s*YES', raw_headers, re.IGNORECASE)
            if spam_match:
                result["spam_flagged"] = True
                result["risk_flags"].append({
                    "text": "X-Spam-Flag: YES (servidor destino lo marco como SPAM)",
                    "severity": "high", "category": "spam_flag"
                })

        return result


# =========================================================================
# MODULE 10: ATTACHMENT ANALYZER
# =========================================================================

class AttachmentAnalyzer:
    """Analyze email attachments for threats."""

    DANGEROUS_EXTENSIONS = {
        'critical': ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse',
                     '.wsf', '.wsh', '.hta', '.msi', '.dll', '.com', '.pif', '.cpl', '.inf', '.reg'],
        'high': ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm', '.xlam', '.ppam',
                 '.iso', '.img', '.vhd', '.vhdx', '.lnk', '.url', '.jar'],
        'medium': ['.zip', '.rar', '.7z', '.tar', '.gz', '.cab', '.arj',
                   '.doc', '.xls', '.ppt', '.rtf', '.pdf'],
    }

    DOUBLE_EXTENSION_PATTERNS = [
        r'\.\w{2,4}\.(exe|scr|bat|cmd|ps1|vbs|js|hta|msi|dll|com|pif)$',
        r'\.\w{2,4}\.(zip|rar|7z|iso|img)$',
    ]

    @classmethod
    def analyze(cls, attachments: list) -> dict:
        """
        Analyze a list of attachments.
        Each attachment: {"filename": str, "size": int, "sha256": str, "mime_type": str}
        """
        result = {
            "total": len(attachments),
            "dangerous": [],
            "suspicious": [],
            "clean": [],
            "anomalies": [],
            "risk_flags": [],
        }

        for att in attachments:
            fn = att.get('filename', '').lower()
            ext = '.' + fn.rsplit('.', 1)[-1] if '.' in fn else ''
            sha = att.get('sha256', '')
            size = att.get('size', 0)
            mime = att.get('mime_type', '')

            assessment = {"filename": att.get('filename', ''), "extension": ext,
                         "size": size, "sha256": sha, "mime_type": mime, "issues": []}

            # Check dangerous extensions
            severity = None
            for sev, exts in cls.DANGEROUS_EXTENSIONS.items():
                if ext in exts:
                    severity = sev
                    assessment["issues"].append(f"Extension peligrosa ({ext}) - {sev}")
                    break

            # Double extension check
            for pattern in cls.DOUBLE_EXTENSION_PATTERNS:
                if re.search(pattern, fn, re.IGNORECASE):
                    assessment["issues"].append(f"Doble extension detectada: {fn}")
                    severity = severity or 'high'

            # MIME type mismatch
            if mime and ext:
                mime_ext_map = {
                    'image/png': ['.png'], 'image/jpeg': ['.jpg', '.jpeg'],
                    'application/pdf': ['.pdf'], 'application/zip': ['.zip'],
                    'application/x-msdownload': ['.exe', '.dll'],
                    'text/javascript': ['.js'], 'application/javascript': ['.js'],
                }
                expected = mime_ext_map.get(mime, [])
                if expected and ext not in expected:
                    assessment["issues"].append(f"MIME ({mime}) no coincide con extension ({ext})")

            # Size anomalies
            if size > 0 and ext in ['.png', '.jpg', '.gif', '.bmp'] and size > 5_000_000:
                assessment["issues"].append(f"Imagen inusualmente grande ({size/1024/1024:.1f}MB)")

            # Random-looking filename (hex hash names)
            if re.match(r'^[0-9a-f]{8,}\.', fn):
                assessment["issues"].append("Nombre de archivo aleatorio (posible generado automaticamente)")

            # Classify
            if severity == 'critical' or len(assessment["issues"]) >= 3:
                result["dangerous"].append(assessment)
                for issue in assessment["issues"]:
                    result["risk_flags"].append({
                        "text": f"Adjunto peligroso: {issue} ({att.get('filename','')})",
                        "severity": "critical" if severity == 'critical' else "high",
                        "category": "attachment"
                    })
            elif severity or assessment["issues"]:
                result["suspicious"].append(assessment)
                for issue in assessment["issues"]:
                    result["risk_flags"].append({
                        "text": f"Adjunto sospechoso: {issue} ({att.get('filename','')})",
                        "severity": severity or "medium", "category": "attachment"
                    })
            else:
                result["clean"].append(assessment)

        return result


# =========================================================================
# MODULE 11: MSG PARSER (OLE2 Compound Binary)
# =========================================================================

class MsgParser:
    """
    Parse Microsoft Outlook .msg files (OLE2 Compound Binary Format).
    No external dependencies - pure Python using struct.
    """

    # MAPI Property IDs
    PROP_MAP = {
        '0037': 'subject', '0042': 'sender_name_repr',
        '0065': 'sender_email_repr', '0070': 'conversation_topic',
        '007D': 'transport_headers', '0C1A': 'sender_name',
        '0C1F': 'sender_email', '0E04': 'display_to',
        '1000': 'body', '1009': 'rtf_body', '1013': 'html_body',
        '1035': 'internet_message_id', '3001': 'display_name',
        '3003': 'email_address', '3701': 'attach_data',
        '3704': 'attach_filename', '3707': 'attach_long_filename',
        '370E': 'attach_mime_tag', '3712': 'content_id',
    }

    @classmethod
    def parse(cls, file_path: str) -> dict:
        """Parse a .msg file and extract all components."""
        with open(file_path, 'rb') as f:
            data = f.read()

        if data[:8] != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
            return {"error": "Not a valid OLE2/MSG file"}

        result = {
            "subject": "", "sender_name": "", "sender_email": "",
            "display_to": "", "body": "", "transport_headers": "",
            "internet_message_id": "", "attachments": [],
            "properties": {}, "raw_entries": [],
        }

        try:
            sector_size = 1 << struct.unpack_from('<H', data, 30)[0]
            mini_sector_size = 1 << struct.unpack_from('<H', data, 32)[0]
            dir_start = struct.unpack_from('<I', data, 48)[0]
            mini_cutoff = struct.unpack_from('<I', data, 56)[0]
            minifat_start = struct.unpack_from('<I', data, 60)[0]

            # Read DIFAT
            difat = []
            for i in range(109):
                val = struct.unpack_from('<I', data, 76 + i*4)[0]
                if val < 0xFFFFFFFE:
                    difat.append(val)

            def sector_offset(sid):
                return (sid + 1) * sector_size

            def read_sector(sid):
                off = sector_offset(sid)
                return data[off:off+sector_size]

            # Build FAT
            fat = []
            for sid in difat:
                sector = read_sector(sid)
                for i in range(0, sector_size, 4):
                    fat.append(struct.unpack_from('<I', sector, i)[0])

            def follow_chain(start):
                chain = []
                sid = start
                visited = set()
                while sid < 0xFFFFFFFE and sid not in visited:
                    visited.add(sid)
                    chain.append(sid)
                    sid = fat[sid] if sid < len(fat) else 0xFFFFFFFE
                return chain

            def read_stream(start, size):
                result_bytes = b''
                for sid in follow_chain(start):
                    result_bytes += read_sector(sid)
                return result_bytes[:size]

            # Read directory
            entries = []
            for sid in follow_chain(dir_start):
                sector = read_sector(sid)
                for i in range(0, sector_size, 128):
                    entry = sector[i:i+128]
                    name_len = struct.unpack_from('<H', entry, 64)[0]
                    if name_len == 0:
                        continue
                    name = entry[:name_len-2].decode('utf-16-le', errors='replace')
                    etype = entry[66]
                    estart = struct.unpack_from('<I', entry, 116)[0]
                    esize = struct.unpack_from('<I', entry, 120)[0]
                    entries.append({'name': name, 'type': etype, 'start': estart, 'size': esize})

            # Build mini stream
            root_data = b''
            if entries:
                root = entries[0]
                if root['size'] > 0:
                    root_data = read_stream(root['start'], root['size'])

            # Mini FAT
            minifat = []
            if minifat_start < 0xFFFFFFFE:
                for sid in follow_chain(minifat_start):
                    sector = read_sector(sid)
                    for i in range(0, sector_size, 4):
                        minifat.append(struct.unpack_from('<I', sector, i)[0])

            def read_mini_stream(start, size):
                result_bytes = b''
                sid = start
                visited = set()
                while sid < 0xFFFFFFFE and sid not in visited:
                    visited.add(sid)
                    off = sid * mini_sector_size
                    result_bytes += root_data[off:off+mini_sector_size]
                    sid = minifat[sid] if sid < len(minifat) else 0xFFFFFFFE
                return result_bytes[:size]

            def get_entry_data(entry):
                if entry['size'] == 0:
                    return b''
                if entry['size'] < mini_cutoff:
                    return read_mini_stream(entry['start'], entry['size'])
                return read_stream(entry['start'], entry['size'])

            def try_decode(raw):
                for enc in ['utf-8', 'utf-16-le', 'latin-1', 'cp1252']:
                    try:
                        text = raw.decode(enc)
                        if '\x00' not in text[:100] or enc == 'utf-16-le':
                            return text.replace('\x00', '')
                    except:
                        continue
                return raw.decode('latin-1', errors='replace')

            # Extract properties
            current_attach = None
            attach_list = []

            for entry in entries:
                name = entry['name']
                result["raw_entries"].append({"name": name, "type": entry['type'], "size": entry['size']})

                # Track attachment storages
                if name.startswith('__attach_version1.0_'):
                    current_attach = {"filename": "", "long_filename": "", "mime_type": "",
                                      "size": 0, "sha256": "", "content_id": ""}
                    attach_list.append(current_attach)
                    continue

                m = re.match(r'__substg1\.0_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})', name)
                if not m or entry['size'] == 0:
                    continue

                prop_id = m.group(1).upper()
                prop_type = m.group(2).upper()
                prop_name = cls.PROP_MAP.get(prop_id)

                try:
                    raw = get_entry_data(entry)

                    if prop_id == '3701':  # Binary attachment data
                        if current_attach is not None:
                            current_attach['size'] = len(raw)
                            current_attach['sha256'] = hashlib.sha256(raw).hexdigest()
                        continue

                    if prop_type in ('001F', '001E'):
                        text = try_decode(raw)
                        if prop_name:
                            if prop_name in ('subject', 'body', 'transport_headers',
                                            'sender_name', 'sender_email', 'display_to',
                                            'internet_message_id'):
                                result[prop_name] = text
                            elif prop_name == 'attach_filename' and current_attach:
                                current_attach['filename'] = text
                            elif prop_name == 'attach_long_filename' and current_attach:
                                current_attach['long_filename'] = text
                            elif prop_name == 'attach_mime_tag' and current_attach:
                                current_attach['mime_type'] = text
                            elif prop_name == 'content_id' and current_attach:
                                current_attach['content_id'] = text
                        result["properties"][prop_id] = text[:500]
                except Exception:
                    pass

            # Finalize attachments
            for att in attach_list:
                fn = att.get('long_filename') or att.get('filename') or 'unknown'
                result["attachments"].append({
                    "filename": fn,
                    "size": att.get('size', 0),
                    "sha256": att.get('sha256', ''),
                    "mime_type": att.get('mime_type', ''),
                    "content_id": att.get('content_id', ''),
                })

        except Exception as e:
            result["error"] = str(e)

        return result


# =========================================================================
# MASTER ANALYSIS ORCHESTRATOR
# =========================================================================

def run_enhanced_analysis(base_analysis: dict, raw_headers: str, enable_network: bool = True,
                          body_text: str = '', attachments: list = None) -> dict:
    """
    Run ALL enhanced analysis modules on top of the base analysis.
    base_analysis: dict from analyze_full() with parsed_headers, hops, auth, iocs, risk
    enable_network: if True, makes network calls (GeoIP, DNSBL, DNS).
    """
    parsed = base_analysis['parsed_headers']
    hops = base_analysis['hops']
    auth = base_analysis['auth']
    iocs = base_analysis['iocs']
    risk = base_analysis['risk']

    # --- Enhanced Modules ---

    # Module 1: DNS Resolution
    dns_results = {}
    if enable_network:
        for domain in iocs['domains'][:5]:  # Limit to top 5
            dns_results[domain] = {
                "resolve": DNSResolver.resolve_a(domain),
                "mx": DNSResolver.query_mx_via_dns(domain),
                "txt": DNSResolver.query_txt_via_dns(domain),
            }
        # Reverse DNS for public IPs
        for ip in iocs['public_ips'][:5]:
            dns_results[f"PTR:{ip}"] = DNSResolver.reverse_dns(ip)

    # Module 2: DNSBL Check
    dnsbl_results = {}
    if enable_network:
        for ip in iocs['public_ips'][:3]:  # Limit to 3 IPs
            dnsbl_results[ip] = DNSBLChecker.check_ip(ip)

    # Module 3: GeoIP
    geoip_results = {}
    if enable_network and HAS_REQUESTS:
        for ip in iocs['public_ips'][:5]:
            geoip_results[ip] = GeoIPLookup.lookup(ip)

    # Module 4: Homoglyph detection
    homoglyph_results = HomoglyphDetector.analyze_all_domains(iocs['domains'])

    # Levenshtein brand similarity
    brands = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'netflix',
              'facebook', 'instagram', 'linkedin', 'dropbox', 'adobe',
              'chase', 'wellsfargo', 'citibank', 'santander', 'bbva']
    brand_similarity = []
    for d in iocs['domains']:
        sims = HomoglyphDetector.find_brand_similarity(d, brands)
        if sims:
            brand_similarity.extend(sims)

    # Module 5: Header Forensics
    forensics = HeaderForensics.analyze(parsed, raw_headers)

    # Module 6: URL Intelligence
    url_analysis = URLIntelligence.analyze_all(iocs['urls'])

    # Module 7: Sender Intelligence
    sender_intel = SenderIntel.analyze(parsed)

    # Module 8: Temporal Analysis
    temporal = TemporalAnalyzer.analyze(parsed, hops)

    # --- Risk Scoring (enhanced) ---
    # Deep copy risk to avoid mutating the base analysis
    import copy
    risk = copy.deepcopy(risk)

    # Add extra risk from new modules
    extra_flags = []
    extra_score = 0

    # DNSBL hits
    for ip, bl_result in dnsbl_results.items():
        if bl_result.get('is_blacklisted'):
            extra_score += min(bl_result['listed_count'] * 5, 15)
            lists = ', '.join(r['name'] for r in bl_result['listed_on'][:3])
            extra_flags.append({
                "text": f"IP {ip} en {bl_result['listed_count']} blacklists: {lists}",
                "severity": "critical", "category": "blacklist"
            })

    # GeoIP flags
    for ip, geo in geoip_results.items():
        if geo.get('is_proxy'):
            extra_score += 10
            extra_flags.append({
                "text": f"IP {ip} detectada como PROXY ({geo.get('isp','?')})",
                "severity": "high", "category": "geoip"
            })
        if geo.get('is_hosting'):
            extra_score += 5
            extra_flags.append({
                "text": f"IP {ip} es un servidor de HOSTING ({geo.get('org','?')}, {geo.get('country','?')})",
                "severity": "medium", "category": "geoip"
            })

    # Homoglyph flags
    for hg in homoglyph_results:
        if hg.get('has_homoglyphs'):
            extra_score += 20
            extra_flags.append({
                "text": f"HOMOGLYPH detectado en '{hg['domain']}' (equiv. ASCII: {hg['ascii_equivalent']})",
                "severity": "critical", "category": "homoglyph"
            })
        if hg.get('has_mixed_scripts'):
            extra_score += 15
            extra_flags.append({
                "text": f"Scripts mixtos en '{hg['domain']}': {', '.join(hg['scripts_detected'])}",
                "severity": "critical", "category": "homoglyph"
            })

    # Brand similarity
    for sim in brand_similarity:
        if sim['similarity'] >= 80 and not sim['is_exact']:
            extra_score += 10
            extra_flags.append({
                "text": f"Dominio '{sim['domain']}' {sim['similarity']}% similar a '{sim['brand']}'",
                "severity": "high", "category": "brand_impersonation"
            })

    # Sender intel flags
    if sender_intel.get('is_disposable'):
        extra_score += 15
        extra_flags.append({
            "text": f"Email desechable/temporal: {sender_intel.get('from_domain')}",
            "severity": "high", "category": "sender"
        })
    if sender_intel.get('display_name_spoofing'):
        extra_score += 10

    # Header forensics anomalies
    for anomaly in forensics.get('anomalies', []):
        severity_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2}
        extra_score += severity_scores.get(anomaly['severity'], 0)
        extra_flags.append({**anomaly, "category": "forensics"})

    # URL intelligence
    for ua in url_analysis:
        if ua.get('is_shortened'):
            extra_score += 5
            extra_flags.append({
                "text": f"URL acortada detectada: {ua['shortener_service']} ({ua['url'][:60]})",
                "severity": "medium", "category": "url"
            })
        if ua.get('has_ip_address'):
            extra_score += 8
            extra_flags.append({
                "text": f"URL con IP directa: {ua['url'][:60]}",
                "severity": "high", "category": "url"
            })

    # Temporal anomalies
    for anomaly in temporal.get('anomalies', []):
        extra_flags.append({**anomaly, "category": "temporal"})
    for delay in temporal.get('suspicious_delays', []):
        extra_flags.append({
            "text": delay['text'],
            "severity": delay['severity'],
            "category": "temporal"
        })

    # Module 9: Body Analysis
    body_analysis = {}
    if body_text:
        body_analysis = BodyAnalyzer.analyze(body_text, parsed, raw_headers)
        for bf in body_analysis.get('risk_flags', []):
            severity_scores = {'critical': 15, 'high': 8, 'medium': 4, 'low': 2}
            extra_score += severity_scores.get(bf['severity'], 0)
            extra_flags.append(bf)

    # Module 10: Attachment Analysis
    attachment_analysis = {}
    if attachments:
        attachment_analysis = AttachmentAnalyzer.analyze(attachments)
        for af in attachment_analysis.get('risk_flags', []):
            severity_scores = {'critical': 15, 'high': 8, 'medium': 4, 'low': 2}
            extra_score += severity_scores.get(af['severity'], 0)
            extra_flags.append(af)

    # Update risk with extra data
    risk['flags'].extend(extra_flags)
    risk['score'] = min(risk['score'] + extra_score, 100)
    risk['flag_count'] = len(risk['flags'])

    # Recalculate verdict
    if risk['score'] >= 70:
        risk['verdict'] = 'PHISHING'
        risk['risk_level'] = 'critical'
    elif risk['score'] >= 50:
        risk['verdict'] = 'HIGH_RISK'
        risk['risk_level'] = 'high'
    elif risk['score'] >= 30:
        risk['verdict'] = 'SUSPICIOUS'
        risk['risk_level'] = 'medium'
    elif risk['score'] >= 15:
        risk['verdict'] = 'LOW_RISK'
        risk['risk_level'] = 'low'
    else:
        risk['verdict'] = 'CLEAN'
        risk['risk_level'] = 'clean'

    # Build enhanced result (merge with base analysis)
    result = {
        "id": base_analysis['id'],
        "timestamp": base_analysis['timestamp'],
        "hash": base_analysis['hash'],
        "parsed_headers": parsed,
        "hops": hops,
        "auth": auth,
        "iocs": iocs,
        "risk": risk,
        # Enhanced modules
        "dns_results": dns_results,
        "dnsbl_results": dnsbl_results,
        "geoip_results": geoip_results,
        "homoglyph_analysis": homoglyph_results,
        "brand_similarity": brand_similarity,
        "header_forensics": forensics,
        "url_analysis": url_analysis,
        "sender_intel": sender_intel,
        "temporal_analysis": temporal,
        "body_analysis": body_analysis,
        "attachment_analysis": attachment_analysis,
        # Meta
        "modules_used": [
            "HeaderParser", "IOCExtractor", "AuthAnalyzer", "RiskEngine",
            "BodyAnalyzer", "AttachmentAnalyzer",
            "DNSResolver", "DNSBLChecker", "GeoIPLookup", "HomoglyphDetector",
            "HeaderForensics", "URLIntelligence", "SenderIntel", "TemporalAnalyzer"
        ]
    }

    return result
