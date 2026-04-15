#!/usr/bin/env python3
"""
External Threat Intelligence Connectors
========================================
Safe integrations with VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, IPQualityScore
using stdlib only (urllib.request, json, ssl).
"""

import json
import urllib.request
import urllib.error
import ssl
from typing import Dict, Any, Optional


class ThreatIntelConnector:
    """Unified interface for external threat intelligence APIs."""

    TIMEOUT = 10
    AI_TIMEOUT = 30

    @staticmethod
    def _create_ssl_context():
        """Create default SSL context for HTTPS."""
        return ssl.create_default_context()

    @staticmethod
    def _safe_request(url: str, headers: Dict[str, str] = None, timeout: int = 10) -> Optional[Dict]:
        """Safe HTTP GET request with error handling."""
        try:
            ctx = ThreatIntelConnector._create_ssl_context()
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError, Exception) as e:
            return {"error": f"API request failed: {str(e)}"}

    # ========================================================================
    # VIRUSTOTAL (v3 API)
    # ========================================================================

    @staticmethod
    def virustotal_check_ip(ip: str, api_key: str) -> Dict[str, Any]:
        """Check IP reputation on VirusTotal."""
        if not ip or not api_key:
            return {"error": "Missing IP or API key"}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": api_key}
        result = ThreatIntelConnector._safe_request(url, headers, ThreatIntelConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            data = result.get("data", {})
            attrs = data.get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})

            return {
                "malicious_count": last_analysis.get("malicious", 0),
                "suspicious_count": last_analysis.get("suspicious", 0),
                "engines": attrs.get("last_analysis_date"),
                "country": attrs.get("country", "Unknown"),
                "as_owner": attrs.get("as_owner", "Unknown"),
                "reputation": attrs.get("reputation", 0),
                "last_analysis_stats": last_analysis
            }
        except Exception as e:
            return {"error": f"Failed to parse VirusTotal response: {str(e)}"}

    @staticmethod
    def virustotal_check_domain(domain: str, api_key: str) -> Dict[str, Any]:
        """Check domain reputation on VirusTotal."""
        if not domain or not api_key:
            return {"error": "Missing domain or API key"}

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key}
        result = ThreatIntelConnector._safe_request(url, headers, ThreatIntelConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            data = result.get("data", {})
            attrs = data.get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})
            whois = attrs.get("whois", "")

            return {
                "malicious_count": last_analysis.get("malicious", 0),
                "suspicious_count": last_analysis.get("suspicious", 0),
                "registrar": attrs.get("registrar", "Unknown"),
                "creation_date": attrs.get("creation_date", "Unknown"),
                "reputation": attrs.get("reputation", 0),
                "categories": attrs.get("categories", {}),
                "last_analysis_stats": last_analysis
            }
        except Exception as e:
            return {"error": f"Failed to parse VirusTotal response: {str(e)}"}

    @staticmethod
    def virustotal_check_hash(hash_val: str, api_key: str) -> Dict[str, Any]:
        """Check file hash on VirusTotal."""
        if not hash_val or not api_key:
            return {"error": "Missing hash or API key"}

        url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
        headers = {"x-apikey": api_key}
        result = ThreatIntelConnector._safe_request(url, headers, ThreatIntelConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            data = result.get("data", {})
            attrs = data.get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})

            return {
                "malicious_count": last_analysis.get("malicious", 0),
                "suspicious_count": last_analysis.get("suspicious", 0),
                "type_description": attrs.get("type_description", "Unknown"),
                "names": attrs.get("names", []),
                "tags": attrs.get("tags", []),
                "last_analysis_stats": last_analysis
            }
        except Exception as e:
            return {"error": f"Failed to parse VirusTotal response: {str(e)}"}

    @staticmethod
    def virustotal_check_url(url_to_check: str, api_key: str) -> Dict[str, Any]:
        """Check URL on VirusTotal."""
        if not url_to_check or not api_key:
            return {"error": "Missing URL or API key"}

        import base64
        # URL IDs in VT are base64-encoded
        url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().rstrip('=')
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": api_key}
        result = ThreatIntelConnector._safe_request(url, headers, ThreatIntelConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            data = result.get("data", {})
            attrs = data.get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})

            return {
                "malicious_count": last_analysis.get("malicious", 0),
                "suspicious_count": last_analysis.get("suspicious", 0),
                "categories": attrs.get("categories", {}),
                "last_analysis_stats": last_analysis
            }
        except Exception as e:
            return {"error": f"Failed to parse VirusTotal response: {str(e)}"}

    # ========================================================================
    # ABUSEIPDB (v2)
    # ========================================================================

    @staticmethod
    def abuseipdb_check_ip(ip: str, api_key: str) -> Dict[str, Any]:
        """Check IP on AbuseIPDB."""
        if not ip or not api_key:
            return {"error": "Missing IP or API key"}

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
        headers = {"Key": api_key, "Accept": "application/json"}
        result = ThreatIntelConnector._safe_request(url, headers, ThreatIntelConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            data = result.get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "usage_type": data.get("usageType", "Unknown"),
                "total_reports": data.get("totalReports", 0),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False)
            }
        except Exception as e:
            return {"error": f"Failed to parse AbuseIPDB response: {str(e)}"}

    # ========================================================================
    # SHODAN
    # ========================================================================

    @staticmethod
    def shodan_check_ip(ip: str, api_key: str) -> Dict[str, Any]:
        """Check IP on Shodan."""
        if not ip or not api_key:
            return {"error": "Missing IP or API key"}

        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        result = ThreatIntelConnector._safe_request(url, timeout=ThreatIntelConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            return {
                "ports": result.get("ports", []),
                "vulns": result.get("vulns", []),
                "os": result.get("os", "Unknown"),
                "isp": result.get("isp", "Unknown"),
                "org": result.get("org", "Unknown"),
                "country": result.get("country_name", "Unknown"),
                "city": result.get("city", "Unknown"),
                "hostnames": result.get("hostnames", [])
            }
        except Exception as e:
            return {"error": f"Failed to parse Shodan response: {str(e)}"}

    # ========================================================================
    # ALIENVAULT OTX
    # ========================================================================

    @staticmethod
    def otx_check_ip(ip: str, api_key: str) -> Dict[str, Any]:
        """Check IP on AlienVault OTX."""
        if not ip or not api_key:
            return {"error": "Missing IP or API key"}

        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": api_key}
        result = ThreatIntelConnector._safe_request(url, headers, ThreatIntelConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            return {
                "pulse_count": result.get("pulse_count", 0),
                "reputation": result.get("reputation", 0),
                "country": result.get("country", "Unknown"),
                "asn": result.get("asn", "Unknown"),
                "related_pulses": len(result.get("pulses", []))
            }
        except Exception as e:
            return {"error": f"Failed to parse OTX response: {str(e)}"}

    @staticmethod
    def otx_check_domain(domain: str, api_key: str) -> Dict[str, Any]:
        """Check domain on AlienVault OTX."""
        if not domain or not api_key:
            return {"error": "Missing domain or API key"}

        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": api_key}
        result = ThreatIntelConnector._safe_request(url, headers, ThreatIntelConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            return {
                "pulse_count": result.get("pulse_count", 0),
                "whois": result.get("whois", ""),
                "malware_count": len(result.get("malware", []))
            }
        except Exception as e:
            return {"error": f"Failed to parse OTX response: {str(e)}"}

    # ========================================================================
    # IPQUALITYSCORE
    # ========================================================================

    @staticmethod
    def ipqualityscore_check_ip(ip: str, api_key: str) -> Dict[str, Any]:
        """Check IP on IPQualityScore."""
        if not ip or not api_key:
            return {"error": "Missing IP or API key"}

        url = f"https://ipqualityscore.com/api/json/ip/{api_key}/{ip}"
        result = ThreatIntelConnector._safe_request(url, timeout=ThreatIntelConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            return {
                "fraud_score": result.get("fraud_score", 0),
                "is_proxy": result.get("is_proxy", False),
                "is_vpn": result.get("is_vpn", False),
                "is_tor": result.get("is_tor", False),
                "is_bot": result.get("is_bot", False),
                "is_crawler": result.get("is_crawler", False),
                "country": result.get("country_code", "Unknown"),
                "isp": result.get("isp", "Unknown"),
                "abuse_velocity": result.get("abuse_velocity", "Unknown")
            }
        except Exception as e:
            return {"error": f"Failed to parse IPQualityScore response: {str(e)}"}

    # ========================================================================
    # ENRICHMENT UTILITY
    # ========================================================================

    @staticmethod
    def enrich_analysis(analysis: Dict[str, Any], api_keys: Dict[str, str]) -> Dict[str, Any]:
        """
        Auto-enrich an analysis with all available threat intel APIs.
        Extracts IPs, domains, URLs, and hashes from analysis and checks each with available APIs.

        Returns: {enrichment: {ip: {...}, domain: {...}, url: {...}, hash: {...}}}
        """
        enrichment = {
            "ips": {},
            "domains": {},
            "urls": {},
            "hashes": {},
            "timestamp": None
        }

        from datetime import datetime
        enrichment["timestamp"] = datetime.utcnow().isoformat()

        # Extract IoCs from analysis
        iocs = analysis.get("iocs", {})

        # Enrich IPs
        for ip in iocs.get("ips", []):
            if not ip or ip in enrichment["ips"]:
                continue
            ip_result = {}

            if "virustotal" in api_keys:
                ip_result["virustotal"] = ThreatIntelConnector.virustotal_check_ip(ip, api_keys["virustotal"])
            if "abuseipdb" in api_keys:
                ip_result["abuseipdb"] = ThreatIntelConnector.abuseipdb_check_ip(ip, api_keys["abuseipdb"])
            if "shodan" in api_keys:
                ip_result["shodan"] = ThreatIntelConnector.shodan_check_ip(ip, api_keys["shodan"])
            if "otx" in api_keys:
                ip_result["otx"] = ThreatIntelConnector.otx_check_ip(ip, api_keys["otx"])
            if "ipqualityscore" in api_keys:
                ip_result["ipqualityscore"] = ThreatIntelConnector.ipqualityscore_check_ip(ip, api_keys["ipqualityscore"])

            enrichment["ips"][ip] = ip_result

        # Enrich domains
        for domain in iocs.get("domains", []):
            if not domain or domain in enrichment["domains"]:
                continue
            domain_result = {}

            if "virustotal" in api_keys:
                domain_result["virustotal"] = ThreatIntelConnector.virustotal_check_domain(domain, api_keys["virustotal"])
            if "otx" in api_keys:
                domain_result["otx"] = ThreatIntelConnector.otx_check_domain(domain, api_keys["otx"])

            enrichment["domains"][domain] = domain_result

        # Enrich URLs
        for url in iocs.get("urls", []):
            if not url or url in enrichment["urls"]:
                continue
            url_result = {}

            if "virustotal" in api_keys:
                url_result["virustotal"] = ThreatIntelConnector.virustotal_check_url(url, api_keys["virustotal"])

            enrichment["urls"][url] = url_result

        # Enrich hashes
        for hash_val in iocs.get("hashes", []):
            if not hash_val or hash_val in enrichment["hashes"]:
                continue
            hash_result = {}

            if "virustotal" in api_keys:
                hash_result["virustotal"] = ThreatIntelConnector.virustotal_check_hash(hash_val, api_keys["virustotal"])

            enrichment["hashes"][hash_val] = hash_result

        return enrichment


class AIConnector:
    """Unified interface for AI-powered threat analysis."""

    TIMEOUT = 30

    @staticmethod
    def _create_ssl_context():
        """Create default SSL context for HTTPS."""
        return ssl.create_default_context()

    @staticmethod
    def _safe_request(url: str, headers: Dict[str, str] = None, data: bytes = None, timeout: int = 30) -> Optional[Dict]:
        """Safe HTTP POST request with error handling."""
        try:
            ctx = AIConnector._create_ssl_context()
            req = urllib.request.Request(url, headers=headers or {}, data=data)
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError, Exception) as e:
            return {"error": f"API request failed: {str(e)}"}

    # ========================================================================
    # OPENAI CHATGPT
    # ========================================================================

    @staticmethod
    def openai_analyze(analysis: Dict[str, Any], api_key: str, model: str = 'gpt-4o-mini') -> Dict[str, Any]:
        """Send analysis to ChatGPT for threat assessment."""
        if not api_key:
            return {"error": "Missing OpenAI API key"}

        # Build focused prompt in Spanish
        risk_score = analysis.get("risk", {}).get("score", 0)
        flags = analysis.get("risk", {}).get("flags", [])
        iocs = analysis.get("iocs", {})
        auth_status = analysis.get("auth_status", {})

        prompt = f"""Analiza el siguiente incidente de seguridad de correo electrónico y proporciona una evaluación de amenaza detallada.

**Información del Análisis:**
- Puntuación de Riesgo: {risk_score}/100
- Veredicto: {analysis.get('risk', {}).get('verdict', 'desconocido')}
- Indicadores de Riesgo: {', '.join(flags[:5]) if flags else 'ninguno'}
- IPs Detectadas: {', '.join(iocs.get('ips', [])[:5]) if iocs.get('ips') else 'ninguna'}
- Dominios Detectados: {', '.join(iocs.get('domains', [])[:5]) if iocs.get('domains') else 'ninguno'}
- URLs Sospechosas: {', '.join(iocs.get('urls', [])[:3]) if iocs.get('urls') else 'ninguna'}
- Estado de Autenticación: SPF={auth_status.get('spf', 'desconocido')}, DKIM={auth_status.get('dkim', 'desconocido')}, DMARC={auth_status.get('dmarc', 'desconocido')}

Proporciona tu análisis en JSON con esta estructura:
{{
    "resumen_ejecutivo": "Resumen breve del incidente",
    "nivel_amenaza": "CRITICO|ALTO|MEDIO|BAJO",
    "tecnicas_detectadas": ["técnica1", "técnica2"],
    "recomendaciones_inmediatas": ["acción1", "acción2"],
    "recomendaciones_largo_plazo": ["medida1", "medida2"],
    "indicadores_clave": ["IoC1", "IoC2"],
    "evaluacion_impacto": "Descripción del impacto potencial"
}}"""

        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "Eres un analista de ciberseguridad experto. Analiza incidentes de phishing y proporciona evaluaciones estructuradas en JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 1500
        }

        data = json.dumps(payload).encode('utf-8')
        result = AIConnector._safe_request(url, headers, data, AIConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            message = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            # Try to parse JSON from response
            try:
                # Look for JSON in the response
                start = message.find('{')
                end = message.rfind('}') + 1
                if start >= 0 and end > start:
                    json_str = message[start:end]
                    return json.loads(json_str)
            except:
                pass

            # Fallback to raw text
            return {"assessment": message}
        except Exception as e:
            return {"error": f"Failed to parse ChatGPT response: {str(e)}"}

    # ========================================================================
    # ANTHROPIC CLAUDE
    # ========================================================================

    @staticmethod
    def claude_analyze(analysis: Dict[str, Any], api_key: str, model: str = 'claude-sonnet-4-20250514') -> Dict[str, Any]:
        """Send analysis to Claude for threat assessment."""
        if not api_key:
            return {"error": "Missing Anthropic API key"}

        # Build focused prompt in Spanish
        risk_score = analysis.get("risk", {}).get("score", 0)
        flags = analysis.get("risk", {}).get("flags", [])
        iocs = analysis.get("iocs", {})
        auth_status = analysis.get("auth_status", {})

        prompt = f"""Analiza el siguiente incidente de seguridad de correo electrónico y proporciona una evaluación de amenaza detallada.

**Información del Análisis:**
- Puntuación de Riesgo: {risk_score}/100
- Veredicto: {analysis.get('risk', {}).get('verdict', 'desconocido')}
- Indicadores de Riesgo: {', '.join(flags[:5]) if flags else 'ninguno'}
- IPs Detectadas: {', '.join(iocs.get('ips', [])[:5]) if iocs.get('ips') else 'ninguna'}
- Dominios Detectados: {', '.join(iocs.get('domains', [])[:5]) if iocs.get('domains') else 'ninguno'}
- URLs Sospechosas: {', '.join(iocs.get('urls', [])[:3]) if iocs.get('urls') else 'ninguna'}
- Estado de Autenticación: SPF={auth_status.get('spf', 'desconocido')}, DKIM={auth_status.get('dkim', 'desconocido')}, DMARC={auth_status.get('dmarc', 'desconocido')}

Proporciona tu análisis en JSON con esta estructura exacta:
{{
    "resumen_ejecutivo": "Resumen breve del incidente",
    "nivel_amenaza": "CRITICO|ALTO|MEDIO|BAJO",
    "tecnicas_detectadas": ["técnica1", "técnica2"],
    "recomendaciones_inmediatas": ["acción1", "acción2"],
    "recomendaciones_largo_plazo": ["medida1", "medida2"],
    "indicadores_clave": ["IoC1", "IoC2"],
    "evaluacion_impacto": "Descripción del impacto potencial"
}}"""

        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }

        payload = {
            "model": model,
            "max_tokens": 1500,
            "system": "Eres un analista de ciberseguridad experto. Analiza incidentes de phishing y proporciona evaluaciones estructuradas en JSON valido.",
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }

        data = json.dumps(payload).encode('utf-8')
        result = AIConnector._safe_request(url, headers, data, AIConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            message = result.get("content", [{}])[0].get("text", "")
            # Try to parse JSON from response
            try:
                # Look for JSON in the response
                start = message.find('{')
                end = message.rfind('}') + 1
                if start >= 0 and end > start:
                    json_str = message[start:end]
                    return json.loads(json_str)
            except:
                pass

            # Fallback to raw text
            return {"assessment": message}
        except Exception as e:
            return {"error": f"Failed to parse Claude response: {str(e)}"}

    # ========================================================================
    # GOOGLE GEMINI
    # ========================================================================

    @staticmethod
    def gemini_analyze(analysis: Dict[str, Any], api_key: str, model: str = 'gemini-2.0-flash') -> Dict[str, Any]:
        """Send analysis to Google Gemini for threat assessment."""
        if not api_key:
            return {"error": "Missing Google Gemini API key"}

        risk_score = analysis.get("risk", {}).get("score", 0)
        flags = analysis.get("risk", {}).get("flags", [])
        iocs = analysis.get("iocs", {})
        auth_status = analysis.get("auth_status", {})

        prompt = f"""Analiza el siguiente incidente de seguridad de correo electrónico y proporciona una evaluación de amenaza detallada.

**Información del Análisis:**
- Puntuación de Riesgo: {risk_score}/100
- Veredicto: {analysis.get('risk', {}).get('verdict', 'desconocido')}
- Indicadores de Riesgo: {', '.join(flags[:5]) if flags else 'ninguno'}
- IPs Detectadas: {', '.join(iocs.get('ips', [])[:5]) if iocs.get('ips') else 'ninguna'}
- Dominios Detectados: {', '.join(iocs.get('domains', [])[:5]) if iocs.get('domains') else 'ninguno'}
- URLs Sospechosas: {', '.join(iocs.get('urls', [])[:3]) if iocs.get('urls') else 'ninguna'}
- Estado de Autenticación: SPF={auth_status.get('spf', 'desconocido')}, DKIM={auth_status.get('dkim', 'desconocido')}, DMARC={auth_status.get('dmarc', 'desconocido')}

Proporciona tu análisis en JSON con esta estructura exacta:
{{
    "resumen_ejecutivo": "Resumen breve del incidente",
    "nivel_amenaza": "CRITICO|ALTO|MEDIO|BAJO",
    "tecnicas_detectadas": ["técnica1", "técnica2"],
    "recomendaciones_inmediatas": ["acción1", "acción2"],
    "recomendaciones_largo_plazo": ["medida1", "medida2"],
    "indicadores_clave": ["IoC1", "IoC2"],
    "evaluacion_impacto": "Descripción del impacto potencial"
}}"""

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": "Eres un analista de ciberseguridad experto. Analiza incidentes de phishing y proporciona evaluaciones estructuradas en JSON valido."}]},
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1500}
        }

        data = json.dumps(payload).encode('utf-8')
        result = AIConnector._safe_request(url, headers, data, AIConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            message = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            try:
                start = message.find('{')
                end = message.rfind('}') + 1
                if start >= 0 and end > start:
                    json_str = message[start:end]
                    return json.loads(json_str)
            except:
                pass
            return {"assessment": message}
        except Exception as e:
            return {"error": f"Failed to parse Gemini response: {str(e)}"}

    # ========================================================================
    # MISTRAL AI
    # ========================================================================

    @staticmethod
    def mistral_analyze(analysis: Dict[str, Any], api_key: str, model: str = 'mistral-large-latest') -> Dict[str, Any]:
        """Send analysis to Mistral AI for threat assessment."""
        if not api_key:
            return {"error": "Missing Mistral AI API key"}

        risk_score = analysis.get("risk", {}).get("score", 0)
        flags = analysis.get("risk", {}).get("flags", [])
        iocs = analysis.get("iocs", {})
        auth_status = analysis.get("auth_status", {})

        prompt = f"""Analiza el siguiente incidente de seguridad de correo electrónico y proporciona una evaluación de amenaza detallada.

**Información del Análisis:**
- Puntuación de Riesgo: {risk_score}/100
- Veredicto: {analysis.get('risk', {}).get('verdict', 'desconocido')}
- Indicadores de Riesgo: {', '.join(flags[:5]) if flags else 'ninguno'}
- IPs Detectadas: {', '.join(iocs.get('ips', [])[:5]) if iocs.get('ips') else 'ninguna'}
- Dominios Detectados: {', '.join(iocs.get('domains', [])[:5]) if iocs.get('domains') else 'ninguno'}
- URLs Sospechosas: {', '.join(iocs.get('urls', [])[:3]) if iocs.get('urls') else 'ninguna'}
- Estado de Autenticación: SPF={auth_status.get('spf', 'desconocido')}, DKIM={auth_status.get('dkim', 'desconocido')}, DMARC={auth_status.get('dmarc', 'desconocido')}

Proporciona tu análisis en JSON con esta estructura exacta:
{{
    "resumen_ejecutivo": "Resumen breve del incidente",
    "nivel_amenaza": "CRITICO|ALTO|MEDIO|BAJO",
    "tecnicas_detectadas": ["técnica1", "técnica2"],
    "recomendaciones_inmediatas": ["acción1", "acción2"],
    "recomendaciones_largo_plazo": ["medida1", "medida2"],
    "indicadores_clave": ["IoC1", "IoC2"],
    "evaluacion_impacto": "Descripción del impacto potencial"
}}"""

        url = "https://api.mistral.ai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "Eres un analista de ciberseguridad experto. Analiza incidentes de phishing y proporciona evaluaciones estructuradas en JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 1500
        }

        data = json.dumps(payload).encode('utf-8')
        result = AIConnector._safe_request(url, headers, data, AIConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            message = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            try:
                start = message.find('{')
                end = message.rfind('}') + 1
                if start >= 0 and end > start:
                    json_str = message[start:end]
                    return json.loads(json_str)
            except:
                pass
            return {"assessment": message}
        except Exception as e:
            return {"error": f"Failed to parse Mistral response: {str(e)}"}

    # ========================================================================
    # GROQ (OpenAI-compatible)
    # ========================================================================

    @staticmethod
    def groq_analyze(analysis: Dict[str, Any], api_key: str, model: str = 'llama-3.3-70b-versatile') -> Dict[str, Any]:
        """Send analysis to Groq for threat assessment (ultra-fast inference)."""
        if not api_key:
            return {"error": "Missing Groq API key"}

        risk_score = analysis.get("risk", {}).get("score", 0)
        flags = analysis.get("risk", {}).get("flags", [])
        iocs = analysis.get("iocs", {})
        auth_status = analysis.get("auth_status", {})

        prompt = f"""Analiza el siguiente incidente de seguridad de correo electrónico y proporciona una evaluación de amenaza detallada.

**Información del Análisis:**
- Puntuación de Riesgo: {risk_score}/100
- Veredicto: {analysis.get('risk', {}).get('verdict', 'desconocido')}
- Indicadores de Riesgo: {', '.join(flags[:5]) if flags else 'ninguno'}
- IPs Detectadas: {', '.join(iocs.get('ips', [])[:5]) if iocs.get('ips') else 'ninguna'}
- Dominios Detectados: {', '.join(iocs.get('domains', [])[:5]) if iocs.get('domains') else 'ninguno'}
- URLs Sospechosas: {', '.join(iocs.get('urls', [])[:3]) if iocs.get('urls') else 'ninguna'}
- Estado de Autenticación: SPF={auth_status.get('spf', 'desconocido')}, DKIM={auth_status.get('dkim', 'desconocido')}, DMARC={auth_status.get('dmarc', 'desconocido')}

Proporciona tu análisis en JSON con esta estructura exacta:
{{
    "resumen_ejecutivo": "Resumen breve del incidente",
    "nivel_amenaza": "CRITICO|ALTO|MEDIO|BAJO",
    "tecnicas_detectadas": ["técnica1", "técnica2"],
    "recomendaciones_inmediatas": ["acción1", "acción2"],
    "recomendaciones_largo_plazo": ["medida1", "medida2"],
    "indicadores_clave": ["IoC1", "IoC2"],
    "evaluacion_impacto": "Descripción del impacto potencial"
}}"""

        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "Eres un analista de ciberseguridad experto. Analiza incidentes de phishing y proporciona evaluaciones estructuradas en JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 1500
        }

        data = json.dumps(payload).encode('utf-8')
        result = AIConnector._safe_request(url, headers, data, AIConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            message = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            try:
                start = message.find('{')
                end = message.rfind('}') + 1
                if start >= 0 and end > start:
                    json_str = message[start:end]
                    return json.loads(json_str)
            except:
                pass
            return {"assessment": message}
        except Exception as e:
            return {"error": f"Failed to parse Groq response: {str(e)}"}

    # ========================================================================
    # DEEPSEEK
    # ========================================================================

    @staticmethod
    def deepseek_analyze(analysis: Dict[str, Any], api_key: str, model: str = 'deepseek-chat') -> Dict[str, Any]:
        """Send analysis to DeepSeek for threat assessment."""
        if not api_key:
            return {"error": "Missing DeepSeek API key"}

        risk_score = analysis.get("risk", {}).get("score", 0)
        flags = analysis.get("risk", {}).get("flags", [])
        iocs = analysis.get("iocs", {})
        auth_status = analysis.get("auth_status", {})

        prompt = f"""Analiza el siguiente incidente de seguridad de correo electrónico y proporciona una evaluación de amenaza detallada.

**Información del Análisis:**
- Puntuación de Riesgo: {risk_score}/100
- Veredicto: {analysis.get('risk', {}).get('verdict', 'desconocido')}
- Indicadores de Riesgo: {', '.join(flags[:5]) if flags else 'ninguno'}
- IPs Detectadas: {', '.join(iocs.get('ips', [])[:5]) if iocs.get('ips') else 'ninguna'}
- Dominios Detectados: {', '.join(iocs.get('domains', [])[:5]) if iocs.get('domains') else 'ninguno'}
- URLs Sospechosas: {', '.join(iocs.get('urls', [])[:3]) if iocs.get('urls') else 'ninguna'}
- Estado de Autenticación: SPF={auth_status.get('spf', 'desconocido')}, DKIM={auth_status.get('dkim', 'desconocido')}, DMARC={auth_status.get('dmarc', 'desconocido')}

Proporciona tu análisis en JSON con esta estructura exacta:
{{
    "resumen_ejecutivo": "Resumen breve del incidente",
    "nivel_amenaza": "CRITICO|ALTO|MEDIO|BAJO",
    "tecnicas_detectadas": ["técnica1", "técnica2"],
    "recomendaciones_inmediatas": ["acción1", "acción2"],
    "recomendaciones_largo_plazo": ["medida1", "medida2"],
    "indicadores_clave": ["IoC1", "IoC2"],
    "evaluacion_impacto": "Descripción del impacto potencial"
}}"""

        url = "https://api.deepseek.com/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "Eres un analista de ciberseguridad experto. Analiza incidentes de phishing y proporciona evaluaciones estructuradas en JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 1500
        }

        data = json.dumps(payload).encode('utf-8')
        result = AIConnector._safe_request(url, headers, data, AIConnector.TIMEOUT)

        if "error" in result:
            return result

        try:
            message = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            try:
                start = message.find('{')
                end = message.rfind('}') + 1
                if start >= 0 and end > start:
                    json_str = message[start:end]
                    return json.loads(json_str)
            except:
                pass
            return {"assessment": message}
        except Exception as e:
            return {"error": f"Failed to parse DeepSeek response: {str(e)}"}

    # ========================================================================
    # CONVENIENCE METHOD
    # ========================================================================

    # Provider registry for easy extension
    PROVIDERS = {
        'openai': {'method': 'openai_analyze', 'key': 'openai'},
        'claude': {'method': 'claude_analyze', 'key': 'claude'},
        'gemini': {'method': 'gemini_analyze', 'key': 'gemini'},
        'mistral': {'method': 'mistral_analyze', 'key': 'mistral'},
        'groq': {'method': 'groq_analyze', 'key': 'groq'},
        'deepseek': {'method': 'deepseek_analyze', 'key': 'deepseek'},
    }

    # Default fallback order
    FALLBACK_ORDER = ['openai', 'claude', 'gemini', 'mistral', 'groq', 'deepseek']

    @staticmethod
    def get_ai_assessment(analysis: Dict[str, Any], api_keys: Dict[str, str], preferred: str = 'auto') -> Dict[str, Any]:
        """
        Get AI assessment using preferred provider, with fallback chain.

        Args:
            analysis: Full analysis dict
            api_keys: Dict with provider keys ('openai', 'claude', 'gemini', 'mistral', 'groq', 'deepseek')
            preferred: Provider name or 'auto' (tries all configured providers in order)

        Returns: Assessment dict with threat evaluation
        """
        # Direct provider selection
        if preferred != 'auto' and preferred in AIConnector.PROVIDERS:
            prov = AIConnector.PROVIDERS[preferred]
            key = api_keys.get(prov['key'])
            if key:
                method = getattr(AIConnector, prov['method'])
                return method(analysis, key)
            return {"error": f"No API key configured for {preferred}"}

        # Auto mode: try each configured provider in fallback order
        if preferred == 'auto':
            for provider_name in AIConnector.FALLBACK_ORDER:
                prov = AIConnector.PROVIDERS[provider_name]
                key = api_keys.get(prov['key'])
                if key:
                    method = getattr(AIConnector, prov['method'])
                    result = method(analysis, key)
                    if "error" not in result:
                        return result

        return {"error": "No AI API keys configured or provider not available"}
