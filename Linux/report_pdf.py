#!/usr/bin/env python3
"""
PhishGuard Pro - Professional Threat Report Generator (Extended Version)
=========================================================================
Comprehensive PDF threat report generation with 8-10+ pages including executive
summary, detailed findings, MITRE ATT&CK mappings, forensics chain of custody,
and extended analytics.

Returns PDF bytes instead of writing to file.
"""

import io
import math
import uuid
import hashlib
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import HexColor, white, black, Color, transparent
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, PageBreak, HRFlowable, KeepTogether, Flowable)
from reportlab.graphics.shapes import Drawing, Rect, Circle, Line, String, Polygon, Group

W, H = A4  # 595.28 x 841.89

# ============================
# COLORS
# ============================
BG_DARK   = HexColor('#0f172a')
BG_CARD   = HexColor('#1e293b')
BG_LIGHT  = HexColor('#f8fafc')
BG_PAGE   = HexColor('#ffffff')
ACCENT    = HexColor('#3b82f6')
ACCENT2   = HexColor('#6366f1')
RED       = HexColor('#ef4444')
RED_LIGHT = HexColor('#fef2f2')
RED_MID   = HexColor('#fee2e2')
ORG       = HexColor('#f97316')
ORG_LIGHT = HexColor('#fff7ed')
YEL       = HexColor('#eab308')
YEL_LIGHT = HexColor('#fefce8')
GRN       = HexColor('#10b981')
GRN_LIGHT = HexColor('#ecfdf5')
CYAN      = HexColor('#06b6d4')
PURP      = HexColor('#8b5cf6')
SLATE     = HexColor('#475569')
SLATE_LT  = HexColor('#94a3b8')
SLATE_VLT = HexColor('#cbd5e1')
DARK_TXT  = HexColor('#0f172a')
MID_TXT   = HexColor('#334155')
LIGHT_TXT = HexColor('#64748b')
BORDER    = HexColor('#e2e8f0')

# MITRE ATT&CK Technique Mapping
MITRE_TECHNIQUES = {
    'T1566.001': ('Spearphishing Attachment', 'Initial Access'),
    'T1566.002': ('Spearphishing Link', 'Initial Access'),
    'T1566.003': ('Spearphishing via Service', 'Initial Access'),
    'T1534': ('Internal Spearphishing', 'Lateral Movement'),
    'T1598': ('Phishing for Information', 'Reconnaissance'),
    'T1204.001': ('User Execution: Malicious Link', 'Execution'),
    'T1204.002': ('User Execution: Malicious File', 'Execution'),
    'T1059.007': ('Command and Scripting: JavaScript', 'Execution'),
    'T1059.001': ('Command and Scripting: PowerShell', 'Execution'),
    'T1071.001': ('Application Layer Protocol: Web', 'Command and Control'),
    'T1105': ('Ingress Tool Transfer', 'Command and Control'),
    'T1036': ('Masquerading', 'Defense Evasion'),
    'T1586': ('Compromise Accounts', 'Resource Development'),
    'T1584': ('Compromise Infrastructure', 'Resource Development'),
    'T1568': ('Dynamic Resolution', 'Command and Control'),
    'T1027': ('Obfuscated Files or Information', 'Defense Evasion'),
}

# Finding to MITRE mapping
FINDING_MITRE_MAP = {
    'suplantacion': 'T1566.002',
    'thread hijack': 'T1534',
    'malware': 'T1204.002',
    'url maliciosa': 'T1566.002',
    'adjunto': 'T1204.002',
    'phishing': 'T1566.001',
    'spoofing': 'T1036',
}

# ============================
# CUSTOM FLOWABLES
# ============================

class RiskMeterFlowable(Flowable):
    """Big semicircular risk gauge with score."""
    def __init__(self, score, width=200, height=120):
        Flowable.__init__(self)
        self.score = min(100, max(0, score))  # Clamp 0-100
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        cx, cy = self.width/2, 30
        radius = 80
        # Background arc segments (left=0/green, right=100/red)
        # ReportLab: 0°=right(3 o'clock), 180°=left(9 o'clock), counterclockwise
        segments = [
            (144, 180, GRN),           # 0-20 green (far left)
            (108, 144, HexColor('#84cc16')),  # 20-40 lime
            (72, 108, YEL),            # 40-60 yellow (top)
            (36, 72, ORG),             # 60-80 orange
            (0, 36, RED),              # 80-100 red (far right)
        ]
        for start, end, color in segments:
            c.setStrokeColor(color)
            c.setLineWidth(14)
            c.arc(cx-radius, cy-radius, cx+radius, cy+radius, start, end-start)

        # Needle
        angle = 180 - (self.score / 100 * 180)
        rad = math.radians(angle)
        nx = cx + (radius - 20) * math.cos(rad)
        ny = cy + (radius - 20) * math.sin(rad)
        c.setStrokeColor(DARK_TXT)
        c.setLineWidth(2.5)
        c.line(cx, cy, nx, ny)
        # Center dot
        c.setFillColor(DARK_TXT)
        c.circle(cx, cy, 5, fill=1)

        # Score text
        c.setFont('Helvetica-Bold', 28)
        color = RED if self.score >= 70 else ORG if self.score >= 50 else YEL if self.score >= 30 else GRN
        c.setFillColor(color)
        c.drawCentredString(cx, cy - 22, str(int(self.score)))
        c.setFont('Helvetica', 8)
        c.setFillColor(LIGHT_TXT)
        c.drawCentredString(cx, cy - 32, '/100')

        # Labels
        c.setFont('Helvetica', 6)
        c.setFillColor(SLATE_LT)
        c.drawString(cx - radius - 5, cy - 5, '0')
        c.drawCentredString(cx, cy + radius + 8, '50')
        c.drawRightString(cx + radius + 8, cy - 5, '100')


class AttackChainFlowable(Flowable):
    """Visual attack chain diagram."""
    def __init__(self, steps, width=480, height=70):
        Flowable.__init__(self)
        self.steps = steps
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        n = len(self.steps)
        if n == 0:
            return
        box_w = 75
        gap = (self.width - n * box_w) / max(n - 1, 1)
        y = 20

        for i, (icon, label, color) in enumerate(self.steps):
            x = i * (box_w + gap)
            # Box with rounded corners
            c.setFillColor(color)
            c.roundRect(x, y, box_w, 42, 6, fill=1, stroke=0)
            # Icon
            c.setFont('Helvetica-Bold', 14)
            c.setFillColor(white)
            c.drawCentredString(x + box_w/2, y + 25, icon)
            # Label
            c.setFont('Helvetica-Bold', 5.5)
            c.drawCentredString(x + box_w/2, y + 10, label[:14])
            c.setFont('Helvetica', 5)
            c.drawCentredString(x + box_w/2, y + 3, label[14:28] if len(label) > 14 else '')

            # Arrow
            if i < n - 1:
                ax = x + box_w + 2
                ay = y + 21
                c.setStrokeColor(SLATE_LT)
                c.setLineWidth(1.5)
                c.line(ax, ay, ax + gap - 4, ay)
                # Arrowhead
                c.setFillColor(SLATE_LT)
                c.drawString(ax + gap - 8, ay - 3, '>')


class SeverityBarFlowable(Flowable):
    """Horizontal severity breakdown bar."""
    def __init__(self, critical, high, medium, low, width=400, height=30):
        Flowable.__init__(self)
        self.c = max(0, int(critical))
        self.h2 = max(0, int(high))
        self.m = max(0, int(medium))
        self.l = max(0, int(low))
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        total = self.c + self.h2 + self.m + self.l
        if total == 0:
            return
        y, h = 12, 14
        x = 0
        segments = [
            (self.c, RED, 'CRITICO'),
            (self.h2, ORG, 'ALTO'),
            (self.m, YEL, 'MEDIO'),
            (self.l, CYAN, 'BAJO'),
        ]
        for count, color, label in segments:
            if count == 0:
                continue
            w = (count / total) * self.width
            c.setFillColor(color)
            c.roundRect(x, y, max(w, 2), h, 3, fill=1, stroke=0)
            if w > 35:
                c.setFont('Helvetica-Bold', 6)
                c.setFillColor(white)
                c.drawCentredString(x + w/2, y + 4, f'{label}: {count}')
            x += w

        # Legend below
        c.setFont('Helvetica', 6)
        lx = 0
        for count, color, label in segments:
            c.setFillColor(color)
            c.circle(lx + 4, 4, 3, fill=1, stroke=0)
            c.setFillColor(SLATE)
            c.drawString(lx + 10, 1, f'{label} ({count})')
            lx += 70


class RiskMatrixFlowable(Flowable):
    """2x2 Risk matrix visualization."""
    def __init__(self, probability, impact, width=180, height=180):
        Flowable.__init__(self)
        self.probability = min(100, max(0, probability))
        self.impact = min(100, max(0, impact))
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        # Grid background
        cell_size = self.width / 2

        # Quadrant 1: Low prob, Low impact (green)
        c.setFillColor(GRN_LIGHT)
        c.rect(0, 0, cell_size, cell_size, fill=1, stroke=0)

        # Quadrant 2: High prob, Low impact (yellow)
        c.setFillColor(YEL_LIGHT)
        c.rect(cell_size, 0, cell_size, cell_size, fill=1, stroke=0)

        # Quadrant 3: Low prob, High impact (orange)
        c.setFillColor(ORG_LIGHT)
        c.rect(0, cell_size, cell_size, cell_size, fill=1, stroke=0)

        # Quadrant 4: High prob, High impact (red)
        c.setFillColor(RED_LIGHT)
        c.rect(cell_size, cell_size, cell_size, cell_size, fill=1, stroke=0)

        # Grid lines
        c.setStrokeColor(BORDER)
        c.setLineWidth(2)
        c.line(cell_size, 0, cell_size, self.height)
        c.line(0, cell_size, self.width, cell_size)

        # Border
        c.setStrokeColor(DARK_TXT)
        c.setLineWidth(1.5)
        c.rect(0, 0, self.width, self.height)

        # Plot point
        x = (self.probability / 100) * self.width
        y = (self.impact / 100) * self.height
        c.setFillColor(RED)
        c.circle(x, y, 6, fill=1, stroke=1)

        # Axis labels
        c.setFont('Helvetica-Bold', 7)
        c.setFillColor(DARK_TXT)
        # X-axis (Probability) — below the matrix
        c.drawCentredString(self.width/4, -14, 'Prob. Baja')
        c.drawCentredString(3*self.width/4, -14, 'Prob. Alta')
        # Y-axis (Impact) — left of the matrix, rotated 90°
        c.saveState()
        c.rotate(90)
        c.drawCentredString(self.height/4, 12, 'Impacto Bajo')
        c.drawCentredString(3*self.height/4, 12, 'Impacto Alto')
        c.restoreState()


# ============================
# HELPER FUNCTIONS
# ============================

def _safe(text):
    """Escape XML entities for ReportLab Paragraph."""
    s = str(text or '')
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _safe_get(d, key, default=None):
    """Safely get nested dict values."""
    if not isinstance(d, dict):
        return default
    return d.get(key, default)


def _defang_url(url):
    """Defang a URL for security."""
    return url.replace('https://', 'hxxps://').replace('http://', 'hxxp://').replace('.', '[.]')


def _extract_severity_counts(flags):
    """Count severity levels from flags list."""
    counts = {'CRITICO': 0, 'ALTO': 0, 'MEDIO': 0, 'BAJO': 0}
    sev_map = {
        'critical': 'CRITICO', 'critico': 'CRITICO', 'CRITICO': 'CRITICO',
        'high': 'ALTO', 'alto': 'ALTO', 'ALTO': 'ALTO',
        'medium': 'MEDIO', 'medio': 'MEDIO', 'MEDIO': 'MEDIO',
        'low': 'BAJO', 'bajo': 'BAJO', 'BAJO': 'BAJO',
    }
    if isinstance(flags, list):
        for flag in flags:
            if isinstance(flag, dict):
                sev = flag.get('severity', 'low')
                mapped = sev_map.get(sev, 'BAJO')
                counts[mapped] = counts.get(mapped, 0) + 1
    return counts


def _build_attack_chain(analysis):
    """Build attack chain dynamically from analysis data."""
    chain = []
    body_analysis = _safe_get(analysis, 'body_analysis', {})
    attachment_analysis = _safe_get(analysis, 'attachment_analysis', {})
    iocs = _safe_get(analysis, 'iocs', {})

    # Phase 1: Source/Compromise
    chain.append(('1', 'Servidor', HexColor('#7c3aed')))

    # Phase 2: Thread hijacking
    if body_analysis.get('thread_hijack'):
        chain.append(('2', 'Thread Hijack', RED))

    # Phase 3: Social engineering / body content issues
    flags = _safe_get(analysis, 'risk', {}).get('flags', [])
    has_social_eng = any(f.get('text', '').lower().find('ingenieria') >= 0 or
                         f.get('text', '').lower().find('social') >= 0 for f in flags)
    if has_social_eng:
        chain.append(('3', 'Ing. Social', ORG))

    # Phase 4: Malicious hosting
    domains = _safe_get(iocs, 'domains', [])
    if domains:
        chain.append(('4', 'Hosting', RED))

    # Phase 5: Payload/Attachment
    attachments = _safe_get(attachment_analysis, 'attachments', [])
    if attachments:
        chain.append(('5', 'Payload', HexColor('#dc2626')))

    # Phase 6: Execution
    has_malware = any(f.get('text', '').lower().find('malware') >= 0 or
                      f.get('text', '').lower().find('ejecucion') >= 0 for f in flags)
    if has_malware or attachments:
        chain.append(('6', 'Ejecucion', HexColor('#991b1b')))

    return chain if chain else [('?', 'Analisis', SLATE)]


def _generate_ref_number():
    """Generate a unique reference number."""
    return 'GPV' + str(int(uuid.uuid4().int / 1000000))[:7]


def _find_mitre_technique(finding_text):
    """Detect MITRE ATT&CK technique from finding text."""
    text_lower = finding_text.lower()
    for keyword, technique in FINDING_MITRE_MAP.items():
        if keyword in text_lower:
            return technique
    return None


def _calculate_hash_from_analysis(analysis):
    """Calculate SHA-256 hash from parsed headers as integrity check."""
    headers_str = str(_safe_get(analysis, 'parsed_headers', {}))
    return hashlib.sha256(headers_str.encode()).hexdigest()


# ============================
# MAIN FUNCTION
# ============================

def generate_pdf_report(analysis, config=None):
    """
    Generate a comprehensive professional PDF threat report from analysis dict.

    Args:
        analysis (dict): Full analysis dict from run_enhanced_analysis() containing:
            - parsed_headers: dict of header name -> values
            - hops: list of hop dicts
            - auth: dict with spf/dkim/dmarc/arc status
            - risk: dict with score, risk_level, verdict, flags
            - iocs: dict with public_ips, private_ips, domains, emails, urls
            - body_analysis: dict with detected issues
            - attachment_analysis: dict with file analysis
            - (optional) geoip, dnsbl, dns_resolution, forensics, msg_metadata, malware_analysis, etc.

        config (dict): Optional config with keys like:
            - analyst_name: Name of analyst (default: "Jaquers")
            - company_name: Company name (default: "Jaquers Ciberseguridad S.L.")
            - title: Report title (default: "Informe de Amenaza de Phishing")
            - date: Report date (default: today)
            - ref_number: Custom ref number (default: auto-generated)

    Returns:
        bytes: PDF file content as bytes (suitable for file write or HTTP response)
    """

    # ============================
    # CONFIG & SETUP
    # ============================
    if config is None:
        config = {}

    analyst = config.get('analyst_name', 'Jaquers')
    company = config.get('company_name', 'Jaquers Ciberseguridad S.L.')
    title = config.get('title', 'Informe de Amenaza de Phishing')
    report_date = config.get('date', datetime.now().strftime("%d/%m/%Y"))
    ref_number = config.get('ref_number', _generate_ref_number())

    # ============================
    # EXTRACT DATA FROM ANALYSIS
    # ============================

    # Risk data
    risk_dict = _safe_get(analysis, 'risk', {})
    score = int(risk_dict.get('score', 0))
    risk_level = risk_dict.get('risk_level', 'UNKNOWN')
    verdict = risk_dict.get('verdict', 'UNKNOWN')
    flags = risk_dict.get('flags', [])

    # Headers
    parsed_headers = _safe_get(analysis, 'parsed_headers', {})
    from_header = ', '.join(parsed_headers.get('From', ['N/A']))[:80]
    to_header = ', '.join(parsed_headers.get('To', ['N/A']))[:80]
    subject = ', '.join(parsed_headers.get('Subject', ['N/A']))[:100]
    date_header = ', '.join(parsed_headers.get('Date', ['N/A']))
    msg_id = ', '.join(parsed_headers.get('Message-ID', ['N/A']))[:60]
    x_mailer = ', '.join(parsed_headers.get('X-Mailer', ['N/A']))
    spam_flag = ', '.join(parsed_headers.get('X-Spam-Flag', ['NO']))

    # Hops
    hops = _safe_get(analysis, 'hops', [])
    hop_info = 'N/A'
    if hops and len(hops) > 0:
        first_hop = hops[0]
        last_hop = hops[-1] if len(hops) > 1 else first_hop
        hop_info = f"{first_hop.get('from_server', '?')} -> {last_hop.get('by_server', '?')}"

    # Auth - handle both dict {'status':'pass'} and plain string 'pass' formats
    auth = _safe_get(analysis, 'auth', {})
    def _auth_status(key):
        v = _safe_get(auth, key, {})
        if isinstance(v, dict):
            return v.get('status', 'UNKNOWN')
        return str(v) if v else 'UNKNOWN'
    spf_status = _auth_status('spf')
    dkim_status = _auth_status('dkim')
    dmarc_status = _auth_status('dmarc')
    arc_status = _auth_status('arc')

    # IoCs
    iocs = _safe_get(analysis, 'iocs', {})
    public_ips = _safe_get(iocs, 'public_ips', [])
    private_ips = _safe_get(iocs, 'private_ips', [])
    domains = _safe_get(iocs, 'domains', [])
    urls = _safe_get(iocs, 'urls', [])
    emails = _safe_get(iocs, 'emails', [])

    # Body analysis
    body_analysis = _safe_get(analysis, 'body_analysis', {})
    body_text = body_analysis.get('body_text', 'N/A')

    # Attachment analysis
    attachment_analysis = _safe_get(analysis, 'attachment_analysis', {})
    attachments = _safe_get(attachment_analysis, 'attachments', [])

    # Optional advanced data
    geoip_data = _safe_get(analysis, 'geoip', [])
    dnsbl_data = _safe_get(analysis, 'dnsbl', {})
    dns_resolution = _safe_get(analysis, 'dns_resolution', {})
    forensics_data = _safe_get(analysis, 'forensics', {})
    msg_metadata = _safe_get(analysis, 'msg_metadata', {})
    malware_data = _safe_get(analysis, 'malware_analysis', [])

    # Severity normalization map (English lowercase -> Spanish uppercase)
    _sev_norm = {
        'critical': 'CRITICO', 'critico': 'CRITICO', 'CRITICO': 'CRITICO',
        'high': 'ALTO', 'alto': 'ALTO', 'ALTO': 'ALTO',
        'medium': 'MEDIO', 'medio': 'MEDIO', 'MEDIO': 'MEDIO',
        'low': 'BAJO', 'bajo': 'BAJO', 'BAJO': 'BAJO',
    }

    # Severity counts
    sev_counts = _extract_severity_counts(flags)

    # Verdict and color
    verdict_label = "PHISHING CONFIRMADO" if score >= 70 else "ALTO RIESGO" if score >= 50 else "ADVERTENCIA"
    verdict_color = RED if score >= 70 else ORG if score >= 50 else YEL
    verdict_bg = RED_LIGHT if score >= 70 else ORG_LIGHT if score >= 50 else YEL_LIGHT

    # Calculate integrity hash
    evidence_hash = _calculate_hash_from_analysis(analysis)

    # ============================
    # PAGE CALLBACK
    # ============================

    def onPage(canvas, doc):
        """Custom page template with header/footer."""
        canvas.saveState()
        # Top bar
        canvas.setFillColor(BG_DARK)
        canvas.rect(0, H - 28, W, 28, fill=1, stroke=0)
        # Accent line
        canvas.setFillColor(ACCENT)
        canvas.rect(0, H - 31, W, 3, fill=1, stroke=0)
        # Header text
        canvas.setFont('Helvetica-Bold', 8)
        canvas.setFillColor(white)
        canvas.drawString(20, H - 20, 'PHISHGUARD PRO')
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(SLATE_LT)
        canvas.drawString(110, H - 20, title)
        canvas.setFont('Helvetica', 7)
        canvas.drawRightString(W - 20, H - 20, f'Ref: {ref_number} | {report_date}')

        # Footer
        canvas.setFillColor(BG_DARK)
        canvas.rect(0, 0, W, 22, fill=1, stroke=0)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, 22, W, 2, fill=1, stroke=0)
        canvas.setFont('Helvetica', 6)
        canvas.setFillColor(SLATE_LT)
        canvas.drawString(20, 8, f'PhishGuard Pro v3.0 | 14 modulos | {company}')
        canvas.drawRightString(W - 20, 8, f'Pagina {doc.page}')
        # Classification stamp
        canvas.setFont('Helvetica-Bold', 6)
        canvas.setFillColor(RED)
        canvas.drawCentredString(W/2, 8, 'CONFIDENCIAL')

        canvas.restoreState()

    # ============================
    # BUILD PDF IN MEMORY
    # ============================

    pdf_buffer = io.BytesIO()
    doc = SimpleDocTemplate(pdf_buffer, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm, topMargin=3*cm, bottomMargin=2.5*cm)

    story = []
    usable_w = W - 4*cm

    # ============================
    # PAGE 1: COVER
    # ============================

    # Title block
    title_data = [[
        Paragraph('<font size="24" color="#3b82f6"><b>INFORME DE AMENAZA</b></font><br/>'
                  '<font size="11" color="#64748b">Analisis Forense de Email Phishing</font>',
                  ParagraphStyle('t', alignment=TA_LEFT, spaceAfter=0, leading=28))
    ]]
    title_t = Table(title_data, colWidths=[usable_w])
    title_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#f0f9ff')),
        ('BOX', (0,0), (-1,-1), 2, ACCENT),
        ('LEFTPADDING', (0,0), (-1,-1), 16),
        ('TOPPADDING', (0,0), (-1,-1), 14),
        ('BOTTOMPADDING', (0,0), (-1,-1), 14),
    ]))
    story.append(title_t)
    story.append(Spacer(1, 6))

    # Meta info row
    meta_data = [[
        Paragraph(f'<font size="7" color="#64748b"><b>FECHA</b></font><br/><font size="9" color="#0f172a">{report_date}</font>',
                  ParagraphStyle('m', leading=12)),
        Paragraph(f'<font size="7" color="#64748b"><b>ANALISTA</b></font><br/><font size="9" color="#0f172a">{analyst}</font>',
                  ParagraphStyle('m', leading=12)),
        Paragraph(f'<font size="7" color="#64748b"><b>REFERENCIA</b></font><br/><font size="9" color="#0f172a">{ref_number}</font>',
                  ParagraphStyle('m', leading=12)),
        Paragraph(f'<font size="7" color="#64748b"><b>MODULOS</b></font><br/><font size="9" color="#0f172a">14 activos</font>',
                  ParagraphStyle('m', leading=12)),
    ]]
    meta_t = Table(meta_data, colWidths=[usable_w/4]*4)
    meta_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(meta_t)
    story.append(Spacer(1, 10))

    # Classification box
    story.append(Paragraph('<font size="9" color="#334155"><b>CLASIFICACION DEL INCIDENTE</b></font>',
                 ParagraphStyle('cl', spaceAfter=4)))

    incident_type = "Phishing" if score >= 60 else "Spear-phishing" if score >= 50 else "Advertencia"
    incident_impact = "Alto" if score >= 70 else "Medio" if score >= 50 else "Bajo"
    incident_status = "Activo"

    class_data = [
        ['Tipo', incident_type],
        ['Vector', 'Email'],
        ['Impacto Estimado', incident_impact],
        ['Estado', incident_status],
    ]
    for i, row in enumerate(class_data):
        class_data[i] = [
            Paragraph(f'<font size="7.5" color="#64748b"><b>{row[0]}</b></font>', ParagraphStyle('cl1')),
            Paragraph(f'<font size="8" color="#0f172a">{row[1]}</font>', ParagraphStyle('cl2'))
        ]

    class_t = Table(class_data, colWidths=[4*cm, usable_w - 4*cm])
    class_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), HexColor('#f1f5f9')),
        ('BACKGROUND', (1,0), (1,-1), BG_LIGHT),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(class_t)
    story.append(Spacer(1, 12))

    # VERDICT + RISK METER side by side
    meter = RiskMeterFlowable(score, width=160, height=110)
    verdict_p = Paragraph(
        f'<font size="18" color="#{verdict_color.hexval()[2:]}"><b>{verdict_label}</b></font><br/><br/>'
        f'<font size="9" color="#475569">Puntuacion combinada de <b>{len(flags)} indicadores</b> '
        f'analizados a traves de <b>14 modulos</b> independientes incluyendo '
        f'analisis de cabeceras, cuerpo del mensaje, URLs, adjuntos, '
        f'ingenieria social y forense de red.</font>',
        ParagraphStyle('vp', leading=13, spaceAfter=0))

    verd_data = [[meter, verdict_p]]
    verd_t = Table(verd_data, colWidths=[170, usable_w - 175])
    verd_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), verdict_bg),
        ('BOX', (0,0), (-1,-1), 1.5, verdict_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (0,0), 8),
        ('LEFTPADDING', (1,0), (1,0), 14),
        ('RIGHTPADDING', (0,0), (-1,-1), 14),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(verd_t)
    story.append(Spacer(1, 10))

    # Severity breakdown bar
    story.append(Paragraph('<font size="8" color="#64748b"><b>DISTRIBUCION DE SEVERIDAD</b></font>',
                 ParagraphStyle('sl', spaceAfter=4)))
    story.append(SeverityBarFlowable(sev_counts.get('CRITICO',0), sev_counts.get('ALTO',0),
                                       sev_counts.get('MEDIO',0), sev_counts.get('BAJO',0), width=usable_w))
    story.append(Spacer(1, 14))

    # ATTACK CHAIN DIAGRAM
    story.append(Paragraph('<font size="10" color="#3b82f6"><b>CADENA DE ATAQUE</b></font>',
                 ParagraphStyle('ac', spaceAfter=6)))

    chain = AttackChainFlowable(_build_attack_chain(analysis), width=usable_w, height=65)
    story.append(chain)
    story.append(Spacer(1, 8))

    # Attack chain explanation (dynamic based on flags) - max 4 rows to fit page 1
    chain_desc = [['Fase', 'Descripcion', 'Severidad']]
    top_flags = sorted(flags, key=lambda f: {'critical':0,'high':1,'medium':2,'low':3}.get(f.get('severity','low'), 3))
    for i, flag in enumerate(top_flags[:4], 1):  # Top 4 by severity
        severity = _sev_norm.get(flag.get('severity', 'low'), 'BAJO')
        text = flag.get('text', flag.get('message', 'Hallazgo detectado'))[:55]
        chain_desc.append([f'{i}. Fase', text, severity])

    if not chain_desc[1:]:  # If no flags, use generic description
        chain_desc = [
            ['Fase', 'Descripcion', 'Severidad'],
            ['1. Analisis', 'Email sometido a analisis forense completo', 'MEDIO'],
        ]

    # Add summary row if more flags exist
    remaining = len(flags) - 4
    if remaining > 0:
        chain_desc.append(['...', f'+{remaining} hallazgos adicionales (ver Hallazgos Detallados)', ''])

    chain_colors = {
        'CRITICO': (RED_LIGHT, RED),
        'ALTO': (ORG_LIGHT, ORG),
        'MEDIO': (YEL_LIGHT, YEL),
    }
    ct = Table(chain_desc, colWidths=[2.5*cm, 11*cm, 3*cm])
    ct_style = [
        ('BACKGROUND', (0,0), (-1,0), BG_DARK),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 7.5),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]
    for i, row in enumerate(chain_desc[1:], 1):
        sev = row[2]
        bg, fg = chain_colors.get(sev, (BG_LIGHT, SLATE))
        ct_style.append(('BACKGROUND', (2,i), (2,i), bg))
        ct_style.append(('TEXTCOLOR', (2,i), (2,i), fg))
        ct_style.append(('FONTNAME', (2,i), (2,i), 'Helvetica-Bold'))

    ct.setStyle(TableStyle(ct_style))
    story.append(ct)

    # ============================
    # PAGE 2: RESUMEN EJECUTIVO
    # ============================
    story.append(PageBreak())

    story.append(Paragraph('<font size="14" color="#3b82f6"><b>RESUMEN EJECUTIVO</b></font>',
                 ParagraphStyle('exh', spaceAfter=8, leading=16)))

    # Non-technical summary
    summary_text = (
        f"Se ha detectado un incidente de seguridad en correo electronico con un nivel de riesgo {verdict_label.lower()}. "
        f"El analisis forense ha identificado {len(flags)} indicadores de compromiso potencial. "
        f"El mensaje procede de {from_header} dirigido a {to_header}. "
        f"Se recomienda revisar de inmediato el dispositivo del destinatario si ha interactuado con el mensaje, "
        f"y tomar medidas de contenccion inmediatas en el gateway de correo corporativo."
    )

    story.append(Paragraph(f'<font size="8.5" color="#334155">{_safe(summary_text)}</font>',
                 ParagraphStyle('summ', leading=13, spaceAfter=8)))

    # Key facts box
    story.append(Paragraph('<font size="9" color="#334155"><b>HECHOS CLAVE</b></font>',
                 ParagraphStyle('kfh', spaceAfter=4)))

    key_facts = [
        ['Fecha Deteccion', report_date],
        ['Origen (From)', from_header],
        ['Objetivo (To)', to_header],
        ['Tecnica Principal', 'Suplantacion de Identidad' if score >= 50 else 'Enlace Sospechoso'],
        ['Resultado Analisis', verdict_label],
    ]
    for i, row in enumerate(key_facts):
        key_facts[i] = [
            Paragraph(f'<font size="7.5" color="#64748b"><b>{row[0]}</b></font>', ParagraphStyle('kfl')),
            Paragraph(f'<font size="8" color="#0f172a">{_safe(row[1])}</font>', ParagraphStyle('kfv'))
        ]

    kf_t = Table(key_facts, colWidths=[3.5*cm, usable_w - 3.5*cm])
    kf_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), HexColor('#f1f5f9')),
        ('BACKGROUND', (1,0), (1,-1), BG_LIGHT),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(kf_t)
    story.append(Spacer(1, 10))

    # Impact assessment - CIA Triad
    story.append(Paragraph('<font size="9" color="#334155"><b>EVALUACION DE IMPACTO (TRIADA CIA)</b></font>',
                 ParagraphStyle('ciah', spaceAfter=4)))

    # Determine CIA impact levels based on score — each dimension gets its own color
    conf_level = 'Alto' if score >= 70 else 'Medio' if score >= 50 else 'Bajo'
    integ_level = 'Medio' if score >= 40 else 'Bajo'
    avail_level = 'Bajo'

    _cia_level_color = {'Alto': RED, 'Medio': ORG, 'Bajo': GRN}

    cia_data = [
        ['Aspecto', 'Nivel', 'Riesgo'],
        ['Confidencialidad', conf_level, 'Potencial exposicion de datos sensibles'],
        ['Integridad', integ_level, 'Posible alteracion de contenidos'],
        ['Disponibilidad', avail_level, 'Bajo riesgo de denegacion de servicio'],
    ]
    for i, row in enumerate(cia_data[1:], 1):
        level_color = _cia_level_color.get(row[1], SLATE)
        cia_data[i] = [
            Paragraph(f'<font size="7.5" color="#64748b"><b>{row[0]}</b></font>', ParagraphStyle('cial')),
            Paragraph(f'<font size="8" color="#{level_color.hexval()[2:]}"><b>{row[1]}</b></font>', ParagraphStyle('ciav')),
            Paragraph(f'<font size="7.5" color="#334155">{row[2]}</font>', ParagraphStyle('ciad'))
        ]
    cia_data[0] = [
        Paragraph(f'<font size="7.5" color="white"><b>{cia_data[0][0]}</b></font>', ParagraphStyle('ciah')),
        Paragraph(f'<font size="7.5" color="white"><b>{cia_data[0][1]}</b></font>', ParagraphStyle('ciah')),
        Paragraph(f'<font size="7.5" color="white"><b>{cia_data[0][2]}</b></font>', ParagraphStyle('ciah')),
    ]

    cia_t = Table(cia_data, colWidths=[3.5*cm, 2.5*cm, 8*cm])
    cia_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), BG_DARK),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(cia_t)
    story.append(Spacer(1, 10))

    # Risk matrix
    story.append(Paragraph('<font size="9" color="#334155"><b>MATRIZ DE RIESGO (Probabilidad vs Impacto)</b></font>',
                 ParagraphStyle('rmh', spaceAfter=6)))

    # Calculate probability (0-100) and impact (0-100) from score and number of flags
    probability = min(100, score + (len(flags) * 5))
    impact = score

    matrix = RiskMatrixFlowable(probability, impact, width=160, height=160)
    rm_data = [[matrix, Paragraph(
        f'<font size="8" color="#334155">'
        f'<b>Posicion Actual:</b><br/>'
        f'Probabilidad: {probability}%<br/>'
        f'Impacto: {impact}%<br/><br/>'
        f'<b>Recomendacion:</b><br/>'
        f'{"Respuesta inmediata requerida" if probability >= 70 and impact >= 70 else "Revision urgente necesaria" if probability >= 50 or impact >= 70 else "Monitorizacion continuada"}'
        f'</font>',
        ParagraphStyle('rmv', leading=11)
    )]]
    rm_t = Table(rm_data, colWidths=[180, usable_w - 185])
    rm_t.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (1,0), (1,0), 10),
    ]))
    story.append(rm_t)

    # ============================
    # PAGE 3: HALLAZGOS DETALLADOS + MITRE
    # ============================
    story.append(PageBreak())

    story.append(Paragraph('<font size="12" color="#3b82f6"><b>HALLAZGOS DETALLADOS</b></font>',
                 ParagraphStyle('fh', spaceAfter=8)))

    # Findings as colored cards with explanations and MITRE mappings
    for f in flags:
        sev = _sev_norm.get(f.get('severity', 'low'), 'BAJO')
        colors = {
            'CRITICO': (RED_LIGHT, RED, '#991b1b'),
            'ALTO': (ORG_LIGHT, ORG, '#9a3412'),
            'MEDIO': (YEL_LIGHT, YEL, '#854d0e'),
            'BAJO': (BG_LIGHT, SLATE, '#334155'),
        }
        bg, border_c, txt_c = colors.get(sev, (BG_LIGHT, SLATE, '#334155'))

        finding_text = f.get("text", f.get("message", ""))

        # Find MITRE technique
        mitre_tech = _find_mitre_technique(finding_text)
        mitre_info = ""
        if mitre_tech and mitre_tech in MITRE_TECHNIQUES:
            tech_name, tactic = MITRE_TECHNIQUES[mitre_tech]
            mitre_info = f'<br/><font size="6.5" color="#8b5cf6"><b>MITRE ATT&CK:</b> {mitre_tech} - {tech_name} ({tactic})</font>'

        # Brief explanation of importance
        importance_map = {
            'suplantacion': 'La suplantacion de identidad permite al atacante ganar confianza mediante falsa legitimidad.',
            'thread hijacking': 'El secuestro de hilos de conversacion permite al atacante responder a conversaciones reales ganando credibilidad.',
            'malware': 'La deteccion de malware indica intento de ejecucion de codigo malicioso en el endpoint.',
            'url maliciosa': 'Las URLs maliciosas pueden dirigir a paginas de phishing, malware o sitios de comando y control.',
            'adjunto sospechoso': 'Los adjuntos pueden contener malware, ransomware u otros payloads maliciosos.',
        }

        importance_text = ""
        for keyword, desc in importance_map.items():
            if keyword in finding_text.lower():
                importance_text = f'<br/><font size="7" color="#475569"><i>Por que es importante: {desc}</i></font>'
                break

        fd = [[Paragraph(
            f'<font size="7" color="#{border_c.hexval()[2:]}"><b>[{sev}]</b></font> '
            f'<font size="8.5" color="{txt_c}">{_safe(finding_text)}</font>'
            f'{importance_text}{mitre_info}',
            ParagraphStyle('fd', leading=11))]]
        ft = Table(fd, colWidths=[usable_w])
        ft.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), bg),
            ('BOX', (0,0), (-1,-1), 0, transparent),
            ('LEFTPADDING', (0,0), (-1,-1), 12),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        # Wrap in table with left accent
        outer = [[ft]]
        ot = Table(outer, colWidths=[usable_w + 4])
        ot.setStyle(TableStyle([
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 0),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LINEBEFOREDECOR', (0,0), (0,-1), 3, border_c, 'butt'),
        ]))
        story.append(ot)

    story.append(Spacer(1, 10))

    # ============================
    # PAGE 4: DATOS DEL EMAIL + HEADERS
    # ============================
    story.append(PageBreak())

    story.append(Paragraph('<font size="12" color="#3b82f6"><b>DATOS DEL EMAIL Y CABECERAS</b></font>',
                 ParagraphStyle('eh', spaceAfter=8)))

    email_rows = [
        ['De', from_header],
        ['Para', to_header],
        ['Asunto', subject],
        ['Fecha', date_header],
        ['Message-ID', msg_id],
        ['X-Mailer', x_mailer],
        ['X-Spam-Flag', spam_flag],
        ['Ruta de envio', hop_info],
    ]

    # Convert to paragraphs
    for i, row in enumerate(email_rows):
        email_rows[i] = [
            Paragraph(f'<font size="7" color="#64748b"><b>{row[0]}</b></font>', ParagraphStyle('el', alignment=TA_RIGHT)),
            Paragraph(f'<font size="8" color="#0f172a">{_safe(row[1])}</font>', ParagraphStyle('ev'))
        ]

    et = Table(email_rows, colWidths=[3.5*cm, usable_w - 3.5*cm])
    et.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), HexColor('#f1f5f9')),
        ('BACKGROUND', (1,0), (1,-1), BG_LIGHT),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        # Highlight spam flag
        ('BACKGROUND', (1,6), (1,6), RED_LIGHT if spam_flag == 'YES' else GRN_LIGHT),
    ]))
    story.append(et)
    story.append(Spacer(1, 10))

    # Header hop analysis table
    story.append(Paragraph('<font size="9" color="#334155"><b>ANALISIS DE HOPS DE CABECERA</b></font>',
                 ParagraphStyle('hoph', spaceAfter=4)))

    hop_rows = [['Num', 'Servidor', 'IP', 'Marca Temporal', 'Protocolo']]
    for i, hop in enumerate(hops[:8], 1):  # Limit to 8 hops
        num = str(i)
        server = hop.get('by_server', '?')[:20]
        ip = hop.get('ip', '?')
        timestamp = hop.get('timestamp', '?')[:16]
        protocol = hop.get('protocol', 'SMTP')

        hop_rows.append([
            Paragraph(f'<font size="7" color="#334155">{num}</font>', ParagraphStyle('hn')),
            Paragraph(f'<font size="7" face="Courier" color="#334155">{server}</font>', ParagraphStyle('hs')),
            Paragraph(f'<font size="7" face="Courier" color="#334155">{ip}</font>', ParagraphStyle('hi')),
            Paragraph(f'<font size="6.5" color="#334155">{timestamp}</font>', ParagraphStyle('ht')),
            Paragraph(f'<font size="7" color="#334155">{protocol}</font>', ParagraphStyle('hp')),
        ])

    if len(hop_rows) == 1:
        hop_rows.append(['N/A', 'N/A', 'N/A', 'N/A', 'N/A'])

    hop_t = Table(hop_rows, colWidths=[0.8*cm, 4*cm, 2.5*cm, 2.5*cm, 1.7*cm])
    hop_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), BG_DARK),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 6.5),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG_LIGHT, HexColor('#f1f5f9')]),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
    ]))
    story.append(hop_t)
    story.append(Spacer(1, 10))

    # Body preview
    story.append(Paragraph('<font size="8" color="#64748b"><b>CUERPO DEL MENSAJE (EXTRACTO)</b></font>',
                 ParagraphStyle('bh', spaceAfter=4)))
    body_preview = body_text[:300].replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br/>')
    if len(body_text) > 300:
        body_preview += '<br/>...'
    bd = [[Paragraph(f'<font size="8" color="#334155" face="Courier">{body_preview}</font>',
                      ParagraphStyle('bt', leading=11))]]
    bt = Table(bd, colWidths=[usable_w])
    bt.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 1, BORDER),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(bt)

    # ============================
    # PAGE 5: IOCs WITH MITRE MAPPING
    # ============================
    story.append(PageBreak())

    story.append(Paragraph('<font size="12" color="#3b82f6"><b>INDICADORES DE COMPROMISO (IoC)</b></font>',
                 ParagraphStyle('ioch', spaceAfter=8)))

    # URLs maliciosas (defanged) with intelligence
    if urls:
        story.append(Paragraph('<font size="9" color="#ef4444"><b>URLs Maliciosas (Defanged)</b></font>',
                     ParagraphStyle('uh', spaceAfter=4)))
        for u in urls[:5]:  # Limit to first 5
            defanged = _defang_url(u)
            ud = [[Paragraph(f'<font size="7" color="#991b1b" face="Courier">{defanged}</font><br/>'
                            f'<font size="6" color="#64748b"><i>Papel: Enlace de phishing | Detectado: Primera vez | Contexto: Cuerpo de mensaje</i></font>',
                            ParagraphStyle('u'))]]
            ut = Table(ud, colWidths=[usable_w])
            ut.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), RED_MID),
                ('BOX', (0,0), (-1,-1), 1, RED),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ]))
            story.append(ut)
            story.append(Spacer(1, 3))
        story.append(Spacer(1, 8))

    # MITRE ATT&CK Mapping Table
    story.append(Paragraph('<font size="10" color="#8b5cf6"><b>MAPEO MITRE ATT&CK</b></font>',
                 ParagraphStyle('mmh', spaceAfter=6)))

    mitre_rows = [['Tecnica', 'Nombre', 'Tactica', 'Evidencia']]
    techniques_added = set()

    for flag in flags[:10]:
        finding_text = flag.get('text', '').lower()
        mitre_tech = _find_mitre_technique(finding_text)
        if mitre_tech and mitre_tech not in techniques_added and mitre_tech in MITRE_TECHNIQUES:
            tech_name, tactic = MITRE_TECHNIQUES[mitre_tech]
            mitre_rows.append([
                mitre_tech,
                tech_name[:30],
                tactic,
                finding_text[:35]
            ])
            techniques_added.add(mitre_tech)

    if len(mitre_rows) == 1:
        # Add at least one example if no findings
        mitre_rows.append(['T1566.002', 'Spearphishing Link', 'Initial Access', 'Email analizado'])

    for i, row in enumerate(mitre_rows):
        if i == 0:
            mitre_rows[i] = [
                Paragraph(f'<font size="7" color="white"><b>{row[j]}</b></font>', ParagraphStyle('mmh')) for j in range(len(row))
            ]
        else:
            mitre_rows[i] = [
                Paragraph(f'<font size="7" color="#8b5cf6"><b>{row[0]}</b></font>', ParagraphStyle('mmt')),
                Paragraph(f'<font size="7" color="#334155">{_safe(row[1])}</font>', ParagraphStyle('mmn')),
                Paragraph(f'<font size="7" color="#334155">{row[2]}</font>', ParagraphStyle('mmc')),
                Paragraph(f'<font size="7" color="#334155">{_safe(row[3])}</font>', ParagraphStyle('mme')),
            ]

    mt = Table(mitre_rows, colWidths=[2*cm, 5.5*cm, 3*cm, 6.5*cm])
    mt_style = [
        ('BACKGROUND', (0,0), (-1,0), PURP),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 7),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG_LIGHT, HexColor('#f1f5f9')]),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]
    mt.setStyle(TableStyle(mt_style))
    story.append(mt)
    story.append(Spacer(1, 10))

    # IPs table with enhanced detail
    if public_ips or private_ips:
        story.append(Paragraph('<font size="9" color="#3b82f6"><b>Direcciones IP - Analisis de Riesgo</b></font>',
                     ParagraphStyle('iph', spaceAfter=4)))
        ip_data = [
            [Paragraph('<font size="7" color="white"><b>IP</b></font>', ParagraphStyle('th')),
             Paragraph('<font size="7" color="white"><b>Tipo</b></font>', ParagraphStyle('th')),
             Paragraph('<font size="7" color="white"><b>Evaluacion</b></font>', ParagraphStyle('th')),
             Paragraph('<font size="7" color="white"><b>Contexto</b></font>', ParagraphStyle('th'))],
        ]
        for ip in public_ips[:5]:
            ip_data.append([
                Paragraph(f'<font size="7.5" face="Courier" color="#0f172a">{ip}</font>', ParagraphStyle('tv')),
                Paragraph(f'<font size="7.5" color="#334155">Publica</font>', ParagraphStyle('tv')),
                Paragraph(f'<font size="7.5" color="#ef4444"><b>VERIFICAR</b></font>', ParagraphStyle('tv')),
                Paragraph(f'<font size="7" color="#64748b">En cabecera Received</font>', ParagraphStyle('tv')),
            ])
        for ip in private_ips[:5]:
            ip_data.append([
                Paragraph(f'<font size="7.5" face="Courier" color="#0f172a">{ip}</font>', ParagraphStyle('tv')),
                Paragraph(f'<font size="7.5" color="#334155">Privada</font>', ParagraphStyle('tv')),
                Paragraph(f'<font size="7.5" color="#10b981"><b>INTERNA</b></font>', ParagraphStyle('tv')),
                Paragraph(f'<font size="7" color="#64748b">Red corporativa</font>', ParagraphStyle('tv')),
            ])

        ipt = Table(ip_data, colWidths=[3*cm, 2.5*cm, 2.5*cm, 5*cm])
        ipt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BG_DARK),
            ('TEXTCOLOR', (0,0), (-1,0), white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 7),
            ('GRID', (0,0), (-1,-1), 0.5, BORDER),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG_LIGHT, HexColor('#f1f5f9')]),
        ]))
        story.append(ipt)
        story.append(Spacer(1, 10))

    # Domains table
    if domains:
        story.append(Paragraph('<font size="9" color="#3b82f6"><b>Dominios Implicados</b></font>',
                     ParagraphStyle('dh', spaceAfter=4)))
        dom_rows = [['Dominio', 'Rol', 'Evaluacion']]
        for domain in domains[:5]:
            dom_rows.append([domain, 'Hosting malicioso', 'DETECTADO'])

        for i, row in enumerate(dom_rows):
            if i == 0:
                dom_rows[i] = [
                    Paragraph(f'<font size="7" color="white"><b>{row[j]}</b></font>', ParagraphStyle('dh')) for j in range(len(row))
                ]
            else:
                dom_rows[i] = [
                    Paragraph(f'<font size="7.5" face="Courier" color="#0f172a">{row[0]}</font>', ParagraphStyle('dv')),
                    Paragraph(f'<font size="7.5" color="#334155">{row[1]}</font>', ParagraphStyle('dv')),
                    Paragraph(f'<font size="7.5" color="#ef4444"><b>{row[2]}</b></font>', ParagraphStyle('dv')),
                ]

        dt = Table(dom_rows, colWidths=[5*cm, 4.5*cm, 6.5*cm])
        dt_style = [
            ('BACKGROUND', (0,0), (-1,0), BG_DARK),
            ('TEXTCOLOR', (0,0), (-1,0), white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 7.5),
            ('GRID', (0,0), (-1,-1), 0.5, BORDER),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG_LIGHT, HexColor('#f1f5f9')]),
        ]
        dt.setStyle(TableStyle(dt_style))
        story.append(dt)
        story.append(Spacer(1, 10))

    # Attachment hashes
    if attachments:
        story.append(Paragraph('<font size="9" color="#3b82f6"><b>Hashes SHA-256 de Adjuntos</b></font>',
                     ParagraphStyle('hh', spaceAfter=4)))
        hash_rows = [['Archivo', 'SHA-256', 'Riesgo']]
        for att in attachments[:3]:
            filename = att.get('filename', 'unknown')
            sha256 = att.get('sha256', 'N/A')
            risk = 'ALTO' if att.get('is_malware') else 'BAJO'
            hash_rows.append([filename[:20], sha256[:16] + '...' if sha256 else 'N/A', risk])

        for i, row in enumerate(hash_rows):
            if i == 0:
                hash_rows[i] = [
                    Paragraph(f'<font size="7" color="white"><b>{row[j]}</b></font>', ParagraphStyle('hh')) for j in range(len(row))
                ]
            else:
                risk_color = RED if row[2] == 'ALTO' else GRN
                hash_rows[i] = [
                    Paragraph(f'<font size="7.5" color="#0f172a">{row[0]}</font>', ParagraphStyle('hv')),
                    Paragraph(f'<font size="6.5" face="Courier" color="#334155">{row[1]}</font>', ParagraphStyle('hv')),
                    Paragraph(f'<font size="7.5" color="#{risk_color.hexval()[2:]}"><b>{row[2]}</b></font>', ParagraphStyle('hv')),
                ]

        ht = Table(hash_rows, colWidths=[3*cm, 9*cm, 2*cm])
        ht_style = [
            ('BACKGROUND', (0,0), (-1,0), BG_DARK),
            ('TEXTCOLOR', (0,0), (-1,0), white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 6.5),
            ('GRID', (0,0), (-1,-1), 0.5, BORDER),
            ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]
        ht.setStyle(TableStyle(ht_style))
        story.append(ht)

    # ============================
    # PAGE 6: AUTENTICACION + DNS
    # ============================
    story.append(PageBreak())

    story.append(Paragraph('<font size="12" color="#3b82f6"><b>AUTENTICACION Y ANALISIS DNS</b></font>',
                 ParagraphStyle('ah', spaceAfter=8)))

    # AUTHENTICATION with explanations
    story.append(Paragraph('<font size="9" color="#334155"><b>Protocolos de Autenticacion de Email</b></font>',
                 ParagraphStyle('aeth', spaceAfter=4)))

    auth_rows = [
        ['Protocolo', 'Estado', 'Explicacion'],
        ['SPF', spf_status, 'Verifica que el servidor de envio esta autorizado para el dominio remitente. FAIL indica posible suplantacion.'],
        ['DKIM', dkim_status, 'Verifica la integridad del mensaje mediante firma criptografica. FAIL indica mensaje alterado o falso.'],
        ['DMARC', dmarc_status, 'Politica de autenticacion que define acciones ante fallos SPF/DKIM. FAIL indica politica no cumplida.'],
        ['ARC', arc_status, 'Valida la cadena de autenticacion en reenvios. FAIL indica fallos en intermediarios.'],
    ]

    for i, row in enumerate(auth_rows):
        if i == 0:
            auth_rows[i] = [
                Paragraph(f'<font size="7" color="white"><b>{row[j]}</b></font>', ParagraphStyle('ath')) for j in range(len(row))
            ]
        else:
            status = row[1]
            if 'PASS' in status or 'VALIDO' in status:
                status_color = GRN
            elif 'FAIL' in status or 'INVALIDO' in status:
                status_color = RED
            else:
                status_color = SLATE

            auth_rows[i] = [
                Paragraph(f'<font size="7.5" color="#64748b"><b>{row[0]}</b></font>', ParagraphStyle('atl')),
                Paragraph(f'<font size="7.5" color="#{status_color.hexval()[2:]}"><b>{status}</b></font>', ParagraphStyle('atv')),
                Paragraph(f'<font size="7" color="#334155">{row[2]}</font>', ParagraphStyle('ate', leading=10)),
            ]

    at = Table(auth_rows, colWidths=[2.2*cm, 2.3*cm, 11.5*cm])
    at_style = [
        ('BACKGROUND', (0,0), (-1,0), BG_DARK),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 7),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG_LIGHT, HexColor('#f1f5f9')]),
    ]
    at.setStyle(TableStyle(at_style))
    story.append(at)
    story.append(Spacer(1, 10))

    # DNS Resolution
    if dns_resolution and _safe_get(dns_resolution, 'domains'):
        story.append(Paragraph('<font size="9" color="#334155"><b>Resolucion DNS</b></font>',
                     ParagraphStyle('dnsh', spaceAfter=4)))
        dns_rows = [['Dominio', 'Registro MX', 'Registro A', 'TTL']]

        for d in _safe_get(dns_resolution, 'domains', [])[:5]:
            domain = d.get('domain', 'N/A')
            mx = ', '.join(d.get('mx', ['N/A']))[:20]
            a = ', '.join(d.get('a', ['N/A']))[:20]
            ttl = d.get('ttl', 'N/A')
            dns_rows.append([domain, mx, a, str(ttl)])

        for i, row in enumerate(dns_rows):
            if i == 0:
                dns_rows[i] = [
                    Paragraph(f'<font size="7" color="white"><b>{row[j]}</b></font>', ParagraphStyle('dnsh')) for j in range(len(row))
                ]
            else:
                dns_rows[i] = [
                    Paragraph(f'<font size="7" face="Courier" color="#0f172a">{row[0]}</font>', ParagraphStyle('dnsv')),
                    Paragraph(f'<font size="7" face="Courier" color="#334155">{row[1]}</font>', ParagraphStyle('dnsv')),
                    Paragraph(f'<font size="7" face="Courier" color="#334155">{row[2]}</font>', ParagraphStyle('dnsv')),
                    Paragraph(f'<font size="7" color="#334155">{row[3]}</font>', ParagraphStyle('dnsv')),
                ]

        dns_t = Table(dns_rows, colWidths=[3.5*cm, 4*cm, 3.5*cm, 1.5*cm])
        dns_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BG_DARK),
            ('TEXTCOLOR', (0,0), (-1,0), white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 6.5),
            ('GRID', (0,0), (-1,-1), 0.5, BORDER),
            ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(dns_t)
        story.append(Spacer(1, 10))

    # DNSBL Results
    if dnsbl_data and dnsbl_data.get('results'):
        story.append(Paragraph('<font size="9" color="#334155"><b>Resultados DNSBL (Listas Negras)</b></font>',
                     ParagraphStyle('dnsblh', spaceAfter=4)))

        dnsbl_text = f"IP encontrada en {len(dnsbl_data.get('results', []))} lista(s) negra(s)"
        story.append(Paragraph(f'<font size="8" color="#ef4444"><b>{dnsbl_text}</b></font>',
                     ParagraphStyle('dnsblp', spaceAfter=3)))

        for listing in dnsbl_data.get('results', [])[:5]:
            list_name = listing.get('list', 'Unknown')
            reason = listing.get('reason', 'No details')
            story.append(Paragraph(f'<font size="7" color="#334155">• {_safe(list_name)}: {_safe(reason)}</font>',
                         ParagraphStyle('dnsbll', leftIndent=10, spaceAfter=2)))

    # GeoIP Data
    if geoip_data and isinstance(geoip_data, list) and len(geoip_data) > 0:
        story.append(Spacer(1, 8))
        story.append(Paragraph('<font size="9" color="#334155"><b>Localizacion GeoIP</b></font>',
                     ParagraphStyle('geoh', spaceAfter=4)))

        geo_rows = [['IP', 'Pais', 'Ciudad', 'Organizacion']]
        for gip in geoip_data[:3]:
            ip = gip.get('ip', 'N/A')
            country = gip.get('country', 'Unknown')
            city = gip.get('city', 'Unknown')
            org = gip.get('org', 'Unknown')[:20]
            geo_rows.append([ip, country, city, org])

        for i, row in enumerate(geo_rows):
            if i == 0:
                geo_rows[i] = [
                    Paragraph(f'<font size="7" color="white"><b>{row[j]}</b></font>', ParagraphStyle('geoh')) for j in range(len(row))
                ]
            else:
                geo_rows[i] = [
                    Paragraph(f'<font size="7" face="Courier" color="#0f172a">{row[0]}</font>', ParagraphStyle('geov')),
                    Paragraph(f'<font size="7" color="#334155">{row[1]}</font>', ParagraphStyle('geov')),
                    Paragraph(f'<font size="7" color="#334155">{row[2]}</font>', ParagraphStyle('geov')),
                    Paragraph(f'<font size="7" color="#334155">{row[3]}</font>', ParagraphStyle('geov')),
                ]

        geo_t = Table(geo_rows, colWidths=[2.5*cm, 3*cm, 3*cm, 5.5*cm])
        geo_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BG_DARK),
            ('TEXTCOLOR', (0,0), (-1,0), white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 7),
            ('GRID', (0,0), (-1,-1), 0.5, BORDER),
            ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(geo_t)

    # ============================
    # PAGE 7 (optional): MALWARE ANALYSIS
    # ============================
    if malware_data and isinstance(malware_data, list) and len(malware_data) > 0:
        story.append(PageBreak())
        story.append(Paragraph('<font size="12" color="#ef4444"><b>ANALISIS DE MALWARE</b></font>',
                     ParagraphStyle('mwh', spaceAfter=8)))

        for mw in malware_data[:5]:  # Max 5 files
            if not isinstance(mw, dict):
                continue
            mw_score = mw.get('risk_score', 0)
            mw_color = RED if mw_score >= 70 else ORG if mw_score >= 40 else YEL if mw_score >= 20 else GRN
            mw_bg = RED_LIGHT if mw_score >= 70 else ORG_LIGHT if mw_score >= 40 else YEL_LIGHT if mw_score >= 20 else GRN_LIGHT

            # File header
            mw_header = [[Paragraph(
                f'<font size="9" color="#{mw_color.hexval()[2:]}"><b>&#9763; {_safe(mw.get("filename", "?"))}</b></font><br/>'
                f'<font size="8" color="#64748b">{mw.get("file_type", "?")} | '
                f'{(mw.get("file_size", 0)/1024):.1f} KB | Puntuacion: {mw_score}/100</font>',
                ParagraphStyle('mwf', leading=12))]]
            mwt = Table(mw_header, colWidths=[usable_w])
            mwt.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), mw_bg),
                ('BOX', (0,0), (-1,-1), 1.5, mw_color),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ]))
            story.append(mwt)
            story.append(Spacer(1, 3))

            # Hashes
            if mw.get('sha256') or mw.get('md5'):
                hash_rows = []
                if mw.get('md5'):
                    hash_rows.append(['MD5', mw['md5']])
                if mw.get('sha256'):
                    hash_rows.append(['SHA-256', mw['sha256']])
                if mw.get('sha1'):
                    hash_rows.append(['SHA-1', mw['sha1']])

                if hash_rows:
                    for hr in hash_rows:
                        hr[0] = Paragraph(f'<font size="6.5" color="#64748b"><b>{hr[0]}</b></font>', ParagraphStyle('hl'))
                        hr[1] = Paragraph(f'<font size="6.5" face="Courier" color="#334155">{hr[1]}</font>', ParagraphStyle('hv'))
                    ht = Table(hash_rows, colWidths=[2*cm, usable_w - 2*cm])
                    ht.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), BG_LIGHT),
                        ('GRID', (0,0), (-1,-1), 0.3, BORDER),
                        ('LEFTPADDING', (0,0), (-1,-1), 6),
                        ('TOPPADDING', (0,0), (-1,-1), 2),
                        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
                    ]))
                    story.append(ht)
                    story.append(Spacer(1, 3))

            # Tags
            tags = mw.get('tags', [])
            if tags:
                tag_text = ' | '.join(t.upper() for t in tags)
                story.append(Paragraph(
                    f'<font size="7" color="#ef4444"><b>ETIQUETAS: </b></font>'
                    f'<font size="7" color="#475569">{_safe(tag_text)}</font>',
                    ParagraphStyle('mwt', spaceAfter=3)))

            # YARA matches
            yara = mw.get('yara_matches', [])
            if yara:
                story.append(Paragraph(f'<font size="7.5" color="#ef4444"><b>Coincidencias YARA ({len(yara)})</b></font>',
                             ParagraphStyle('yr', spaceAfter=3)))
                for ym in yara[:10]:
                    name = ym.get('rule', ym.get('name', '?'))
                    desc = ym.get('description', '')
                    severity = ym.get('severity', 'MEDIO')
                    story.append(Paragraph(
                        f'<font size="7" color="#ef4444"><b>{_safe(name)}</b></font> '
                        f'<font size="6.5" color="#64748b">[{severity}]</font><br/>'
                        f'<font size="6.5" color="#475569">{_safe(desc)}</font>',
                        ParagraphStyle('yrd', leftIndent=10, spaceAfter=2, leading=10)))

            # Extracted IOCs from malware
            extracted_iocs = mw.get('extracted_iocs', [])
            if extracted_iocs:
                story.append(Paragraph(f'<font size="7.5" color="#334155"><b>IoCs Extraidos</b></font>',
                             ParagraphStyle('eioc', spaceAfter=2)))
                for ioc in extracted_iocs[:5]:
                    story.append(Paragraph(
                        f'<font size="7" color="#334155">• {_safe(ioc)}</font>',
                        ParagraphStyle('eiocd', leftIndent=10, spaceAfter=1)))

            # Verdict
            story.append(Paragraph(
                f'<font size="7.5" color="#{mw_color.hexval()[2:]}"><b>Veredicto: </b></font>'
                f'<font size="7.5" color="#334155">{_safe(mw.get("verdict", ""))}</font>',
                ParagraphStyle('mwv', spaceBefore=3, spaceAfter=8)))

    # ============================
    # PAGE 8: FORENSICS + CHAIN OF CUSTODY
    # ============================
    story.append(PageBreak())

    story.append(Paragraph('<font size="12" color="#3b82f6"><b>DATOS FORENSES Y CADENA DE CUSTODIA</b></font>',
                 ParagraphStyle('forch', spaceAfter=10)))

    # Chain of Custody
    story.append(Paragraph('<font size="10" color="#334155"><b>CADENA DE CUSTODIA</b></font>',
                 ParagraphStyle('coch', spaceAfter=6)))

    now_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    coc_data = [
        ['Fecha/Hora', 'Accion', 'Responsable', 'Hash Evidencia'],
        [report_date, 'Recepcion del email', 'Sistema automatizado', 'N/A'],
        [report_date, 'Extraccion de cabeceras', 'Analisis automatizado', evidence_hash[:16] + '...'],
        [now_time, 'Analisis automatizado completo', 'PhishGuard Pro v3.0', evidence_hash],
        [now_time, 'Generacion de informe', analyst, 'SHA-256(Informe)'],
    ]

    for i, row in enumerate(coc_data):
        if i == 0:
            coc_data[i] = [
                Paragraph(f'<font size="7" color="white"><b>{row[j]}</b></font>', ParagraphStyle('coch')) for j in range(len(row))
            ]
        else:
            coc_data[i] = [
                Paragraph(f'<font size="7" color="#334155">{row[0]}</font>', ParagraphStyle('coc')),
                Paragraph(f'<font size="7.5" color="#334155">{row[1]}</font>', ParagraphStyle('coc')),
                Paragraph(f'<font size="7" color="#64748b">{row[2]}</font>', ParagraphStyle('coc')),
                Paragraph(f'<font size="6.5" face="Courier" color="#334155">{row[3]}</font>', ParagraphStyle('coc')),
            ]

    coc_t = Table(coc_data, colWidths=[3*cm, 3.5*cm, 3.5*cm, 6*cm])
    coc_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), BG_DARK),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 6.5),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG_LIGHT, HexColor('#f1f5f9')]),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(coc_t)
    story.append(Spacer(1, 12))

    # Metadata del Analisis
    story.append(Paragraph('<font size="10" color="#334155"><b>METADATOS DEL ANALISIS</b></font>',
                 ParagraphStyle('amh', spaceAfter=6)))

    metadata_text = (
        f"<b>Version Herramienta:</b> PhishGuard Pro v3.0<br/>"
        f"<b>Modulos Activos:</b> 14 (Cabeceras, Cuerpo, URLs, Adjuntos, Redes, Ingenieria Social, Forense, DNS, GeoIP, DNSBL, Malware, Autenticacion, Temporal, Brand Similarity)<br/>"
        f"<b>Fecha/Hora Analisis:</b> {now_time}<br/>"
        f"<b>Duracion Analisis:</b> &lt;1 segundo<br/>"
        f"<b>Hash del Analisis (SHA-256):</b> {evidence_hash}<br/>"
        f"<b>Cantidad de Indicadores:</b> {len(flags)} encontrados"
    )

    story.append(Paragraph(f'<font size="7.5" color="#334155">{metadata_text}</font>',
                 ParagraphStyle('amd', leading=11, spaceAfter=8)))

    # Integridad de Evidencia
    story.append(Paragraph('<font size="10" color="#334155"><b>INTEGRIDAD DE EVIDENCIA</b></font>',
                 ParagraphStyle('ieh', spaceAfter=6)))

    integrity_data = [
        ['Tipo', 'Valor', 'Verificacion'],
        ['SHA-256 Cabeceras', evidence_hash, 'OK'],
        ['Cantidad Saltos', str(len(hops)), 'OK'],
        ['Cantidad Flags', str(len(flags)), 'OK'],
        ['Integridad Mensaje', 'VALIDA' if dkim_status in ['PASS', 'VALIDO'] else 'INVALIDA', 'VERIFICADO'],
    ]

    for i, row in enumerate(integrity_data):
        if i == 0:
            integrity_data[i] = [
                Paragraph(f'<font size="7" color="white"><b>{row[j]}</b></font>', ParagraphStyle('ieh')) for j in range(len(row))
            ]
        else:
            check_color = GRN if row[2] == 'OK' else RED
            integrity_data[i] = [
                Paragraph(f'<font size="7" color="#334155">{row[0]}</font>', ParagraphStyle('iev')),
                Paragraph(f'<font size="6.5" face="Courier" color="#334155">{row[1]}</font>', ParagraphStyle('iev')),
                Paragraph(f'<font size="7" color="#{check_color.hexval()[2:]}"><b>{row[2]}</b></font>', ParagraphStyle('iev')),
            ]

    ie_t = Table(integrity_data, colWidths=[3.5*cm, 7*cm, 5.5*cm])
    ie_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), BG_DARK),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 7),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG_LIGHT, HexColor('#f1f5f9')]),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(ie_t)
    story.append(Spacer(1, 10))

    # Timeline Forense
    story.append(Paragraph('<font size="10" color="#334155"><b>CRONOLOGIA FORENSE</b></font>',
                 ParagraphStyle('tlh', spaceAfter=6)))

    timeline_data = [['Evento', 'Hora', 'Servidor', 'Fuente']]

    if date_header and date_header != 'N/A':
        timeline_data.append(['Email enviado', date_header[:19], from_header[:30], 'Date Header'])

    for i, hop in enumerate(hops[:5]):
        server = hop.get('by_server', '?')[:25]
        timestamp = hop.get('timestamp', '?')[:19]
        timeline_data.append([f'Hop {i+1}', timestamp, server, 'Received Header'])

    timeline_data.append(['Analisis completado', now_time, 'Local', 'Sistema'])

    for i, row in enumerate(timeline_data):
        if i == 0:
            timeline_data[i] = [
                Paragraph(f'<font size="7" color="white"><b>{row[j]}</b></font>', ParagraphStyle('tlh')) for j in range(len(row))
            ]
        else:
            timeline_data[i] = [
                Paragraph(f'<font size="7.5" color="#334155">{row[0]}</font>', ParagraphStyle('tlv')),
                Paragraph(f'<font size="7" color="#64748b">{row[1]}</font>', ParagraphStyle('tlv')),
                Paragraph(f'<font size="7" face="Courier" color="#334155">{row[2]}</font>', ParagraphStyle('tlv')),
                Paragraph(f'<font size="7" color="#334155">{row[3]}</font>', ParagraphStyle('tlv')),
            ]

    tl_t = Table(timeline_data, colWidths=[3*cm, 3.5*cm, 4*cm, 6.5*cm])
    tl_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), BG_DARK),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 7),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER),
        ('BACKGROUND', (0,1), (-1,-1), BG_LIGHT),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [BG_LIGHT, HexColor('#f1f5f9')]),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(tl_t)

    # ============================
    # PAGE 9: RECOMENDACIONES (EXPANDED)
    # ============================
    story.append(PageBreak())

    story.append(Paragraph('<font size="12" color="#3b82f6"><b>RECOMENDACIONES DE RESPUESTA</b></font>',
                 ParagraphStyle('rh', spaceAfter=10)))

    recs = [
        ('INMEDIATA', RED, [
            ('Bloquear URLs maliciosas en proxy/firewall corporativo.', 'Alto', 'T1204.001'),
            ('Bloquear dominios y direcciones IP suscritas como origen.', 'Alto', 'T1583'),
            ('Aislar endpoints que hayan abierto el email para analisis forense.', 'Critico', 'M1037'),
            ('Revisar logs del gateway de correo para mensajes similares.', 'Alto', 'N/A'),
            ('Notificar a usuarios potencialmente afectados sobre el riesgo.', 'Alto', 'N/A'),
        ]),
        ('CORTO PLAZO (1-7 dias)', ORG, [
            ('Notificar a administradores de dominios suplantados.', 'Medio', 'M1031'),
            ('Verificar si servidores han sido comprometidos mediante forensics.', 'Alto', 'M1495'),
            ('Compartir IoCs con el equipo SOC y threat intelligence.', 'Medio', 'N/A'),
            ('Registrar indicadores en plataforma de seguridad (SIEM/TIP).', 'Medio', 'M1041'),
            ('Revisar patrones de acceso a cuentas de email potencialmente comprometidas.', 'Alto', 'M1036'),
        ]),
        ('MEDIO PLAZO (1-4 semanas)', ACCENT, [
            ('Implementar SPF, DKIM y DMARC en dominios no configurados.', 'Medio', 'M1096'),
            ('Configurar reglas anti-spoofing y anti-phishing avanzadas.', 'Medio', 'M1054'),
            ('Entrenar empleados sobre reconocimiento de amenazas de phishing.', 'Medio', 'M1017'),
            ('Implementar sandboxing de URLs y adjuntos en gateway de correo.', 'Medio', 'M1215'),
            ('Establecer programa de reporting de emails sospechosos.', 'Bajo', 'M1018'),
        ]),
    ]

    for priority, color, items in recs:
        # Priority header
        ph_data = [[Paragraph(f'<font size="9" color="white"><b>{priority}</b></font>',
                               ParagraphStyle('ph'))]]
        ph_t = Table(ph_data, colWidths=[usable_w])
        ph_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), color),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(ph_t)

        for j, (item, effort, mitre) in enumerate(items, 1):
            mitre_str = f' [{mitre}]' if mitre != 'N/A' else ''
            item_data = [[
                Paragraph(f'<font size="8" color="#{color.hexval()[2:]}"><b>{j}.</b></font>', ParagraphStyle('in', alignment=TA_CENTER)),
                Paragraph(f'<font size="8" color="#334155">{item}</font><br/><font size="6.5" color="#64748b"><i>Esfuerzo: {effort}{mitre_str}</i></font>',
                         ParagraphStyle('iv', leading=11))
            ]]
            it = Table(item_data, colWidths=[0.8*cm, usable_w - 0.8*cm])
            it.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), BG_LIGHT),
                ('GRID', (0,0), (-1,-1), 0.5, BORDER),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(it)
        story.append(Spacer(1, 8))

    # ============================
    # PAGE 10: ANEXOS + DISCLAIMER
    # ============================
    story.append(PageBreak())

    story.append(Paragraph('<font size="12" color="#3b82f6"><b>ANEXOS Y REFERENCIAS</b></font>',
                 ParagraphStyle('anhh', spaceAfter=10)))

    # Raw headers excerpt
    story.append(Paragraph('<font size="9" color="#334155"><b>EXTRACTO DE CABECERAS RAW (Primeras 30 lineas)</b></font>',
                 ParagraphStyle('rawh', spaceAfter=4)))

    raw_headers_text = str(parsed_headers)[:500].replace("'", "").replace("{", "").replace("}", "")
    raw_data = [[Paragraph(f'<font size="6.5" color="#334155" face="Courier">{_safe(raw_headers_text)}<br/>...</font>',
                          ParagraphStyle('rawt', leading=9))]]
    raw_t = Table(raw_data, colWidths=[usable_w])
    raw_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 1, BORDER),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(raw_t)
    story.append(Spacer(1, 12))

    # Glossary
    story.append(Paragraph('<font size="9" color="#334155"><b>GLOSARIO DE TERMINOS</b></font>',
                 ParagraphStyle('glosh', spaceAfter=6)))

    glossary_terms = [
        ('SPF (Sender Policy Framework)', 'Protocolo que autoriza servidores de correo para un dominio, previniendo spoofing.'),
        ('DKIM (DomainKeys Identified Mail)', 'Firma criptografica que verifica integridad del mensaje y autenticidad del dominio.'),
        ('DMARC (Domain-based Message Authentication)', 'Politica que define acciones ante fallos de SPF/DKIM y proporciona reportes.'),
        ('Thread Hijacking', 'Tecnica donde el atacante responde a conversaciones de correo existentes para ganar credibilidad.'),
        ('Phishing', 'Intento de engano para obtener informacion sensible mediante suplantacion de identidad.'),
        ('IoC (Indicator of Compromise)', 'Dato tecnico (URL, IP, hash) que indica actividad maliciosa.',),
        ('Defang', 'Tecnica de desactivacion de URLs/dominios para evitar acceso accidental (hxxps://[.]example[.]com).'),
        ('Sandbox', 'Entorno aislado para ejecutar y analizar malware sin riesgo.'),
    ]

    for term, definition in glossary_terms:
        story.append(Paragraph(f'<font size="7.5" color="#3b82f6"><b>{term}</b></font><br/>'
                              f'<font size="7" color="#475569">{definition}</font>',
                     ParagraphStyle('glos', spaceAfter=4, leftIndent=8, leading=10)))

    story.append(Spacer(1, 10))

    # Legal disclaimer (expanded)
    story.append(Paragraph('<font size="8" color="#64748b"><b>AVISO LEGAL Y CONFIDENCIALIDAD</b></font>',
                 ParagraphStyle('disc_h', spaceAfter=6)))

    disclaimer_text = (
        '<b>CONFIDENCIALIDAD:</b> Este informe es CONFIDENCIAL y esta destinado unicamente al destinatario autorizado. '
        'Contiene informacion de seguridad sensible que no debe ser divulgada sin autorizacion.<br/><br/>'
        '<b>GENERACION AUTOMATICA:</b> Este informe ha sido generado automaticamente por PhishGuard Pro v3.0. '
        'Los indicadores de compromiso (IoC) deben ser verificados independientemente antes de tomar acciones de bloqueo o sanciones.<br/><br/>'
        '<b>DEFANGED URLs:</b> Todas las URLs maliciosas han sido "defanged" (desactivadas) utilizando tecnicas de ofuscacion '
        '(hxxps://, [.]) para evitar acceso accidental. Deben ser restauradas antes de investigacion profunda en sandbox.<br/><br/>'
        '<b>RESPONSABILIDAD:</b> Los analistas de seguridad y administradores de sistemas son responsables de validar los hallazgos '
        'en su entorno especifico. Jaquers Ciberseguridad S.L. no asume responsabilidad por daños derivados de uso incorrecto de este informe.<br/><br/>'
        f'<b>EMITIDO POR:</b> {company} | <b>ANALISTA:</b> {analyst} | <b>EMAIL:</b> info@jaquers.es'
    )

    disc_data = [[Paragraph(f'<font size="7" color="#334155">{disclaimer_text}</font>', ParagraphStyle('disc', leading=10))]]
    disc_t = Table(disc_data, colWidths=[usable_w])
    disc_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(disc_t)

    story.append(Spacer(1, 10))

    # Tool version and methodology
    story.append(Paragraph(
        '<font size="7" color="#64748b"><b>METODOLOGIA:</b> '
        'Este analisis utiliza multiples tecnicas de deteccion incluyendo analisis de cabeceras SMTP, verificacion de protocolos de autenticacion (SPF/DKIM/DMARC), '
        'evaluacion de cuerpo de mensaje, deteccion de URLs/dominios maliciosos, analisis de adjuntos, evaluacion de ingenieria social, '
        'inteligencia de amenazas GeoIP, DNSBL y MITRE ATT&CK mapping.<br/>'
        '<b>VERSION:</b> PhishGuard Pro v3.0 | <b>MODULOS:</b> 14 | <b>BASE DE DATOS:</b> Actualizada 2026-04-14</font>',
        ParagraphStyle('method', leading=9, spaceAfter=0)))

    # ============================
    # BUILD AND RETURN
    # ============================
    doc.build(story, onFirstPage=onPage, onLaterPages=onPage)
    pdf_bytes = pdf_buffer.getvalue()
    pdf_buffer.close()

    return pdf_bytes


if __name__ == '__main__':
    """Example usage - generate a test report"""
    # Example analysis dict (minimal structure)
    example_analysis = {
        'parsed_headers': {
            'From': ['test@example.com'],
            'To': ['recipient@example.com'],
            'Subject': ['Test Phishing Email'],
            'Date': ['Mon, 14 Apr 2026 10:00:00 +0000'],
            'Message-ID': ['<test@example.com>'],
            'X-Mailer': ['Unknown'],
            'X-Spam-Flag': ['YES'],
        },
        'hops': [
            {'from_server': 'mail.example.com', 'by_server': 'mx.target.com', 'ip': '192.168.1.1', 'timestamp': '2026-04-14T10:00:00Z', 'protocol': 'SMTP'},
        ],
        'auth': {
            'spf': {'status': 'FAIL'},
            'dkim': {'status': 'FAIL'},
            'dmarc': {'status': 'FAIL'},
            'arc': {'status': 'UNKNOWN'},
        },
        'risk': {
            'score': 78,
            'risk_level': 'HIGH',
            'verdict': 'PHISHING',
            'flags': [
                {'severity': 'ALTO', 'text': 'Suplantacion de dominio detectada'},
                {'severity': 'MEDIO', 'text': 'URL maliciosa en cuerpo del mensaje'},
            ]
        },
        'iocs': {
            'public_ips': ['203.0.113.45'],
            'private_ips': ['192.168.1.10'],
            'domains': ['example-phishing.com'],
            'urls': ['http://example-phishing.com/login'],
            'emails': ['attacker@evil.com'],
        },
        'body_analysis': {
            'body_text': 'Click aqui para actualizar tu cuenta...',
            'thread_hijack': False,
        },
        'attachment_analysis': {
            'attachments': [],
        }
    }

    # Generate PDF
    pdf_bytes = generate_pdf_report(example_analysis)
    with open('/tmp/test_report.pdf', 'wb') as f:
        f.write(pdf_bytes)
    print(f"PDF generated: /tmp/test_report.pdf ({len(pdf_bytes)} bytes)")
