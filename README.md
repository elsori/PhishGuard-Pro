# PhishGuard Pro v3.0

**Framework profesional de analisis, seguimiento, auditoria e informe de phishing.**

Desarrollado por **Jaquers Ciberseguridad S.L.** — Sergio Soriano

---

## Requisitos

- Python 3.8 o superior
- Navegador web moderno (Chrome, Firefox, Edge)

Las dependencias se instalan automaticamente al ejecutar el launcher.

## Inicio rapido

### Windows
1. Ejecuta `instalar.bat` (solo la primera vez)
2. Ejecuta `start.bat`

### Linux / macOS
```bash
chmod +x instalar.sh start.sh
./instalar.sh
./start.sh
```

### Manual
```bash
pip install reportlab
python phishguard.py --port 8080
```

Se abrira automaticamente `http://localhost:8080` en tu navegador.

---

## Modulos de analisis (14)

| # | Modulo | Descripcion |
|---|--------|-------------|
| 1 | Header Parser | Analisis completo de cabeceras SMTP |
| 2 | Auth Analyzer | Verificacion SPF, DKIM, DMARC, ARC |
| 3 | IOC Extractor | Extraccion de IPs, dominios, emails, URLs |
| 4 | Risk Engine | Puntuacion de riesgo 0-100 con 30+ reglas |
| 5 | GeoIP Locator | Geolocalizacion de IPs con mapa interactivo |
| 6 | DNSBL Checker | Consulta en 12+ listas negras DNS |
| 7 | DNS Resolver | Resolucion MX, A, TXT de dominios |
| 8 | Header Forensics | Deteccion de anomalias y falsificaciones |
| 9 | Homoglyph Detector | Deteccion de caracteres Unicode sospechosos |
| 10 | Brand Similarity | Similitud con marcas conocidas (Levenshtein) |
| 11 | URL Intelligence | Analisis de URLs con deteccion de ofuscacion |
| 12 | Sender Intel | Verificacion de coherencia del remitente |
| 13 | Body Analyzer | Analisis de cuerpo: ingenieria social, URLs maliciosas, thread hijacking |
| 14 | Attachment Analyzer | Analisis de adjuntos: extensiones peligrosas, hashes SHA-256 |

## Motor de Malware

- Analisis estatico de ejecutables PE, ELF, Mach-O
- Deteccion de scripts maliciosos (VBA, PowerShell, JavaScript)
- 6 motores de deteccion integrados
- Extraccion de IoCs de archivos sospechosos

## Inteligencia de Amenazas (v3.0)

| Conector | Descripcion |
|----------|-------------|
| VirusTotal | Reputacion de IPs, dominios, URLs, hashes |
| AbuseIPDB | Score de abuso y reportes de IPs |
| Shodan | Puertos abiertos, vulnerabilidades, servicios |
| AlienVault OTX | Pulsos de amenazas, correlacion |
| IPQualityScore | Deteccion de proxies, VPN, bots, fraude |

## Asistentes IA (v3.0)

| Proveedor | Modelos |
|-----------|---------|
| OpenAI (ChatGPT) | gpt-4o-mini, gpt-4o, gpt-4-turbo |
| Anthropic (Claude) | claude-sonnet-4, claude-haiku-4.5, claude-opus-4 |
| Google (Gemini) | gemini-2.0-flash, gemini-1.5-pro, gemini-1.5-flash |
| Mistral AI | mistral-large, mistral-small, open-mistral-nemo |
| Groq | llama-3.3-70b, llama-3.1-8b, mixtral-8x7b |
| DeepSeek | deepseek-chat, deepseek-reasoner |

## Gestion de Clientes

- Base de datos SQLite para archivar clientes y escaneos
- Perfil completo: nombre, empresa, email, telefono, sector
- Historico de escaneos por cliente con estadisticas
- Auto-guardado de analisis asociados a clientes

## Funcionalidades

- **Analisis de cabeceras**: Pega cabeceras de email o sube archivos `.eml` / `.msg`
- **Soporte .MSG nativo**: Parser OLE2 puro en Python, sin dependencias externas
- **Gestion de casos**: Crea, asigna y trackea investigaciones
- **Gestion de clientes**: Base de datos SQLite con historico de escaneos
- **Mapa GeoIP interactivo**: Visualizacion con Leaflet.js + fallback SVG (Windows offline)
- **Informes profesionales**: PDF multi-pagina con diagramas, HTML, JSON, CSV, STIX 2.1
- **Threat Intelligence**: 5 conectores externos (VT, AbuseIPDB, Shodan, OTX, IPQS)
- **Asistentes IA**: 6 proveedores (OpenAI, Claude, Gemini, Mistral, Groq, DeepSeek)
- **Auditoria completa**: Log de todas las acciones del analista
- **Bilingue**: Interfaz y reportes en espanol e ingles

## Estructura de archivos

```
PhishGuard_Pro/
├── Windows/
│   ├── phishguard.py        # Servidor principal + API REST
│   ├── modules.py           # 14 modulos de analisis
│   ├── malware_analyzer.py  # Motor de analisis de malware
│   ├── report_pdf.py        # Generador de informes PDF
│   ├── client_db.py         # Gestion de clientes SQLite
│   ├── connectors.py        # ThreatIntel + AI connectors
│   ├── frontend.html        # Interfaz web completa
│   ├── instalar.bat         # Instalador Windows
│   ├── start.bat            # Launcher Windows
│   ├── requirements.txt     # Dependencias Python
│   ├── README.md            # Este archivo
│   └── data/                # Datos persistentes
└── Linux/
    ├── (mismos archivos Python + HTML)
    ├── instalar.sh          # Instalador Linux/macOS
    ├── start.sh             # Launcher Linux/macOS
    └── data/
```

## API REST

| Endpoint | Metodo | Descripcion |
|----------|--------|-------------|
| `/api/analyze` | POST | Analiza cabeceras de email |
| `/api/analyze-msg` | POST | Analiza archivo .msg (base64) |
| `/api/analyze-malware` | POST | Analiza archivo sospechoso |
| `/api/report/pdf` | POST | Genera informe PDF profesional |
| `/api/report/html` | POST | Genera informe HTML |
| `/api/report/json` | POST | Genera informe JSON |
| `/api/report/csv` | POST | Exporta IoCs en CSV |
| `/api/report/stix` | POST | Exporta en formato STIX 2.1 |
| `/api/cases` | GET/POST | Gestion de casos |
| `/api/clients` | GET/POST | Gestion de clientes |
| `/api/clients/<id>/scans` | GET | Escaneos de un cliente |
| `/api/enrich` | POST | Enriquecimiento ThreatIntel |
| `/api/ai/analyze` | POST | Analisis con IA |
| `/api/connectors/test` | POST | Test de conectores |
| `/api/history` | GET | Historial de analisis |
| `/api/stats` | GET | Estadisticas del dashboard |
| `/api/config` | GET/POST | Configuracion del sistema |

---

**Licencia**: Uso interno — Jaquers Ciberseguridad S.L.
