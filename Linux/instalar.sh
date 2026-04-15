#!/bin/bash
cd "$(dirname "$0")"
echo ""
echo "  ============================================"
echo "    PhishGuard Pro v3.0 - Instalador"
echo "    Sergio Soriano"
echo "  ============================================"
echo ""

PYTHON=""
command -v python3 &>/dev/null && PYTHON="python3" || { command -v python &>/dev/null && PYTHON="python"; }
[ -z "$PYTHON" ] && { echo "  [ERROR] Python no encontrado. Instala python3."; exit 1; }
echo "  [OK] Python: $PYTHON"
echo ""
echo "  Instalando dependencias..."

# Try normal pip first, then --break-system-packages for externally managed envs (Kali/Debian/Ubuntu)
$PYTHON -m pip install --upgrade -r requirements.txt 2>/dev/null
if [ $? -ne 0 ]; then
    echo ""
    echo "  [INFO] Entorno gestionado detectado (Kali/Debian). Usando --break-system-packages..."
    $PYTHON -m pip install --upgrade --break-system-packages -r requirements.txt
fi

if [ $? -eq 0 ]; then
    echo ""
    echo "  [OK] Dependencias instaladas correctamente."
    echo "  Ejecuta: ./start.sh"
else
    echo ""
    echo "  [AVISO] Fallo la instalacion con pip."
    echo "  Alternativas:"
    echo "    1. sudo apt install python3-reportlab"
    echo "    2. python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
fi
echo ""
