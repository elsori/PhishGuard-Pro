#!/bin/bash
cd "$(dirname "$0")"
echo ""
echo "  ============================================"
echo "    PhishGuard Pro v3.0"
echo "    Framework de Analisis de Phishing"
echo "    14 modulos + Malware Engine"
echo "    Sergio Soriano"
echo "  ============================================"
echo ""

# Activate venv if exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "  [OK] Virtual environment activado"
fi

PYTHON=""
if command -v python3 &>/dev/null; then
    PYTHON="python3"
elif command -v python &>/dev/null; then
    PYTHON="python"
else
    echo "  [ERROR] No se encontro Python 3 instalado."
    echo "  Instala con:"
    echo "    Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "    Fedora/RHEL:   sudo dnf install python3 python3-pip"
    echo "    Kali:          sudo apt install python3 python3-pip"
    echo "    macOS:         brew install python3"
    exit 1
fi

echo "  [OK] Python encontrado: $PYTHON"
echo ""
echo "  La verificacion de modulos se realiza automaticamente al iniciar."
echo "  Los modulos faltantes se instalaran/actualizaran automaticamente."
echo ""

$PYTHON phishguard.py --port 8080
