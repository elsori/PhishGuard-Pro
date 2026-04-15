@echo off
cd /d "%~dp0"
title PhishGuard Pro v3.0
color 0B
echo.
echo   ============================================
echo     PhishGuard Pro v3.0
echo     Framework de Analisis de Phishing
echo     14 modulos + Malware Engine
echo     Sergio Soriano
echo   ============================================
echo.

:: Buscar Python real (no el alias de Microsoft Store)
set PYTHON=

:: py launcher primero (mas fiable en Windows)
where py >nul 2>&1
if %ERRORLEVEL%==0 (
    py -c "import sys; print(sys.version)" >nul 2>&1
    if %ERRORLEVEL%==0 (
        set PYTHON=py
        goto :found
    )
)

:: python (verificar que NO es alias de MS Store)
where python >nul 2>&1
if %ERRORLEVEL%==0 (
    python -c "import sys; sys.exit(0)" >nul 2>&1
    if %ERRORLEVEL%==0 (
        set PYTHON=python
        goto :found
    )
)

:: python3 (verificar que NO es alias de MS Store)
where python3 >nul 2>&1
if %ERRORLEVEL%==0 (
    python3 -c "import sys; sys.exit(0)" >nul 2>&1
    if %ERRORLEVEL%==0 (
        set PYTHON=python3
        goto :found
    )
)

:: Rutas comunes
if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
    set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    goto :found
)
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    goto :found
)
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    goto :found
)
if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
    set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    goto :found
)

echo   [ERROR] No se encontro Python instalado.
echo   El alias de Python de Microsoft Store NO funciona.
echo   Instala Python real desde: https://www.python.org/downloads/
echo   Marca [x] Add Python to PATH durante la instalacion.
echo.
pause
goto :eof

:found
echo   [OK] Python encontrado: %PYTHON%
echo.

%PYTHON% phishguard.py --port 8080

pause
