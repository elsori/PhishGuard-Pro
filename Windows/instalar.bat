@echo off
cd /d "%~dp0"
title PhishGuard Pro - Instalador
color 0B
echo.
echo   ============================================
echo     PhishGuard Pro v3.0 - Instalador
echo     Sergio Soriano
echo   ============================================
echo.

:: Buscar Python real (no el alias de Microsoft Store)
set PYTHON=

:: Probar py launcher primero (mas fiable en Windows)
where py >nul 2>&1
if %ERRORLEVEL%==0 (
    py -c "import sys; print(sys.version)" >nul 2>&1
    if %ERRORLEVEL%==0 (
        set PYTHON=py
        goto :found
    )
)

:: Probar python (verificar que NO es el alias de Microsoft Store)
where python >nul 2>&1
if %ERRORLEVEL%==0 (
    python -c "import sys; sys.exit(0)" >nul 2>&1
    if %ERRORLEVEL%==0 (
        set PYTHON=python
        goto :found
    )
)

:: Probar python3 (verificar que NO es el alias de Microsoft Store)
where python3 >nul 2>&1
if %ERRORLEVEL%==0 (
    python3 -c "import sys; sys.exit(0)" >nul 2>&1
    if %ERRORLEVEL%==0 (
        set PYTHON=python3
        goto :found
    )
)

:: Buscar en rutas comunes de instalacion
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
if exist "C:\Python313\python.exe" (
    set "PYTHON=C:\Python313\python.exe"
    goto :found
)
if exist "C:\Python312\python.exe" (
    set "PYTHON=C:\Python312\python.exe"
    goto :found
)
if exist "C:\Python311\python.exe" (
    set "PYTHON=C:\Python311\python.exe"
    goto :found
)
if exist "C:\Python310\python.exe" (
    set "PYTHON=C:\Python310\python.exe"
    goto :found
)

echo.
echo   [ERROR] No se encontro Python instalado.
echo.
echo   IMPORTANTE: El alias de Python de Microsoft Store NO funciona.
echo   Debes instalar Python real desde:
echo.
echo       https://www.python.org/downloads/
echo.
echo   Durante la instalacion marca estas opciones:
echo     [x] Add Python to PATH
echo     [x] Install pip
echo.
pause
goto :eof

:found
echo   [OK] Python encontrado: %PYTHON%

:: Mostrar version
%PYTHON% --version 2>&1
echo.

:: Verificar que pip esta disponible
%PYTHON% -m pip --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo   [AVISO] pip no encontrado. Instalando pip...
    %PYTHON% -m ensurepip --upgrade >nul 2>&1
    %PYTHON% -m pip --version >nul 2>&1
    if %ERRORLEVEL% neq 0 (
        echo   [ERROR] No se pudo instalar pip.
        echo   Prueba manualmente: %PYTHON% -m ensurepip --upgrade
        echo.
        pause
        goto :eof
    )
)

echo   Instalando dependencias...
echo.
%PYTHON% -m pip install --upgrade -r requirements.txt
if %ERRORLEVEL%==0 (
    echo.
    echo   ============================================
    echo   [OK] Instalacion completada correctamente.
    echo   ============================================
    echo.
    echo   Para iniciar PhishGuard Pro ejecuta: start.bat
) else (
    echo.
    echo   [AVISO] Hubo un problema con pip install.
    echo   Prueba manualmente:
    echo     %PYTHON% -m pip install reportlab
    echo.
    echo   Si el error persiste, prueba como administrador
    echo   o usa: %PYTHON% -m pip install --user reportlab
)
echo.
pause
