@echo off
setlocal
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
    echo No existe el entorno virtual.
    echo Ejecuta primero herramientas\instalar_dependencias.bat
    pause
    exit /b 1
)

.venv\Scripts\python.exe -m pytest -q
set "EXIT_CODE=%ERRORLEVEL%"
pause
exit /b %EXIT_CODE%
