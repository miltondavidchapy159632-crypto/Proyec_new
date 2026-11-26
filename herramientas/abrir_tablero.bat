@echo off
setlocal
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
    echo No existe el entorno virtual.
    echo Ejecuta primero herramientas\instalar_dependencias.bat
    pause
    exit /b 1
)

if not exist "modelos\modelo_ids.joblib" (
    echo No se encuentra modelos\modelo_ids.joblib
    pause
    exit /b 1
)

set "STREAMLIT_BROWSER_GATHER_USAGE_STATS=false"
start "Servidor del tablero IDS" cmd /c ".venv\Scripts\python.exe -m streamlit run src/app.py"
timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:8501"

echo El tablero se abrio en http://127.0.0.1:8501
echo Cierra la ventana "Servidor del tablero IDS" para detenerlo.
pause
