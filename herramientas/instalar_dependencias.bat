@echo off
setlocal
cd /d "%~dp0.."

where py >nul 2>nul
if errorlevel 1 (
    echo No se encontro el lanzador py de Python.
    echo Instala Python 3.12 y vuelve a ejecutar este archivo.
    pause
    exit /b 1
)

py -3.12 -m venv .venv
if errorlevel 1 (
    echo No se pudo crear el entorno virtual.
    pause
    exit /b 1
)

.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
    echo No se pudieron instalar las dependencias.
    pause
    exit /b 1
)

echo Instalacion completada.
echo Ejecuta herramientas\ejecutar_pruebas.bat para comprobar el proyecto.
pause
