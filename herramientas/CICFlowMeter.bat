@echo off
setlocal

if not defined JAVA_HOME if exist "C:\Program Files\Eclipse Adoptium\jdk-8.0.512.9-hotspot" set "JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-8.0.512.9-hotspot"
if not defined CFM_HOME set "CFM_HOME=%~dp0CICFlowMeter-instalado\CICFlowMeter-4.0"

if not exist "%CFM_HOME%\bin\cfm.bat" (
    echo No se encontro CICFlowMeter en "%CFM_HOME%".
    echo Define CFM_HOME con la ruta de CICFlowMeter-4.0.
    exit /b 1
)

if not "%~1"=="" if "%~2"=="" (
    echo Debes indicar el PCAP de entrada y la carpeta de salida.
    exit /b 2
)

set "INPUT=%~f1"
set "OUTPUT=%~f2"
if not "%~2"=="" if not exist "%OUTPUT%\" mkdir "%OUTPUT%"
pushd "%CFM_HOME%\bin"
if "%~1"=="" (
    call "%CFM_HOME%\bin\CICFlowMeter.bat"
) else (
    call "%CFM_HOME%\bin\cfm.bat" "%INPUT%" "%OUTPUT%"
)
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%
