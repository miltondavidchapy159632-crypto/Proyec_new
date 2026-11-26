# Herramientas y lanzadores

## Archivos incluidos

| Archivo | Uso |
|---|---|
| `abrir_tablero.bat` | Inicia Streamlit y abre `http://127.0.0.1:8501` |
| `instalar_dependencias.bat` | Crea `.venv` e instala `requirements.txt` |
| `ejecutar_pruebas.bat` | Ejecuta las pruebas con pytest |
| `servidor_laboratorio.ps1` | Servicio HTTP de prueba enlazado a `192.168.56.102:8080` |
| `CICFlowMeter.bat` | Abre CICFlowMeter o convierte un PCAP a CSV |

Los tres primeros requieren Python 3.12 y ejecutarse desde la raíz del proyecto. Los `.bat` cambian automáticamente a esa carpeta.

## Dependencias externas no incluidas

Para repetir el laboratorio completo hacen falta:

- VirtualBox.
- Una VM Kali aislada.
- Wireshark y Npcap para captura en vivo.
- Java 8 para CICFlowMeter 4.0.
- Una instalación o compilación de CICFlowMeter.

No se suben instaladores ni binarios compilados a GitHub. CICFlowMeter se puede obtener desde https://github.com/ISCX/CICFlowMeter.

## Configurar el lanzador de CICFlowMeter

El lanzador busca la instalación en:

```text
herramientas\CICFlowMeter-instalado\CICFlowMeter-4.0
```

Esa carpeta no está incluida. Si la instalación está en otro lugar, definir `CFM_HOME` antes de ejecutar el lanzador. Por ejemplo, en CMD:

```bat
set "CFM_HOME=C:\ruta\a\CICFlowMeter-4.0"
herramientas\CICFlowMeter.bat "capturas\normal.pcap" "datos\procesados\normal"
```

El lanzador usa `JAVA_HOME` si está definido; si no, utiliza el `java` disponible en `PATH`.

## Servidor HTTP del laboratorio

Desde CMD, en la raíz del proyecto:

```bat
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File herramientas\servidor_laboratorio.ps1
```

Desde Kali, dentro de la red aislada:

```bash
curl --noproxy "*" http://192.168.56.102:8080
```

Debe responder `Laboratorio IDS activo`. El servicio escucha solamente en la IP del laboratorio. No exponer el puerto a otras redes y no desactivar reglas de firewall personales para esta prueba.
