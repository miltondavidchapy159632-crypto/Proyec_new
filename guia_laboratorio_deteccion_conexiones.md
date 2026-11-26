# Guía paso a paso: laboratorio de detección de conexiones maliciosas con Machine Learning

## 1. Entender la tarea

Según la conversación de la captura, el trabajo propuesto es:

> Entrenar un modelo de Machine Learning con datos de CIC, desplegarlo en un servidor virtualizado y pasarle información de las conexiones de red para que indique si una conexión es maliciosa o no.

La arquitectura sugerida es:

```text
PC 2 — Kali Linux                     PC 1 — Windows
Atacante de laboratorio               Servidor víctima y sensor
      |                                      |
      |        Red interna aislada            | tcpdump / captura de tráfico
      +--------------------------------------+
                                             |
                                             v
                                    Archivo PCAP de la prueba
                                             |
                                             v
                                   CICFlowMeter: características
                                             |
                                             v
                                   CSV de flujos de red
                                             |
                                             v
                            Modelo de Python + tablero Streamlit
                                             |
                                             v
                         Alerta: BENIGNO o MALICIOSO + evidencia
```

### Resultado esperado

Una aplicación que:

1. Cargue el modelo entrenado.
2. Lea las características de conexiones de red.
3. Clasifique cada conexión como `BENIGNO` o `MALICIOSO`.
4. Muestre la IP de origen y destino, los puertos, la probabilidad y la hora.
5. Guarde un historial de alertas.
6. Permita relacionar una alerta con la captura de tráfico que la originó.

### Alcance mínimo recomendado

Para una presentación académica, no es necesario reproducir todos los ataques de CIC-IDS2017. Alcanza con:

- Un clasificador binario: `BENIGNO` frente a `MALICIOSO`.
- Tráfico normal generado por ustedes.
- Un escaneo de puertos controlado.
- Una prueba de fuerza bruta contra un servicio de prueba.
- Una demostración con capturas de tráfico propias.

> La captura no incluye fecha de entrega, rúbrica ni una definición más detallada del alcance. Conviene confirmar esos puntos con el docente antes de invertir demasiado tiempo.

---

## 2. Definir roles y preparar el entorno

### Material necesario

- VirtualBox.
- Una VM con Windows para `PC 1`.
- Una VM con Kali Linux para `PC 2`.
- Python 3.10 o superior.
- Espacio suficiente para las VM, el dataset y las capturas.
- Preferentemente, al menos 8 GB de RAM disponibles para las VM.

### Pasos

1. **Respaldar la VM existente.** Si ya tienen un servidor virtualizado del trabajo anterior, crear una instantánea antes de modificarlo.
2. **Crear o reutilizar `PC 1`.** Puede ser Windows. Allí funcionarán el servicio víctima, el sensor, el modelo y el tablero.
3. **Crear `PC 2`.** Instalar Kali Linux solo para las pruebas ofensivas autorizadas.
4. **Configurar la red como Red interna o Solo anfitrión.** No usar el modo puente conectado a la red de la universidad durante las pruebas.
5. **Comprobar conectividad únicamente entre las dos VM.**
6. **Asignar IP fijas dentro de la red aislada**, por ejemplo:

| Equipo | IP sugerida | Función |
|---|---:|---|
| PC 1 — Windows | `192.168.56.102` | Víctima, sensor y detector |
| PC 2 — Kali | `192.168.56.101` | Atacante de laboratorio |

7. **Verificar el aislamiento.** Durante las pruebas, las VM no deben tener salida a Internet.

### Evidencia para guardar

- Captura de la configuración de red de VirtualBox.
- Captura de las IP de ambas VM.
- Resultado de una prueba de conectividad entre ellas.

### Alternativa A: una sola computadora física

No confundir una **computadora física** con una **máquina virtual**. Un mismo equipo puede ejecutar las dos VM. Si los recursos son limitados, la forma más sencilla es usar el propio Windows como `PC 1` y crear solamente una VM con Kali para `PC 2`.

```text
Windows anfitrión — PC 1              Kali en VirtualBox — PC 2
Servidor víctima, sensor,             Atacante de laboratorio
modelo y tablero                            |
        |                                  |
        +----- Red solo anfitrión ----------+
```

#### Configuración recomendada

1. Abrir VirtualBox y crear una red **Solo anfitrión**, también llamada *Host-only*.
2. Configurar el adaptador de Kali para usar únicamente esa red.
3. Asignar una IP al adaptador solo anfitrión de Windows, por ejemplo `192.168.56.102/24`.
4. Asignar a Kali la IP `192.168.56.101/24`.
5. Comprobar conectividad desde Kali hacia Windows.
6. Iniciar en Windows un servicio local de prueba, enlazado solamente a la IP de la red solo anfitrión.
7. Capturar en Windows con Wireshark/tshark el tráfico procedente de `192.168.56.101`.
8. Ejecutar las pruebas autorizadas desde Kali.
9. Detener la captura, convertir el PCAP con CICFlowMeter y cargar el CSV en el tablero.
10. Al terminar, apagar Kali o desactivar el adaptador solo anfitrión.

Esta modalidad necesita solamente **una VM** y consume menos recursos que ejecutar Windows y Kali dentro de VirtualBox. El Windows anfitrión cumple las funciones de víctima y sensor.

#### Precauciones

- Enlazar el servicio de prueba únicamente a la IP de la red solo anfitrión.
- No exponer ese servicio a la red Wi-Fi o Ethernet de la universidad.
- Comprobar que Kali no tenga un segundo adaptador con acceso a Internet.
- Usar el firewall de Windows para permitir el servicio solo desde la red del laboratorio.

### Alternativa B: solamente una VM, sin segundo sistema operativo

Si únicamente pueden usar una VM y no pueden crear otra, se pueden simular los dos roles dentro del mismo sistema:

1. Entrenar y evaluar el modelo normalmente con CIC-IDS2017.
2. Instalar un servicio de prueba local dentro de la VM.
3. Usar un cliente local para generar tráfico normal.
4. Usar herramientas de prueba contra `127.0.0.1` o contra la IP local para generar un escaneo pequeño o intentos de inicio de sesión fallidos.
5. Capturar el tráfico de loopback con Wireshark, tshark o tcpdump, según el sistema operativo.
6. Convertir la captura con CICFlowMeter.
7. Analizar el CSV con el modelo y mostrar las alertas en Streamlit.

En esta alternativa, el servidor, el cliente, el sensor y el atacante están en la misma VM. Es una simulación menos realista porque muchas conexiones usarán la misma IP, pero permite completar el flujo técnico sin un segundo equipo.

Si la captura de loopback resulta complicada, se puede utilizar como respaldo una demostración con los CSV oficiales de CIC-IDS2017. En ese caso hay que indicar claramente en el informe que la detección se demostró con datos del dataset y que la arquitectura de dos equipos quedó como simulación o trabajo futuro.

---

## 3. Planificar el dataset y las etiquetas

### Dataset recomendado

Usar **CIC-IDS2017**, porque:

- Contiene tráfico benigno y ataques.
- Incluye archivos PCAP.
- Incluye CSV con características de flujos.
- Fue construido para evaluar sistemas de detección de intrusiones.

Página oficial:

- https://www.unb.ca/cic/datasets/ids-2017.html
- Enlace de descarga publicado en esa página: http://cicresearch.ca/CICDataset/CIC-IDS-2017/

### Qué descargar

Para comenzar, descargar `MachineLearningCSV.zip`. Los archivos PCAP completos ocupan varios GB; no hace falta descargar todo el dataset para una primera versión.

Una selección mínima razonable es:

| Día | Contenido | Para qué sirve |
|---|---|---|
| Monday | Actividad normal | Aprender conexiones benignas |
| Tuesday | Fuerza bruta FTP/SSH y tráfico normal | Entrenar y evaluar fuerza bruta |
| Wednesday | DoS, Heartbleed y tráfico normal | Ampliar los ataques conocidos |
| Friday — opcional | PortScan y DDoS | Incorporar escaneos de puertos |

Para la demostración mínima, pueden empezar con **Monday y Tuesday** y añadir **Wednesday**. Si quieren evaluar específicamente la clase `PortScan`, incorporar Friday.

### Definir la etiqueta

La columna `Label` identifica el tipo de tráfico. Para el trabajo solicitado, convertirla en dos clases:

```text
BENIGN      -> 0
Cualquier ataque -> 1
```

Conservar también la etiqueta original en una columna llamada `Tipo_Ataque`. Eso permitirá saber, por ejemplo, si una alerta correspondió a `FTP-Patator`, `SSH-Patator`, `DoS` o `PortScan`.

### Pasos

1. Descargar el archivo desde la página oficial.
2. Verificar que la descarga haya terminado y que el ZIP se pueda abrir.
3. Extraerlo en una carpeta del proyecto.
4. Abrir los CSV seleccionados con Python, Excel o LibreOffice.
5. Revisar la columna `Label` y las columnas de características.
6. Registrar en una tabla cuántos flujos hay por clase y por tipo de ataque.
7. Guardar una copia de los datos originales sin modificar.

> Los CSV de CIC pueden traer espacios al inicio o al final de nombres y valores. Es recomendable limpiar esos espacios antes de entrenar.

---

## 4. Organizar el proyecto

Crear esta estructura dentro de `trabajo_final`:

```text
trabajo_final/
├── datos/
│   ├── originales/
│   └── procesados/
├── capturas/
├── modelos/
├── src/
│   ├── preprocesar.py
│   ├── entrenar.py
│   ├── evaluar.py
│   └── app.py
├── requirements.txt
├── README.md
└── informe/
    ├── metricas.csv
    ├── matriz_confusion.png
    ├── curva_pr.png
    └── capturas/
```

No hace falta implementar todo desde el primer momento. Primero dejar funcionando una versión simple y después mejorar la presentación.

---

## 5. Limpiar y preparar los datos

### Pasos

1. Unir los CSV de los días elegidos en una sola tabla.
2. Quitar espacios innecesarios de los nombres de columnas.
3. Limpiar los valores de `Label`.
4. Crear `Tipo_Ataque` y `Clase`.
5. Revisar valores faltantes.
6. Reemplazar valores infinitos por valores faltantes.
7. Convertir las características a formato numérico cuando corresponda.
8. Completar faltantes con la mediana calculada **solo sobre el conjunto de entrenamiento**.
9. Revisar filas duplicadas.
10. Separar los datos en entrenamiento, validación y prueba.

### Evitar errores importantes

- No usar `Label`, `Clase` ni `Tipo_Ataque` como características del modelo.
- No calcular la mediana usando todo el dataset antes de separarlo.
- No ajustar el modelo con el conjunto de prueba.
- No elegir el umbral de alerta usando el conjunto de prueba.
- Evitar que flujos prácticamente idénticos o pertenecientes a una misma sesión aparezcan simultáneamente en entrenamiento y prueba.
- Para una evaluación más sólida, separar por bloques temporales o días y no solo al azar.

### Entregable de esta etapa

Un archivo `datos/procesados/dataset_listo.csv`, o en su lugar un script que lo genere de forma reproducible, acompañado de:

- Número total de flujos.
- Número de flujos benignos.
- Número de flujos maliciosos.
- Distribución por tipo de ataque.
- Lista final de características.

---

## 6. Entrenar un primer modelo

### Enfoque recomendado

Empezar con **Random Forest**, porque:

- Es fácil de implementar.
- Trabaja bien con datos tabulares.
- Captura relaciones no lineales.
- Permite explicar la importancia de las características.
- No exige normalizar todas las variables para funcionar.

También es útil compararlo con un modelo ingenuo, como `DummyClassifier`, para comprobar que el resultado no se debe al desbalance de las clases.

### Pasos

1. Instalar las dependencias en un entorno virtual:

```bash
python -m venv .venv
```

En Windows:

```bat
.venv\Scripts\activate
```

En Linux o macOS:

```bash
source .venv/bin/activate
```

Después:

```bash
pip install pandas numpy scikit-learn joblib streamlit matplotlib
```

2. Cargar `dataset_listo.csv`.
3. Separar `X` de la etiqueta `y`.
4. Realizar la separación entrenamiento/validación/prueba.
5. Entrenar un primer `RandomForestClassifier`.
6. Usar `class_weight` para ayudar con el desbalance de clases.
7. Ajustar algunos parámetros usando validación: número de árboles, profundidad máxima y tamaño mínimo de hoja.
8. Elegir el umbral de probabilidad para declarar una conexión maliciosa.
9. Evaluar el modelo final una sola vez sobre el conjunto de prueba.
10. Guardar el modelo y su configuración.

Ejemplo mínimo de entrenamiento:

```python
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

df = pd.read_csv("datos/procesados/dataset_listo.csv")
df.columns = df.columns.str.strip()
df["Label"] = df["Label"].astype("string").str.strip()
df = df.dropna(subset=["Label"]).copy()
df["Tipo_Ataque"] = df["Label"].str.upper()
df["Clase"] = (df["Tipo_Ataque"] != "BENIGN").astype(int)
df = df.drop_duplicates().reset_index(drop=True)

features = [
    col for col in df.columns
    if col not in ["Label", "Tipo_Ataque", "Clase"]
]

X = df[features].apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], np.nan)
y = df["Clase"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y,
)

medianas = X_train.median()
X_train = X_train.fillna(medianas)
X_test = X_test.fillna(medianas)

modelo = RandomForestClassifier(
    n_estimators=300,
    class_weight="balanced_subsample",
    random_state=42,
    n_jobs=-1,
)

modelo.fit(X_train, y_train)
probabilidades = modelo.predict_proba(X_test)[:, 1]
predicciones = (probabilidades >= 0.5).astype(int)

print(confusion_matrix(y_test, predicciones, labels=[0, 1]))
print(classification_report(
    y_test,
    predicciones,
    labels=[0, 1],
    target_names=["BENIGNO", "MALICIOSO"],
    zero_division=0,
))

Path("modelos").mkdir(exist_ok=True)
joblib.dump(
    {
        "modelo": modelo,
        "features": features,
        "medianas": medianas,
        "umbral": 0.5,
    },
    "modelos/modelo_ids.joblib",
)
```

Este código es una base académica. Antes de la entrega, revisar la separación de datos para evitar fugas y usar un conjunto de validación independiente si se ajustan hiperparámetros o el umbral.

### Archivos generados

- `modelos/modelo_ids.joblib`
- `informe/metricas.csv`
- `informe/matriz_confusion.png`
- `informe/curva_pr.png`
- `informe/importancia_caracteristicas.png` — opcional, pero útil para explicar el modelo

---

## 7. Evaluar el modelo correctamente

No evaluar el trabajo únicamente con `accuracy`, especialmente si hay muchos más flujos benignos que maliciosos.

### Métricas obligatorias

- **Precision:** de las conexiones marcadas como maliciosas, cuántas realmente lo eran.
- **Recall:** de todas las conexiones maliciosas, cuántas logró detectar.
- **F1-score:** equilibrio entre Precision y Recall.
- **Matriz de confusión.**
- **Cantidad de falsos positivos y falsos negativos.**

### Interpretación para la presentación

- Un **falso negativo** es un ataque que el sistema no detecta.
- Un **falso positivo** es tráfico normal que el sistema marca como ataque.
- En un IDS suele ser importante reducir falsos negativos, pero demasiados falsos positivos hacen que las alertas pierdan valor.

### Pasos

1. Ejecutar el modelo sobre el conjunto de prueba.
2. Guardar la matriz de confusión.
3. Calcular Precision, Recall y F1 para la clase maliciosa.
4. Generar la curva Precision-Recall.
5. Revisar ejemplos de errores.
6. Ajustar el umbral usando validación, no prueba.
7. Documentar el umbral final y el motivo de la elección.

---

## 8. Preparar el sensor y extraer características

### Herramientas recomendadas

- `tcpdump` o `tshark`: capturar y seleccionar tráfico.
- **CICFlowMeter:** convertir PCAP en características de flujos compatibles con el dataset CIC.
- Wireshark: inspeccionar visualmente las capturas.

CICFlowMeter:

- https://github.com/ISCX/CICFlowMeter

### Pasos en PC 1

1. Instalar `tcpdump` o `tshark`. Si se usa WSL, verificar que pueda acceder a la interfaz de red de la VM.
2. Instalar la versión de Java requerida por la release de CICFlowMeter.
3. Instalar CICFlowMeter siguiendo las instrucciones de su repositorio oficial.
4. Identificar la interfaz conectada a la red interna.
5. Hacer una captura corta de prueba.
6. Abrirla con Wireshark para comprobar que contiene tráfico de las dos VM.
7. Convertirla con CICFlowMeter.
8. Revisar el CSV generado y comparar sus columnas con las del dataset de entrenamiento.

### Ejemplo de captura con `tshark`

Ejecutar dentro de la VM del sensor:

```bash
tshark -D
```

Elegir la interfaz de la red interna y reemplazar `eth0` si es necesario:

```bash
tshark -i eth0 -f "host 192.168.56.101" -w captura_prueba.pcapng
```

Detener la captura con `Ctrl + C`.

### Ejemplo de conversión a CSV

1. Abrir CICFlowMeter.
2. Seleccionar el PCAP capturado como entrada.
3. Elegir una carpeta de salida.
4. Ejecutar la extracción.
5. Abrir el CSV resultante.
6. Normalizar los nombres de columnas con el mismo criterio usado durante el entrenamiento.
7. Aplicar el mismo orden de características guardado en el modelo.

> No alimentar el modelo con un CSV que tenga columnas distintas sin hacer una correspondencia explícita. Si se entrena con CIC-IDS2017 y después se usan registros de Zeek, Snort u otra herramienta, las características no serán necesariamente equivalentes.

### Entregable de esta etapa

- Una captura PCAP de prueba.
- El CSV de características extraído.
- Una tabla que relacione las características del dataset con las producidas por CICFlowMeter.

---

## 9. Generar tráfico benigno y ataques autorizados

### Reglas de seguridad

- Ejecutar los ataques únicamente contra las VM del laboratorio.
- Usar servicios y cuentas creadas específicamente para la prueba.
- Mantener las VM aisladas de Internet y de la red universitaria.
- No usar equipos, servicios o cuentas de terceros.
- Evitar inundaciones, denegación de servicio, malware, bots o ataques destructivos.
- Detener las pruebas si el equipo anfitrión o la red real se ven afectados.

### Escenario A — tráfico normal

1. En PC 1, iniciar un servicio local de prueba, por ejemplo un servidor web o FTP.
2. Desde PC 2, generar conexiones legítimas a ese servicio.
3. Navegar, descargar un archivo de prueba o iniciar sesión con una cuenta válida.
4. Capturar el tráfico.
5. Etiquetar el escenario como `BENIGNO`.
6. Guardar la hora de inicio y fin.

### Escenario B — escaneo de puertos

1. Ejecutar un escaneo desde Kali contra la IP de PC 1.
2. Limitar el alcance a la VM y a un rango pequeño de puertos.
3. Capturar el tráfico durante la prueba.
4. Etiquetar el escenario como `MALICIOSO`.
5. Guardar la herramienta utilizada, la IP de origen y la hora.

### Escenario C — fuerza bruta controlada

1. Crear un servicio FTP o SSH de prueba en PC 1.
2. Crear una cuenta destinada únicamente al laboratorio.
3. Desde Kali, realizar una cantidad pequeña y limitada de intentos fallidos.
4. Capturar el tráfico.
5. Etiquetar el escenario como `MALICIOSO`.
6. Registrar la hora y el servicio atacado.

### Registro de pruebas

| Prueba | PC origen | PC destino | Servicio/puerto | Inicio | Fin | Etiqueta | Captura |
|---|---|---|---|---|---|---|---|
| Normal | Kali | Windows | HTTP/80 | — | — | BENIGNO | `normal.pcap` |
| Escaneo | Kali | Windows | Varios | — | — | MALICIOSO | `portscan.pcapng` |
| Fuerza bruta | Kali | Windows | FTP/21 o SSH/22 | — | — | MALICIOSO | `fuerza_bruta.pcapng` |

---

## 10. Integrar el modelo con un tablero de alertas

### Función del tablero

Crear `src/app.py` con Streamlit. La primera versión puede funcionar así:

1. Cargar `modelo_ids.joblib`.
2. Cargar un CSV de flujos producido por CICFlowMeter.
3. Aplicar el mismo preprocesamiento del entrenamiento.
4. Calcular la probabilidad de que cada flujo sea malicioso.
5. Aplicar el umbral guardado.
6. Mostrar los resultados en una tabla.
7. Guardar las alertas en un archivo CSV o SQLite.

### Elementos mínimos de la interfaz

- Estado del modelo: cargado/no cargado.
- Nombre del modelo y umbral de alerta.
- Selector del archivo CSV.
- Indicadores: total de flujos, benignos, maliciosos y alertas.
- Tabla de conexiones analizadas.
- Tabla de alertas.
- Gráfico de conexiones benignas frente a maliciosas.
- Filtros por IP, puerto y etiqueta.
- Evidencia de cada alerta: hora, IP de origen, IP de destino, puerto, protocolo y probabilidad.

### Ejemplo de ejecución local

```bash
streamlit run src/app.py --server.address 127.0.0.1
```

Mantener el tablero dentro de la red aislada. No publicarlo en Internet.

### Funcionamiento continuo, opcional

Si quieren que el sistema analice tráfico automáticamente:

1. Capturar en archivos PCAP rotativos.
2. Procesar cada archivo terminado con CICFlowMeter.
3. Leer los CSV nuevos desde el tablero.
4. Evitar volver a procesar archivos ya analizados.
5. Guardar una alerta por evento o por grupo de flujos, para no llenar la pantalla con avisos duplicados.

Esta automatización puede quedar para una segunda etapa. Para la presentación basta con demostrar el flujo completo: captura, extracción, clasificación y alerta.

---

## 11. Probar la demostración completa

### Lista de pruebas

1. El modelo se carga correctamente al iniciar el tablero.
2. Un CSV benigno produce mayoritariamente alertas `BENIGNO`.
3. Un CSV de escaneo produce alertas `MALICIOSO`.
4. Un CSV de fuerza bruta produce alertas `MALICIOSO`.
5. La IP atacante aparece correctamente en la evidencia.
6. El umbral se puede cambiar y afecta los resultados.
7. El historial de alertas se conserva.
8. La aplicación vuelve a funcionar después de reiniciarla.
9. Las VM siguen aisladas durante toda la demostración.

### Guion sugerido para la presentación

1. Explicar el problema y la arquitectura.
2. Mostrar el dataset y la distribución de clases.
3. Explicar el preprocesamiento.
4. Mostrar las métricas y la matriz de confusión.
5. Iniciar una captura.
6. Generar tráfico normal y mostrar el resultado.
7. Detener la captura y convertirla con CICFlowMeter.
8. Cargar el CSV en el tablero y mostrar que se clasifica como benigno.
9. Repetir con el escaneo controlado.
10. Mostrar la alerta, su probabilidad y la evidencia en la captura.
11. Repetir con la prueba de fuerza bruta si hay tiempo.
12. Cerrar con conclusiones, limitaciones y mejoras futuras.

### Limitaciones que conviene mencionar

- El modelo se entrena con datos de 2017 y puede no representar el tráfico actual.
- Una alta precisión sobre CIC-IDS2017 no garantiza el mismo rendimiento en otra red.
- Las características extraídas deben ser compatibles entre entrenamiento y operación.
- Los ataques simulados son una muestra pequeña del dataset.
- El sistema detecta patrones de flujo; no reemplaza un IDS comercial ni un análisis forense completo.
- Los falsos positivos deben revisarse antes de tomar decisiones automáticas.

---

## 12. Preparar la entrega final

### Archivos recomendados

- Código fuente del preprocesamiento, entrenamiento, evaluación y tablero.
- `requirements.txt`.
- `README.md` con instrucciones de instalación y ejecución.
- Modelo entrenado.
- Lista de características y umbral utilizado.
- Capturas PCAP de las demostraciones.
- CSV extraídos de esas capturas.
- Métricas, matriz de confusión y curva Precision-Recall.
- Capturas de pantalla del tablero.
- Informe o presentación con arquitectura, resultados y conclusiones.

### Estructura sugerida del informe o presentación

1. Título y objetivo.
2. Problema: detección de conexiones maliciosas.
3. Dataset CIC-IDS2017.
4. Arquitectura del laboratorio.
5. Preparación de datos.
6. Modelo seleccionado.
7. Resultados y matriz de confusión.
8. Demostración con tráfico propio.
9. Limitaciones.
10. Conclusiones y trabajos futuros.

### Lista de verificación final

- [ ] El problema y el objetivo están definidos.
- [ ] La arquitectura tiene un diagrama claro.
- [ ] Las VM están aisladas.
- [ ] Se utilizó CIC-IDS2017.
- [ ] Las etiquetas están limpias.
- [ ] No hay fuga de datos entre entrenamiento y prueba.
- [ ] Se reportan Precision, Recall, F1 y matriz de confusión.
- [ ] El modelo está guardado y se puede cargar.
- [ ] El sensor captura tráfico de las pruebas.
- [ ] CICFlowMeter genera características compatibles.
- [ ] El tablero muestra alertas y evidencia.
- [ ] La demostración benigna funciona.
- [ ] La demostración maliciosa funciona.
- [ ] Existen capturas de pantalla para la presentación.
- [ ] El README permite reproducir el trabajo.
- [ ] Las pruebas ofensivas se limitaron al laboratorio propio.

---

## 13. Orden de trabajo sugerido

| Día | Actividad | Resultado |
|---|---|---|
| 1 | Definir alcance y montar las VM | Arquitectura y red aislada |
| 2 | Descargar y explorar CIC-IDS2017 | Dataset seleccionado |
| 3 | Limpiar y preparar datos | Dataset listo |
| 4 | Entrenar el primer modelo | Modelo inicial |
| 5 | Evaluar y ajustar | Métricas y modelo final |
| 6 | Configurar sensor y generar pruebas | PCAP y CSV propios |
| 7 | Integrar tablero y ensayar presentación | Demostración funcional |
| 8 | Documentar y preparar entrega | Código, informe y evidencias |

Si el tiempo es limitado, priorizar este camino: **VM aisladas → dataset mínimo → Random Forest → una captura benigna y una maliciosa → CICFlowMeter → tablero básico → métricas y capturas de pantalla**.

## Referencia del dataset

Canadian Institute for Cybersecurity, *Intrusion detection evaluation dataset (CIC-IDS2017)*:

- https://www.unb.ca/cic/datasets/ids-2017.html

CICFlowMeter, herramienta para analizar PCAP y generar características de flujos:

- https://github.com/ISCX/CICFlowMeter

---

## 14. Implementación ya preparada en este proyecto

### Código disponible

| Archivo | Función |
|---|---|
| `src/data.py` | Carga, limpieza, etiquetado binario, duplicados y separación por grupos temporales |
| `src/model.py` | Random Forest, selección de umbral, guardado y predicción |
| `src/train.py` | Entrenamiento completo desde CSV de CIC |
| `src/evaluate.py` | Evaluación de un modelo guardado con otro CSV etiquetado |
| `src/reporting.py` | Métricas, matriz de confusión, curva PR e importancia de características |
| `src/app.py` | Tablero Streamlit con alertas, evidencias e historial |
| `src/generar_demo.py` | Datos sintéticos y modelo de demostración para probar la interfaz |
| `tests/test_pipeline.py` | Pruebas automatizadas del flujo principal |

### Dataset descargado

- ZIP: `datos/originales/MachineLearningCSV.zip`.
- CSV extraídos: `datos/originales/MachineLearningCVE/`.
- Contenido verificado: 8 CSV, 2.830.743 registros y 79 columnas por archivo.
- SHA-256 del ZIP: `c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928`.
- La prueba CRC del ZIP finalizó sin errores.

El portal oficial requiere registro. Por eso, la descarga se obtuvo del espejo identificado como **no oficial** `bencorn/CICIDS2017` en Hugging Face, fijado al commit `811c007f08d693a8a8b4226c197c138391806ce6`. Para la entrega, conviene citar la página oficial de CIC y mencionar el origen del archivo descargado.

### Modelo real entrenado

Se utilizaron Monday, Tuesday, Wednesday y el archivo de PortScan del viernes. Para reducir el consumo de memoria, se conservaron como máximo 30.000 filas por etiqueta original.

```bash
.venv/Scripts/python.exe -m src.train \
  --input "datos/originales/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv" \
  "datos/originales/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv" \
  "datos/originales/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv" \
  "datos/originales/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv" \
  --max-rows-per-label 30000 \
  --dataset-output "datos/procesados/dataset_listo.csv" \
  --model-output "modelos/modelo_ids.joblib" \
  --report-output "informe"
```

El comando anterior es para Git Bash. En una sola línea también funciona en CMD o PowerShell quitando las barras invertidas de continuación.

Resultados del conjunto de prueba, separado por grupos temporales de 5 minutos:

| Métrica | Resultado |
|---|---:|
| Flujos de prueba | 21.629 |
| Características | 78 |
| Umbral seleccionado | 0,5097 |
| F1 maliciosa | 0,9994 |
| Recall malicioso | 0,9994 |
| Precision maliciosa | 0,9995 |
| Falsos positivos | 8 |
| Falsos negativos | 10 |

También se creó `datos/demo/muestra_cic_real.csv` con 240 flujos etiquetados. El modelo acertó 234: no produjo falsos positivos y dejó seis ataques sin detectar. Su evaluación está en `informe/evaluacion_muestra/`.

> Estos resultados son sobre CIC-IDS2017. Un valor tan alto no demuestra que el modelo funcione igual en una red real; puede haber patrones específicos del dataset. La demostración con capturas propias sigue siendo necesaria.

### Ejecutar el tablero

```bash
.venv/Scripts/python.exe -m streamlit run src/app.py --server.address 127.0.0.1 --server.port 8501
```

Abrir `http://127.0.0.1:8501`, seleccionar `modelo_ids.joblib` y cargar un CSV con las mismas características. El modelo sintético `modelo_demo.joblib` se incluye solamente para pruebas de interfaz y no debe presentarse como el modelo final.

El tablero se probó en el navegador con:

- 1.000 flujos sintéticos: 600 benignos y 400 maliciosos.
- 240 flujos reales de CIC: 66 benignos y 174 maliciosos.
- Un CSV incompatible: la aplicación mostró un error de validación y no lo clasificó.

### Ejecutar las pruebas

```bash
.venv/Scripts/python.exe -m pytest -q
```

Estado actual: **7 pruebas aprobadas**.

### Generar nuevamente la demostración sintética

```bash
.venv/Scripts/python.exe -m src.generar_demo
```

### Estado del laboratorio en este equipo

| Componente | Estado |
|---|---|
| VirtualBox | 7.2.22 instalado |
| VM `PC2-Kali` | Registrada, con 4 GB de RAM, 2 CPU e instantánea `Limpia` |
| Red | Solo anfitrión: Windows `192.168.56.102/24`, Kali `192.168.56.101/24` |
| Aislamiento | Kali tiene una sola interfaz, IP estática, sin gateway y sin DNS |
| Firewall | Regla `Laboratorio_IDS_HTTP_8080`: TCP 8080 solo desde `192.168.56.101` |
| Servicio HTTP | `herramientas/servidor_laboratorio.ps1`, enlazado a `192.168.56.102:8080` |
| Wireshark | 4.6.10 instalado |
| Npcap | 1.90 instalado y servicio en ejecución; `tshark -D` enumera las interfaces reales |
| Java | Temurin 8 y 11 instalados |
| CICFlowMeter | 4.0 compilado; lanzador en `herramientas/CICFlowMeter.bat` |
| Captura normal | `capturas/normal.pcap`: 40 paquetes y 5 flujos TCP |
| Captura de escaneo | `capturas/escaneo.pcap`: 18 paquetes; Nmap probó 6 puertos y encontró 8080 abierto |
| CSV normal | `datos/procesados/normal/normal.pcap_Flow.csv`: 10 flujos |
| CSV de escaneo | `datos/procesados/escaneo/escaneo.pcap_Flow.csv`: 5 flujos |
| Compatibilidad | Ambos CSV tienen las 78 características del modelo después del mapeo de nombres |

Hashes SHA-256 de las capturas:

```text
normal.pcap   c14cad3eecb87bb3d855e13d214f0fda4e8e4cc0a23318b565876f17efc672ab
escaneo.pcap  aa3124b4827eefb79135eb4ac62a1e3556effa10abd88267285f35514807b334
```

Las capturas se obtuvieron con `tcpdump` dentro de Kali contra la IP del laboratorio. No se ejecutó ningún escaneo contra redes externas. El bloqueo TCP entrante preexistente de `python.exe` no se desactivó; el servicio de prueba usa PowerShell y el firewall solo permite el puerto 8080 desde Kali.

### Resultados reales con las capturas del laboratorio

Se aplicó `modelos/modelo_ids.joblib`, con umbral `0.5097023376315192`, a los dos CSV generados por CICFlowMeter:

| Caso | Flujos | BENIGNO | MALICIOSO | Probabilidad media |
|---|---:|---:|---:|---:|
| Tráfico normal | 10 | 10 | 0 | 13.55 % |
| Escaneo autorizado | 5 | 2 | 3 | 46.93 % |

En el escaneo se emitieron alertas para los puertos destino 20, 21 y 80, con probabilidades de 0.6099, 0.5999 y 0.5705. Los flujos hacia 8080 y 443 quedaron por debajo del umbral. Por tanto, la prueba real demuestra detección útil, pero no una cobertura del 100 % de todos los flujos del escaneo.

Evidencia guardada:

- `informe/laboratorio/normal_predicciones.csv`: 10 predicciones reales.
- `informe/laboratorio/escaneo_predicciones.csv`: 5 predicciones reales.
- `informe/laboratorio/resumen_laboratorio.json`: resumen, umbral y probabilidades.
- `informe/capturas/tablero_normal.png`: tablero con 10 conexiones benignas.
- `informe/capturas/tablero_escaneo.png`: tablero con 5 conexiones y 3 alertas.
- `informe/alertas.csv`: historial real de las 3 alertas del escaneo, con IP y puertos.

CICFlowMeter utiliza algunos nombres distintos a CIC-IDS2017. El archivo `src/data.py` traduce 20 nombres y duplica `Fwd Header Length` como `Fwd Header Length.1`, de modo que no sea necesario imputar esas características. La prueba `test_cicflowmeter_headers_match_cic_dataset` comprueba el mapeo.

### Trabajo pendiente fuera de este código

1. Preparar el informe o la presentación con las métricas del modelo, la red aislada, los PCAP, las predicciones y las capturas del tablero.
2. Opcional: agregar una prueba pequeña de FTP o SSH solamente si el docente la exige.

---

## 15. Guion rápido para una sola computadora

### Paso 1 — Herramientas

En este equipo ya están instalados VirtualBox 7.2.22, Wireshark 4.6.10, Java 8 y Java 11. CICFlowMeter 4.0 está compilado y se abre con:

```bat
herramientas\CICFlowMeter.bat
```

Sin argumentos abre la interfaz gráfica. Para convertir un PCAP desde CMD:

```bat
herramientas\CICFlowMeter.bat "capturas\normal.pcap" "datos\procesados\normal"
```

Npcap 1.90 ya está instalado y el servicio `npcap` está en ejecución. Para comprobarlo:

```bat
sc query npcap
"C:\Program Files\Wireshark\tshark.exe" -D
```

### Paso 2 — Verificar la red aislada

La VM `PC2-Kali` ya está configurada con el adaptador **VirtualBox Host-Only Ethernet Adapter**. Windows usa `192.168.56.102/24` y Kali usa `192.168.56.101/24`.

Para reproducir la configuración en otro equipo:

1. Abrir VirtualBox.
2. Ir a **Archivo > Host Network Manager** o **File > Host Network Manager**.
3. Crear una red **Solo anfitrión / Host-only**.
4. Configurar su adaptador de Windows con IP `192.168.56.102` y máscara `255.255.255.0`.
5. En la VM Kali, abrir **Configuración > Red**.
6. Activar solamente el **Adaptador 1** y seleccionar la red **Solo anfitrión** creada.
7. Desactivar los adaptadores adicionales para que Kali no tenga salida a Internet.

### Paso 3 — Comprobar la IP de Kali

La conexión de Kali ya quedó en manual con `192.168.56.101/24`, sin puerta de enlace ni DNS. Para verificarla dentro de Kali:

```bash
ip -4 addr show eth0
ip route
nmcli -f IP4.GATEWAY,IP4.DNS device show eth0
```

Solo debe aparecer la ruta `192.168.56.0/24`; no debe haber una ruta predeterminada. Si Windows bloquea el ping, utilizar la prueba HTTP del siguiente paso.

### Paso 4 — Levantar un servicio de prueba en Windows

Abrir CMD o Git Bash dentro de `trabajo_final` y ejecutar:

```bat
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File herramientas\servidor_laboratorio.ps1
```

Dejar esa ventana abierta. La regla `Laboratorio_IDS_HTTP_8080` ya permite TCP 8080 solamente desde `192.168.56.101`.

Desde Kali:

```bash
curl --noproxy "*" http://192.168.56.102:8080
```

Debe aparecer `Laboratorio IDS activo`. No utilizar el servidor HTTP de Python en este equipo: existe una regla preexistente que bloquea Python entrante y no debe desactivarse para la demostración.

### Paso 5 — Capturar tráfico normal

1. Abrir Wireshark en Windows.
2. Seleccionar el adaptador **Host-only** de VirtualBox, no el Wi-Fi.
3. Aplicar el filtro de captura:

```text
host 192.168.56.101
```

4. Iniciar la captura.
5. Desde Kali ejecutar varias veces:

```bash
curl http://192.168.56.102:8080
```

6. Detener la captura y guardarla como `capturas/normal.pcap`.

### Paso 6 — Capturar un escaneo autorizado

1. Iniciar una nueva captura en Wireshark con el mismo filtro.
2. Desde Kali ejecutar:

```bash
nmap -sT -p 20,21,22,80,443,8080 192.168.56.102
```

3. Detener la captura y guardarla como `capturas/escaneo.pcap`.

Este escaneo debe ejecutarse solamente contra la IP `192.168.56.102` del laboratorio.

### Paso 7 — Convertir cada PCAP a CSV

Con Npcap instalado, crear las carpetas de salida y ejecutar:

```bat
mkdir datos\procesados\normal datos\procesados\escaneo
herramientas\CICFlowMeter.bat "capturas\normal.pcap" "datos\procesados\normal"
herramientas\CICFlowMeter.bat "capturas\escaneo.pcap" "datos\procesados\escaneo"
```

También se puede abrir `herramientas\CICFlowMeter.bat` sin argumentos, seleccionar el PCAP y elegir la carpeta de salida.

En este equipo ya se generaron:

- `datos\procesados\normal\normal.pcap_Flow.csv`: 10 flujos.
- `datos\procesados\escaneo\escaneo.pcap_Flow.csv`: 5 flujos.

Ambos tienen 84 columnas brutas; después del mapeo de `src/data.py`, contienen las 78 características que espera el modelo. El tablero aplica ese mapeo automáticamente.

### Paso 8 — Analizar en el tablero

Si el tablero no está abierto, ejecutar en Windows:

```bash
.venv/Scripts/python.exe -m streamlit run src/app.py --server.address 127.0.0.1 --server.port 8501
```

1. Abrir `http://127.0.0.1:8501`.
2. Seleccionar `modelo_ids.joblib`.
3. Cargar `datos\procesados\normal\normal.pcap_Flow.csv` y pulsar **Procesar conexiones**.
4. Guardar una captura de pantalla del resumen.
5. Repetir con `datos\procesados\escaneo\escaneo.pcap_Flow.csv`.
6. Guardar una captura de pantalla de las alertas.
7. Comparar las IP y los puertos de las alertas con `escaneo.pcap` en Wireshark. CICFlowMeter utiliza `Src IP`, `Dst IP` y `Src Port`; el tablero reconoce esos nombres.

### Paso 9 — Cerrar la demostración

1. Detener el servidor HTTP de prueba.
2. Cerrar Wireshark.
3. Apagar Kali.
4. Desactivar el adaptador solo anfitrión si no se utilizará nuevamente.
5. Guardar los dos PCAP, los dos CSV, las capturas del tablero y las métricas.

La prueba de fuerza bruta es opcional para una primera entrega. Si el docente la exige, crear un servicio FTP o SSH de prueba en Windows y ejecutar una cantidad pequeña de intentos fallidos desde Kali, siempre dentro de la red aislada.
