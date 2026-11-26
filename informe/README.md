# Informe y evidencias

## Evaluación del modelo

| Archivo | Contenido |
|---|---|
| `metricas.json` | Métricas completas, umbral y matriz de confusión |
| `metricas.csv` | Precisión, recall y F1 por clase |
| `matriz_confusion.png` | Matriz de confusión del conjunto de prueba |
| `curva_pr.png` | Curva precisión-recall |
| `importancia_caracteristicas.csv` | Importancia de las 78 características |
| `importancia_caracteristicas.png` | Gráfico de importancia de características |

Estos resultados corresponden a CIC-IDS2017 y no deben confundirse con la demostración de red propia.

## Evidencia real del laboratorio

| Archivo | Contenido |
|---|---|
| `laboratorio/resumen_laboratorio.json` | Resumen del análisis de los dos CSV reales |
| `laboratorio/normal_predicciones.csv` | 10 predicciones del tráfico normal |
| `laboratorio/escaneo_predicciones.csv` | 5 predicciones del escaneo |
| `alertas.csv` | Las 3 alertas reales del escaneo, con IPs y puertos |
| `capturas/tablero_normal.png` | Tablero con 10 flujos benignos |
| `capturas/tablero_escaneo.png` | Tablero con 5 flujos y 3 alertas |

Los PCAP de origen están en `capturas/` y los CSV convertidos están en `datos/procesados/`.

## Resultado de la demostración

- Tráfico normal: 10 benignos y 0 maliciosos.
- Escaneo: 2 benignos y 3 maliciosos.
- Alertas del escaneo: puertos destino 20, 21 y 80.
- Los flujos hacia 8080 y 443 no superaron el umbral.

El conjunto es pequeño y sirve para demostrar el flujo completo, no para afirmar una cobertura universal.

## Datos sintéticos

`datos/demo/demo_flujos.csv` y `modelos/modelo_demo.joblib` son sintéticos y existen solo para probar la interfaz. No se deben presentar como tráfico capturado ni como evaluación final.
