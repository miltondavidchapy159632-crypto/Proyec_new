# Datos del proyecto

## Archivos incluidos

| Carpeta o archivo | Contenido |
|---|---|
| `demo/demo_flujos.csv` | 1.000 flujos sintéticos para probar la interfaz |
| `demo/muestra_cic_real.csv` | Muestra pequeña de CIC-IDS2017 |
| `procesados/normal/normal.pcap_Flow.csv` | 10 flujos reales de tráfico normal |
| `procesados/escaneo/escaneo.pcap_Flow.csv` | 5 flujos reales de un escaneo autorizado |

Los CSV sintéticos no son evidencia del rendimiento real. Las predicciones de los dos CSV del laboratorio están en `informe/laboratorio/`.

## Dataset original no incluido

`datos/originales/` está excluido de Git porque el ZIP y los CSV extraídos ocupan más de 1 GB. Para reentrenar:

1. Descargar `MachineLearningCSV.zip` desde la página oficial de CIC-IDS2017:
   - https://www.unb.ca/cic/datasets/ids-2017.html
   - http://cicresearch.ca/CICDataset/CIC-IDS-2017/
2. Verificar el SHA-256 del ZIP usado en este proyecto:

   ```text
   c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928
   ```

3. Extraerlo en `datos/originales/MachineLearningCVE/`.
4. Ejecutar el comando de entrenamiento del README principal.

El ZIP contiene 8 CSV con 2.830.743 registros en total. El modelo incluido se entrenó con Monday, Tuesday, Wednesday y el archivo de PortScan del viernes, conservando como máximo 30.000 filas por etiqueta original.

## Etiquetas

- `BENIGN` se convierte en clase `0`.
- Cualquier ataque se convierte en clase `1`.
- `Tipo_Ataque` conserva el nombre original del ataque para el análisis.

## Compatibilidad de CICFlowMeter

CICFlowMeter y CIC-IDS2017 usan algunos nombres distintos. `src/data.py` aplica el mapeo automáticamente y completa `Fwd Header Length.1`. Los dos CSV reales incluidos terminan con las 78 características que espera el modelo, sin valores faltantes imputados por schemas distintos.
