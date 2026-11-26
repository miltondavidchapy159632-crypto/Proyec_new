from __future__ import annotations

import io
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.model import load_bundle, predict_frame

MODEL_DIR = ROOT / "modelos"
DEMO_CSV = ROOT / "datos" / "demo" / "demo_flujos.csv"
ALERT_CSV = ROOT / "informe" / "alertas.csv"

st.set_page_config(
    page_title="Detector de conexiones",
    page_icon="",
    layout="wide",
)


@st.cache_resource(show_spinner=False)
def load_model_cached(path: str, modified_time: float) -> dict:
    del modified_time
    return load_bundle(path)


def read_uploaded_csv(uploaded_file) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(uploaded_file.getvalue()), low_memory=False)


def display_key_columns(results: pd.DataFrame) -> list[str]:
    preferred = [
        "ID_Alerta",
        "Deteccion",
        "Nivel_Alerta",
        "Probabilidad_Maliciosa",
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Src IP",
        "Dst IP",
        "Source Port",
        "Src Port",
        "Destination Port",
        "Protocol",
        "Tipo_Ataque",
    ]
    return [column for column in preferred if column in results.columns]


def append_history(new_results: pd.DataFrame) -> pd.DataFrame:
    alerts = new_results[new_results["Deteccion"] == "MALICIOSO"].copy()
    if alerts.empty:
        return st.session_state.get("history", pd.DataFrame())
    alerts["Fecha_Procesamiento"] = datetime.now(timezone.utc).isoformat()
    previous = st.session_state.get("history", pd.DataFrame())
    combined = pd.concat([previous, alerts], ignore_index=True)
    return combined.tail(5_000)


st.title("Detector de conexiones de red")
st.caption(
    "Clasificación de flujos con Machine Learning y evidencia para revisión manual"
)

model_files = sorted(MODEL_DIR.glob("*.joblib"))
if not model_files:
    st.warning(
        "No hay modelos entrenados. Ejecuta primero el entrenamiento o genera el modelo de demostración."
    )
    st.code(
        "python -m src.generar_demo\n"
        "python -m src.train --input datos/originales --model-output modelos/modelo_ids.joblib",
        language="bash",
    )
    st.stop()

with st.sidebar:
    st.header("Configuración")
    default_model = MODEL_DIR / "modelo_ids.joblib"
    default_index = model_files.index(default_model) if default_model in model_files else 0
    selected_model = st.selectbox(
        "Modelo",
        model_files,
        index=default_index,
        format_func=lambda path: path.name,
    )
    modified_time = selected_model.stat().st_mtime
    bundle = load_model_cached(str(selected_model), modified_time)
    threshold = st.slider(
        "Umbral de alerta",
        min_value=0.01,
        max_value=0.99,
        value=float(bundle["threshold"]),
        step=0.01,
        key=f"threshold_{selected_model.name}",
    )
    st.write(f"Umbral guardado: `{bundle['threshold']:.2f}`")
    st.write(f"Características: `{len(bundle['feature_names'])}`")
    if bundle.get("demo"):
        st.warning("Modelo sintético: sirve solo para probar la interfaz.")

    with st.form("csv_form"):
        uploaded_file = st.file_uploader(
            "CSV de flujos", type=["csv"], accept_multiple_files=False
        )
        use_demo = st.checkbox(
            "Usar CSV de demostración",
            value=False,
            disabled=not DEMO_CSV.exists(),
        )
        save_history = st.checkbox("Guardar alertas en informe/alertas.csv", value=True)
        submitted = st.form_submit_button("Procesar conexiones", type="primary")

if submitted:
    if uploaded_file is None and not use_demo:
        st.error("Selecciona un archivo CSV o activa el CSV de demostración.")
    else:
        try:
            frame = (
                read_uploaded_csv(uploaded_file)
                if uploaded_file is not None
                else pd.read_csv(DEMO_CSV, low_memory=False)
            )
            if frame.empty:
                raise ValueError("El CSV no contiene filas.")
            results = predict_frame(bundle, frame, threshold=threshold)
            st.session_state["results"] = results
            st.session_state["history"] = append_history(results)
            st.session_state["source_name"] = (
                uploaded_file.name if uploaded_file is not None else DEMO_CSV.name
            )
            if save_history:
                history = st.session_state["history"]
                if not history.empty:
                    ALERT_CSV.parent.mkdir(parents=True, exist_ok=True)
                    history.to_csv(ALERT_CSV, index=False)
            st.success(f"Se analizaron {len(results):,} conexiones.")
        except Exception as error:
            st.error(f"No se pudo procesar el archivo: {error}")

results = st.session_state.get("results")
if results is None:
    st.info(
        "Carga un CSV producido por CICFlowMeter o utiliza el archivo de demostración para comenzar."
    )
    with st.expander("Cómo obtener el CSV"):
        st.markdown(
            "1. Captura el tráfico de la prueba en un PCAP.\n"
            "2. Convierte el PCAP con CICFlowMeter.\n"
            "3. Carga aquí el CSV generado.\n"
            "4. Revisa las alertas y compara las IP y puertos con la captura."
        )
    st.stop()

malicious_count = int((results["Deteccion"] == "MALICIOSO").sum())
benign_count = len(results) - malicious_count
missing_features = int(results["Caracteristicas_Faltantes"].max())
if missing_features:
    st.warning(
        f"El archivo no incluye {missing_features} características del modelo. "
        "Los valores faltantes se imputaron; revisa la compatibilidad antes de concluir."
    )

st.subheader("Resumen del análisis")
first = st.columns(4)
first[0].metric("Conexiones", f"{len(results):,}")
first[1].metric("Benignas", f"{benign_count:,}")
first[2].metric("Maliciosas", f"{malicious_count:,}")
first[3].metric(
    "Probabilidad media",
    f"{results['Probabilidad_Maliciosa'].mean():.1%}",
)

second = st.columns(2)
with second[0]:
    st.caption("Distribución de detecciones")
    st.bar_chart(
        pd.Series(
            {"BENIGNO": benign_count, "MALICIOSO": malicious_count},
            name="Conexiones",
        )
    )
with second[1]:
    st.caption("Rendimiento del modelo en su conjunto de prueba")
    metrics = bundle.get("metrics", {})
    if metrics:
        st.dataframe(
            pd.DataFrame(
                {
                    "Métrica": ["F1 maliciosa", "Recall", "Precision", "ROC AUC"],
                    "Valor": [
                        metrics.get("f1_maliciosa"),
                        metrics.get("recall_malicioso"),
                        metrics.get("precision_maliciosa"),
                        metrics.get("roc_auc"),
                    ],
                }
            ),
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("El modelo no tiene métricas de evaluación guardadas.")

st.subheader("Alertas")
alerts = results[results["Deteccion"] == "MALICIOSO"]
if alerts.empty:
    st.success("No se superó el umbral de alerta en este archivo.")
else:
    st.dataframe(
        alerts[display_key_columns(results)],
        hide_index=True,
        use_container_width=True,
    )
    if "Source IP" in alerts.columns:
        st.caption("Orígenes con más alertas")
        st.bar_chart(alerts["Source IP"].astype(str).value_counts().head(10))

st.subheader("Todas las conexiones")
st.dataframe(
    results[display_key_columns(results)],
    hide_index=True,
    use_container_width=True,
)

history = st.session_state.get("history", pd.DataFrame())
if not history.empty:
    st.subheader("Historial de alertas")
    st.caption(f"{len(history):,} alertas conservadas en esta sesión")
    st.download_button(
        "Descargar historial de alertas",
        data=history.to_csv(index=False).encode("utf-8"),
        file_name="alertas.csv",
        mime="text/csv",
    )

st.download_button(
    "Descargar resultados completos",
    data=results.to_csv(index=False).encode("utf-8"),
    file_name="resultados_deteccion.csv",
    mime="text/csv",
)

with st.expander("Información del modelo"):
    st.json(
        {
            "modelo": selected_model.name,
            "entrenado": bundle.get("trained_at"),
            "separacion": bundle.get("split_method"),
            "dataset": bundle.get("dataset_info", {}),
            "fuente_analizada": st.session_state.get("source_name", ""),
        }
    )
