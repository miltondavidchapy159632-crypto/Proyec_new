from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from .data import (
    create_flow_groups,
    load_cic_dataset,
    prepare_features,
    sample_per_label,
    save_prepared_dataset,
    split_grouped,
)
from .model import build_pipeline, save_bundle, tune_threshold
from .reporting import compute_metrics, save_reports


def train(
    input_path: str | Path | list[str | Path],
    dataset_output: str | Path,
    model_output: str | Path,
    report_output: str | Path,
    random_state: int = 42,
    max_rows_per_label: int | None = None,
) -> dict:
    data = load_cic_dataset(input_path)
    original_rows = len(data)
    data = sample_per_label(data, max_rows_per_label, random_state)
    prepared = prepare_features(data)
    if prepared.target.nunique() < 2:
        raise ValueError("El dataset necesita al menos una clase benigna y una maliciosa")
    if len(prepared.features) < 30:
        raise ValueError("El dataset es demasiado pequeño; se requieren al menos 30 flujos")

    save_prepared_dataset(prepared, dataset_output)
    groups = create_flow_groups(prepared.metadata)
    train_indices, validation_indices, test_indices, split_method = split_grouped(
        prepared.features, prepared.target, groups, random_state
    )

    x_train = prepared.features.iloc[train_indices]
    y_train = prepared.target.iloc[train_indices]
    x_validation = prepared.features.iloc[validation_indices]
    y_validation = prepared.target.iloc[validation_indices]
    x_test = prepared.features.iloc[test_indices]
    y_test = prepared.target.iloc[test_indices]

    if y_train.nunique() < 2 or y_test.nunique() < 2:
        raise ValueError(
            "La separación no conserva ambas clases en entrenamiento y prueba. "
            "Revisa el dataset o utiliza una separación estratificada."
        )

    pipeline = build_pipeline(random_state)
    pipeline.fit(x_train, y_train)
    validation_probabilities = pipeline.predict_proba(x_validation)[:, 1]
    threshold = tune_threshold(y_validation, validation_probabilities)
    test_probabilities = pipeline.predict_proba(x_test)[:, 1]
    metrics = compute_metrics(y_test, test_probabilities, threshold)

    classifier = pipeline.named_steps["classifier"]
    importance = pd.DataFrame(
        {
            "caracteristica": prepared.feature_names,
            "importancia": classifier.feature_importances_,
        }
    ).sort_values("importancia", ascending=False)
    save_reports(metrics, y_test, test_probabilities, importance, report_output)

    class_counts = prepared.target.value_counts().sort_index().to_dict()
    attack_counts = prepared.attack_types.value_counts().to_dict()
    bundle = {
        "pipeline": pipeline,
        "feature_names": prepared.feature_names,
        "threshold": threshold,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_state": random_state,
        "split_method": split_method,
        "dataset_info": {
            "filas_originales": original_rows,
            "filas_utilizadas": len(prepared.features),
            "filas_tras_muestreo": len(data),
            "max_rows_por_etiqueta": max_rows_per_label,
            "clases": {str(key): int(value) for key, value in class_counts.items()},
            "ataques": {str(key): int(value) for key, value in attack_counts.items()},
            "columnas_eliminadas": prepared.dropped_columns,
            "entrenamiento": len(train_indices),
            "validacion": len(validation_indices),
            "prueba": len(test_indices),
        },
        "metrics": metrics,
        "demo": False,
    }
    save_bundle(bundle, model_output)
    return bundle


def main() -> None:
    parser = argparse.ArgumentParser(description="Entrenar el detector de conexiones")
    parser.add_argument(
        "--input", required=True, nargs="+", help="Carpetas o archivos CSV de CIC"
    )
    parser.add_argument(
        "--dataset-output",
        default="datos/procesados/dataset_listo.csv",
        help="CSV procesado de salida",
    )
    parser.add_argument(
        "--model-output",
        default="modelos/modelo_ids.joblib",
        help="Modelo de salida",
    )
    parser.add_argument(
        "--report-output", default="informe", help="Carpeta de métricas y gráficos"
    )
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument(
        "--max-rows-per-label",
        type=int,
        default=None,
        help="Límite opcional por etiqueta original para reducir el entrenamiento",
    )
    args = parser.parse_args()

    bundle = train(
        input_path=args.input,
        dataset_output=args.dataset_output,
        model_output=args.model_output,
        report_output=args.report_output,
        random_state=args.random_state,
        max_rows_per_label=args.max_rows_per_label,
    )
    print(f"Modelo guardado en: {args.model_output}")
    print(f"Umbral seleccionado: {bundle['threshold']:.4f}")
    print(f"F1 maliciosa: {bundle['metrics']['f1_maliciosa']:.4f}")
    print(f"Recall malicioso: {bundle['metrics']['recall_malicioso']:.4f}")
    print(f"Separación: {bundle['split_method']}")


if __name__ == "__main__":
    main()
