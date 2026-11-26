from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from .data import load_cic_dataset, prepare_features
from .model import load_bundle, predict_frame
from .reporting import compute_metrics, save_reports


def evaluate(
    model_path: str | Path,
    csv_path: str | Path,
    report_output: str | Path,
    threshold: float | None = None,
) -> dict:
    bundle = load_bundle(model_path)
    data = load_cic_dataset(csv_path)
    prepared = prepare_features(data)
    frame = prepared.features.copy()
    for column in prepared.metadata.columns:
        frame[column] = prepared.metadata[column]
    results = predict_frame(bundle, frame, threshold=threshold)
    active_threshold = float(bundle["threshold"] if threshold is None else threshold)
    metrics = compute_metrics(
        prepared.target,
        results["Probabilidad_Maliciosa"].to_numpy(),
        active_threshold,
    )
    classifier = bundle["pipeline"].named_steps["classifier"]
    importance = pd.DataFrame(
        {
            "caracteristica": bundle["feature_names"],
            "importancia": classifier.feature_importances_,
        }
    ).sort_values("importancia", ascending=False)
    save_reports(
        metrics,
        prepared.target,
        results["Probabilidad_Maliciosa"].to_numpy(),
        importance,
        report_output,
    )
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluar un detector entrenado")
    parser.add_argument("--model", required=True, help="Archivo joblib del modelo")
    parser.add_argument("--csv", required=True, help="CSV etiquetado para evaluar")
    parser.add_argument("--report-output", default="informe/evaluacion")
    parser.add_argument("--threshold", type=float, default=None)
    args = parser.parse_args()

    metrics = evaluate(args.model, args.csv, args.report_output, args.threshold)
    print(f"F1 maliciosa: {metrics['f1_maliciosa']:.4f}")
    print(f"Recall malicioso: {metrics['recall_malicioso']:.4f}")
    print(f"Falsos positivos: {metrics['falsos_positivos']}")
    print(f"Falsos negativos: {metrics['falsos_negativos']}")


if __name__ == "__main__":
    main()
