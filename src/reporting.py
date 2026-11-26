from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)


def compute_metrics(
    target: pd.Series,
    probabilities: np.ndarray,
    threshold: float,
) -> dict:
    predictions = (probabilities >= threshold).astype(int)
    report = classification_report(
        target,
        predictions,
        labels=[0, 1],
        target_names=["BENIGNO", "MALICIOSO"],
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(target, predictions, labels=[0, 1])
    has_both_classes = len(np.unique(target)) == 2
    return {
        "umbral": float(threshold),
        "accuracy": float(accuracy_score(target, predictions)),
        "precision_maliciosa": float(
            precision_score(target, predictions, zero_division=0)
        ),
        "recall_malicioso": float(
            recall_score(target, predictions, zero_division=0)
        ),
        "f1_maliciosa": float(report["MALICIOSO"]["f1-score"]),
        "roc_auc": float(roc_auc_score(target, probabilities))
        if has_both_classes
        else None,
        "pr_auc": float(average_precision_score(target, probabilities))
        if has_both_classes
        else None,
        "matriz_confusion": matrix.tolist(),
        "verdaderos_negativos": int(matrix[0, 0]),
        "falsos_positivos": int(matrix[0, 1]),
        "falsos_negativos": int(matrix[1, 0]),
        "verdaderos_positivos": int(matrix[1, 1]),
        "reporte_clases": report,
    }


def save_reports(
    metrics: dict,
    target: pd.Series,
    probabilities: np.ndarray,
    feature_importance: pd.DataFrame | None,
    output_dir: str | Path,
) -> None:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "metricas.json").open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, ensure_ascii=False, indent=2)

    report_rows = []
    for label, values in metrics["reporte_clases"].items():
        if isinstance(values, dict):
            report_rows.append({"clase": label, **values})
    pd.DataFrame(report_rows).to_csv(directory / "metricas.csv", index=False)

    matrix = np.array(metrics["matriz_confusion"])
    figure, axis = plt.subplots(figsize=(6, 5))
    image = axis.imshow(matrix, cmap="Blues")
    axis.set_xticks([0, 1], ["BENIGNO", "MALICIOSO"])
    axis.set_yticks([0, 1], ["BENIGNO", "MALICIOSO"])
    axis.set_xlabel("Predicción")
    axis.set_ylabel("Valor real")
    axis.set_title("Matriz de confusión")
    for row in range(2):
        for column in range(2):
            axis.text(
                column,
                row,
                str(matrix[row, column]),
                ha="center",
                va="center",
                color="white" if matrix[row, column] > matrix.max() / 2 else "black",
            )
    figure.colorbar(image, ax=axis)
    figure.tight_layout()
    figure.savefig(directory / "matriz_confusion.png", dpi=160)
    plt.close(figure)

    precision, recall, _ = precision_recall_curve(target, probabilities)
    figure, axis = plt.subplots(figsize=(7, 5))
    axis.plot(recall, precision, color="#2563eb", linewidth=2)
    axis.set_xlabel("Recall")
    axis.set_ylabel("Precision")
    axis.set_title("Curva Precision-Recall")
    axis.grid(alpha=0.25)
    figure.tight_layout()
    figure.savefig(directory / "curva_pr.png", dpi=160)
    plt.close(figure)

    if feature_importance is not None and not feature_importance.empty:
        top = feature_importance.head(20).sort_values("importancia")
        figure, axis = plt.subplots(figsize=(9, 7))
        axis.barh(top["caracteristica"], top["importancia"], color="#0f766e")
        axis.set_title("Características más importantes")
        axis.set_xlabel("Importancia")
        figure.tight_layout()
        figure.savefig(directory / "importancia_caracteristicas.png", dpi=160)
        plt.close(figure)
        feature_importance.to_csv(
            directory / "importancia_caracteristicas.csv", index=False
        )
