from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import precision_recall_curve
from sklearn.pipeline import Pipeline

from .data import normalize_columns


def build_pipeline(random_state: int = 42) -> Pipeline:
    return Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(strategy="median", keep_empty_features=True),
            ),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=300,
                    class_weight="balanced_subsample",
                    random_state=random_state,
                    n_jobs=-1,
                    min_samples_leaf=2,
                ),
            ),
        ]
    )


def tune_threshold(target: pd.Series, probabilities: np.ndarray) -> float:
    precision, recall, thresholds = precision_recall_curve(target, probabilities)
    if len(thresholds) == 0:
        return 0.5
    denominator = precision[:-1] + recall[:-1]
    f1_scores = np.divide(
        2 * precision[:-1] * recall[:-1],
        denominator,
        out=np.zeros_like(denominator),
        where=denominator > 0,
    )
    best_index = int(np.argmax(f1_scores))
    return float(np.clip(thresholds[best_index], 0.01, 0.99))


def save_bundle(bundle: dict, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path, compress=3)


def load_bundle(model_path: str | Path) -> dict:
    bundle = joblib.load(Path(model_path))
    required = {"pipeline", "feature_names", "threshold"}
    missing = required.difference(bundle)
    if missing:
        raise ValueError(f"El modelo no contiene las claves necesarias: {sorted(missing)}")
    return bundle


def predict_frame(
    bundle: dict,
    frame: pd.DataFrame,
    threshold: float | None = None,
) -> pd.DataFrame:
    data = normalize_columns(frame)
    feature_names = list(bundle["feature_names"])
    missing_features = [name for name in feature_names if name not in data.columns]
    if len(missing_features) > max(1, int(len(feature_names) * 0.25)):
        raise ValueError(
            "El CSV no es compatible con el modelo. Faltan "
            f"{len(missing_features)} de {len(feature_names)} características."
        )

    features = pd.DataFrame(index=data.index)
    for name in feature_names:
        features[name] = (
            pd.to_numeric(data[name], errors="coerce") if name in data else np.nan
        )
    features = features.replace([np.inf, -np.inf], np.nan)
    probabilities = bundle["pipeline"].predict_proba(features)[:, 1]
    active_threshold = float(bundle["threshold"] if threshold is None else threshold)
    malicious = probabilities >= active_threshold

    result = data.copy()
    result["Probabilidad_Maliciosa"] = probabilities
    result["Deteccion"] = np.where(malicious, "MALICIOSO", "BENIGNO")
    result["Nivel_Alerta"] = np.where(
        malicious,
        np.where(probabilities >= 0.8, "ALTA", "MEDIA"),
        "NINGUNA",
    )
    result["Caracteristicas_Faltantes"] = len(missing_features)
    alert_number = 0
    alert_ids = []
    for is_malicious in malicious:
        if is_malicious:
            alert_number += 1
            alert_ids.append(f"ALERT-{alert_number:04d}")
        else:
            alert_ids.append("")
    result["ID_Alerta"] = alert_ids
    return result
