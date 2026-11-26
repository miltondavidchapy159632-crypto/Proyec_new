from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src.data import (
    create_flow_groups,
    load_cic_dataset,
    normalize_columns,
    prepare_features,
    save_prepared_dataset,
    split_grouped,
)
from src.model import build_pipeline, load_bundle, predict_frame, save_bundle, tune_threshold
from src.reporting import compute_metrics


def test_cicflowmeter_headers_match_cic_dataset():
    source_columns = [
        "Dst Port",
        "Total Fwd Packet",
        "Total Bwd packets",
        "Total Length of Fwd Packet",
        "Total Length of Bwd Packet",
        "Packet Length Min",
        "Packet Length Max",
        "CWR Flag Count",
        "Fwd Segment Size Avg",
        "Bwd Segment Size Avg",
        "Fwd Bytes/Bulk Avg",
        "Fwd Packet/Bulk Avg",
        "Fwd Bulk Rate Avg",
        "Bwd Bytes/Bulk Avg",
        "Bwd Packet/Bulk Avg",
        "Bwd Bulk Rate Avg",
        "FWD Init Win Bytes",
        "Bwd Init Win Bytes",
        "Fwd Act Data Pkts",
        "Fwd Seg Size Min",
        "Fwd Header Length",
    ]
    expected_columns = [
        "Destination Port",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Min Packet Length",
        "Max Packet Length",
        "CWE Flag Count",
        "Avg Fwd Segment Size",
        "Avg Bwd Segment Size",
        "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate",
        "Init_Win_bytes_forward",
        "Init_Win_bytes_backward",
        "act_data_pkt_fwd",
        "min_seg_size_forward",
        "Fwd Header Length",
        "Fwd Header Length.1",
    ]

    normalized = normalize_columns(pd.DataFrame([{column: 1 for column in source_columns}]))

    assert all(column in normalized.columns for column in expected_columns)
    assert normalized["Fwd Header Length.1"].tolist() == [1]


def test_load_clean_and_remove_duplicates(tmp_path):
    source = tmp_path / "cic.csv"
    pd.DataFrame(
        {
            " Label ": [" BENIGN ", "BENIGN", "PortScan", ""],
            " Flow Duration ": [100, 100, 20, 50],
            " Total Fwd Packets ": [4, 4, 1, 2],
            "Empty": [np.nan, np.nan, np.nan, np.nan],
        }
    ).to_csv(source, index=False)

    data = load_cic_dataset(source)
    prepared = prepare_features(data)

    assert len(prepared.features) == 2
    assert prepared.target.tolist() == [0, 1]
    assert prepared.attack_types.tolist() == ["BENIGN", "PORTSCAN"]
    assert prepared.feature_names == ["Flow Duration", "Total Fwd Packets"]
    assert prepared.dropped_columns == ["Empty"]


def test_prepared_dataset_round_trip(tmp_path):
    source = tmp_path / "cic.csv"
    output = tmp_path / "processed.csv"
    pd.DataFrame(
        {
            "Label": ["BENIGN", "FTP-Patator"],
            "Flow Duration": [100, 200],
            "Source IP": ["192.168.56.102", "192.168.56.101"],
        }
    ).to_csv(source, index=False)
    prepared = prepare_features(load_cic_dataset(source))

    save_prepared_dataset(prepared, output)
    saved = pd.read_csv(output)

    assert saved["Clase"].tolist() == [0, 1]
    assert saved["Tipo_Ataque"].tolist() == ["BENIGN", "FTP-PATATOR"]
    assert saved["Source IP"].tolist() == ["192.168.56.102", "192.168.56.101"]


def test_group_split_has_no_overlap():
    rows = 200
    target = pd.Series([index % 2 for index in range(rows)])
    features = pd.DataFrame({"feature": np.arange(rows)})
    metadata = pd.DataFrame(
        {
            "Timestamp": [
                pd.Timestamp("2026-01-01")
                + pd.to_timedelta(index // 10, unit="m")
                for index in range(rows)
            ],
            "Source IP": ["192.168.56.101"] * rows,
            "Destination IP": ["192.168.56.102"] * rows,
            "Source Port": np.arange(rows) + 30_000,
            "Destination Port": [80] * rows,
            "Protocol": [6] * rows,
        }
    )
    groups = create_flow_groups(metadata)

    train, validation, test, method = split_grouped(features, target, groups, 42)

    train_groups = set(groups.iloc[train])
    validation_groups = set(groups.iloc[validation])
    test_groups = set(groups.iloc[test])
    assert train_groups.isdisjoint(validation_groups)
    assert train_groups.isdisjoint(test_groups)
    assert validation_groups.isdisjoint(test_groups)
    assert set(target.iloc[train]) == {0, 1}
    assert set(target.iloc[test]) == {0, 1}
    assert method in {"grupos_temporales_5min", "estratificado_aleatorio"}


def test_model_training_and_prediction(tmp_path):
    rng = np.random.default_rng(42)
    rows = 120
    target = pd.Series([index % 2 for index in range(rows)])
    features = pd.DataFrame(
        {
            "Flow Duration": rng.integers(10, 1_000, rows),
            "Total Fwd Packets": rng.integers(1, 20, rows),
            "SYN Flag Count": target + rng.integers(0, 2, rows),
        }
    )
    pipeline = build_pipeline(42)
    pipeline.set_params(classifier__n_estimators=20)
    pipeline.fit(features, target)
    probabilities = pipeline.predict_proba(features)[:, 1]
    threshold = tune_threshold(target, probabilities)
    bundle = {
        "pipeline": pipeline,
        "feature_names": features.columns.tolist(),
        "threshold": threshold,
        "demo": True,
    }
    model_path = tmp_path / "model.joblib"
    save_bundle(bundle, model_path)
    loaded = load_bundle(model_path)

    live = features.head(10).copy()
    live["Label"] = "BENIGN"
    live["Source IP"] = "192.168.56.101"
    results = predict_frame(loaded, live)

    assert len(results) == 10
    assert set(results["Deteccion"]).issubset({"BENIGNO", "MALICIOSO"})
    assert results["Probabilidad_Maliciosa"].between(0, 1).all()
    assert (results.loc[results["Deteccion"] == "MALICIOSO", "ID_Alerta"] != "").all()


def test_prediction_rejects_incompatible_csv():
    bundle = {
        "pipeline": None,
        "feature_names": [f"feature_{index}" for index in range(20)],
        "threshold": 0.5,
    }
    with pytest.raises(ValueError, match="no es compatible"):
        predict_frame(bundle, pd.DataFrame({"feature_0": [1]}))


def test_metrics_include_confusion_counts():
    target = pd.Series([0, 0, 1, 1])
    probabilities = np.array([0.1, 0.7, 0.6, 0.9])
    metrics = compute_metrics(target, probabilities, 0.5)

    assert metrics["verdaderos_negativos"] == 1
    assert metrics["falsos_positivos"] == 1
    assert metrics["falsos_negativos"] == 0
    assert metrics["verdaderos_positivos"] == 2
    assert metrics["f1_maliciosa"] == pytest.approx(0.8)
