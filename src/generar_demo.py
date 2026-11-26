from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from .data import load_cic_dataset, prepare_features
from .model import build_pipeline, save_bundle, tune_threshold
from .reporting import compute_metrics

DEMO_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
]


def generate_demo_data(
    benign_rows: int = 600,
    scan_rows: int = 200,
    brute_rows: int = 200,
    seed: int = 42,
) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    frames = []
    start = pd.Timestamp("2026-01-01 09:00:00")

    specifications = [
        ("BENIGN", benign_rows, 80, 443),
        ("PortScan", scan_rows, 6, 22),
        ("FTP-Patator", brute_rows, 21, 21),
    ]
    offset = 0
    for label, count, destination_port, fixed_port in specifications:
        if label == "BENIGN":
            duration = rng.integers(1_000, 60_000, count)
            fwd_packets = rng.integers(5, 50, count)
            bwd_packets = rng.integers(4, 45, count)
            fwd_bytes = rng.integers(250, 5_000, count)
            bwd_bytes = rng.integers(300, 6_000, count)
            iat_mean = rng.integers(1_000, 10_000, count)
            syn = rng.integers(1, 3, count)
            ack = rng.integers(1, 4, count)
            rst = rng.integers(0, 2, count)
            ports = rng.choice([80, 443], count)
        elif label == "PortScan":
            duration = rng.integers(0, 300, count)
            fwd_packets = rng.integers(1, 3, count)
            bwd_packets = rng.integers(0, 2, count)
            fwd_bytes = rng.integers(40, 90, count)
            bwd_bytes = rng.integers(0, 70, count)
            iat_mean = rng.integers(0, 150, count)
            syn = rng.integers(1, 3, count)
            ack = rng.integers(0, 2, count)
            rst = rng.integers(0, 3, count)
            ports = rng.integers(20, 101, count)
        else:
            duration = rng.integers(500, 4_000, count)
            fwd_packets = rng.integers(2, 6, count)
            bwd_packets = rng.integers(1, 4, count)
            fwd_bytes = rng.integers(80, 260, count)
            bwd_bytes = rng.integers(40, 180, count)
            iat_mean = rng.integers(200, 1_500, count)
            syn = rng.integers(1, 3, count)
            ack = rng.integers(1, 3, count)
            rst = rng.integers(0, 2, count)
            ports = np.full(count, fixed_port)

        total_bytes = fwd_bytes + bwd_bytes
        total_packets = fwd_packets + bwd_packets
        frame = pd.DataFrame(
            {
                "Timestamp": [
                    (
                        start + pd.to_timedelta(offset + index, unit="s")
                    ).isoformat()
                    for index in range(count)
                ],
                "Source IP": "192.168.56.101",
                "Destination IP": "192.168.56.102",
                "Source Port": rng.integers(30_000, 60_000, count),
                "Destination Port": ports,
                "Protocol": 6,
                "Flow Duration": duration,
                "Total Fwd Packets": fwd_packets,
                "Total Backward Packets": bwd_packets,
                "Total Length of Fwd Packets": fwd_bytes,
                "Total Length of Bwd Packets": bwd_bytes,
                "Fwd Packet Length Max": np.maximum(40, fwd_bytes // fwd_packets + 20),
                "Fwd Packet Length Mean": fwd_bytes / fwd_packets,
                "Fwd Packet Length Std": rng.uniform(5, 80, count),
                "Bwd Packet Length Max": np.maximum(
                    0, bwd_bytes // np.maximum(bwd_packets, 1) + 20
                ),
                "Bwd Packet Length Mean": bwd_bytes / np.maximum(bwd_packets, 1),
                "Bwd Packet Length Std": rng.uniform(0, 70, count),
                "Flow Bytes/s": total_bytes * 1_000_000 / np.maximum(duration, 1),
                "Flow Packets/s": total_packets * 1_000_000 / np.maximum(duration, 1),
                "Flow IAT Mean": iat_mean,
                "Flow IAT Std": rng.uniform(0, iat_mean),
                "Flow IAT Max": iat_mean * rng.uniform(1, 3, count),
                "Flow IAT Min": rng.uniform(0, np.maximum(iat_mean, 1)),
                "Fwd IAT Mean": iat_mean / np.maximum(fwd_packets, 1),
                "Fwd IAT Std": rng.uniform(0, 500, count),
                "Bwd IAT Mean": iat_mean / np.maximum(bwd_packets, 1),
                "Bwd IAT Std": rng.uniform(0, 500, count),
                "SYN Flag Count": syn,
                "ACK Flag Count": ack,
                "FIN Flag Count": rng.integers(0, 3, count),
                "RST Flag Count": rst,
                "PSH Flag Count": rng.integers(0, 5, count),
                "Label": label,
            }
        )
        frames.append(frame)
        offset += count
    return pd.concat(frames, ignore_index=True)


def train_demo(output_csv: str | Path, output_model: str | Path) -> dict:
    data = generate_demo_data()
    csv_path = Path(output_csv)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    data.to_csv(csv_path, index=False)

    prepared = prepare_features(load_cic_dataset(csv_path))
    x = prepared.features
    y = prepared.target
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.25, random_state=42, stratify=y
    )
    pipeline = build_pipeline(42)
    pipeline.set_params(classifier__n_estimators=150)
    pipeline.fit(x_train, y_train)
    threshold = tune_threshold(y_test, pipeline.predict_proba(x_test)[:, 1])
    metrics = compute_metrics(y_test, pipeline.predict_proba(x_test)[:, 1], threshold)
    bundle = {
        "pipeline": pipeline,
        "feature_names": prepared.feature_names,
        "threshold": threshold,
        "trained_at": pd.Timestamp.now(tz="UTC").isoformat(),
        "split_method": "demostracion_sintetica",
        "dataset_info": {
            "filas_originales": len(data),
            "filas_utilizadas": len(data),
            "clases": {"0": int((y == 0).sum()), "1": int((y == 1).sum())},
            "ataques": data["Label"].value_counts().to_dict(),
            "entrenamiento": len(x_train),
            "prueba": len(x_test),
        },
        "metrics": metrics,
        "demo": True,
    }
    save_bundle(bundle, output_model)
    return bundle


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generar datos sintéticos y un modelo solo para probar la interfaz"
    )
    parser.add_argument("--output", default="datos/demo/demo_flujos.csv")
    parser.add_argument("--model", default="modelos/modelo_demo.joblib")
    args = parser.parse_args()
    bundle = train_demo(args.output, args.model)
    print(f"Datos de demostración: {args.output}")
    print(f"Modelo de demostración: {args.model}")
    print(f"F1 maliciosa: {bundle['metrics']['f1_maliciosa']:.4f}")


if __name__ == "__main__":
    main()
