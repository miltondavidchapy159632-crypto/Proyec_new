from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

LABEL_COLUMN = "Label"
TARGET_COLUMN = "Clase"
ATTACK_COLUMN = "Tipo_Ataque"
SOURCE_COLUMN = "Archivo_Origen"
ROW_COLUMN = "Fila_Origen"
METADATA_COLUMNS = [
    "Timestamp",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol",
]
EXCLUDED_FEATURES = {
    LABEL_COLUMN,
    TARGET_COLUMN,
    ATTACK_COLUMN,
    SOURCE_COLUMN,
    ROW_COLUMN,
}
CICFLOWMETER_RENAMES = {
    "Dst Port": "Destination Port",
    "Total Fwd Packet": "Total Fwd Packets",
    "Total Bwd packets": "Total Backward Packets",
    "Total Length of Fwd Packet": "Total Length of Fwd Packets",
    "Total Length of Bwd Packet": "Total Length of Bwd Packets",
    "Packet Length Min": "Min Packet Length",
    "Packet Length Max": "Max Packet Length",
    "CWR Flag Count": "CWE Flag Count",
    "Fwd Segment Size Avg": "Avg Fwd Segment Size",
    "Bwd Segment Size Avg": "Avg Bwd Segment Size",
    "Fwd Bytes/Bulk Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Packet/Bulk Avg": "Fwd Avg Packets/Bulk",
    "Fwd Bulk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Bytes/Bulk Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Packet/Bulk Avg": "Bwd Avg Packets/Bulk",
    "Bwd Bulk Rate Avg": "Bwd Avg Bulk Rate",
    "FWD Init Win Bytes": "Init_Win_bytes_forward",
    "Bwd Init Win Bytes": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
}


@dataclass
class PreparedDataset:
    features: pd.DataFrame
    target: pd.Series
    attack_types: pd.Series
    metadata: pd.DataFrame
    feature_names: list[str]
    dropped_columns: list[str]
    source_rows: int


def normalize_columns(frame: pd.DataFrame) -> pd.DataFrame:
    result = frame.copy()
    result.columns = [
        str(column).replace("\ufeff", "").strip() for column in result.columns
    ]
    for source, target in CICFLOWMETER_RENAMES.items():
        if target not in result.columns and source in result.columns:
            result = result.rename(columns={source: target})
    if "Fwd Header Length.1" not in result.columns and "Fwd Header Length" in result.columns:
        result["Fwd Header Length.1"] = result["Fwd Header Length"]
    duplicates = result.columns[result.columns.duplicated()].unique().tolist()
    if duplicates:
        raise ValueError(f"Hay nombres de columnas duplicados: {duplicates}")
    return result


def find_csv_files(input_path: str | Path) -> list[Path]:
    path = Path(input_path)
    if path.is_file():
        if path.suffix.lower() != ".csv":
            raise ValueError(f"El archivo de entrada no es CSV: {path}")
        return [path]
    if not path.exists():
        raise FileNotFoundError(f"No existe la ruta de entrada: {path}")
    files = sorted(file for file in path.rglob("*.csv") if file.is_file())
    if not files:
        raise FileNotFoundError(f"No se encontraron archivos CSV en: {path}")
    return files


def load_cic_dataset(input_path: str | Path | list[str | Path]) -> pd.DataFrame:
    if isinstance(input_path, (list, tuple)):
        files = []
        for item in input_path:
            files.extend(find_csv_files(item))
    else:
        files = find_csv_files(input_path)
    frames = []
    for file in files:
        frame = normalize_columns(pd.read_csv(file, low_memory=False))
        if LABEL_COLUMN not in frame.columns:
            raise ValueError(f"El archivo {file.name} no tiene la columna 'Label'")
        frame[SOURCE_COLUMN] = file.name
        frame[ROW_COLUMN] = np.arange(len(frame), dtype=int)
        frames.append(frame)

    data = pd.concat(frames, ignore_index=True)
    data[LABEL_COLUMN] = data[LABEL_COLUMN].astype("string").str.strip()
    data = data[data[LABEL_COLUMN].notna()].copy()
    data = data[data[LABEL_COLUMN].str.len() > 0].copy()
    data[ATTACK_COLUMN] = data[LABEL_COLUMN].str.upper()
    data[TARGET_COLUMN] = (data[ATTACK_COLUMN] != "BENIGN").astype(int)
    return data.reset_index(drop=True)


def prepare_features(data: pd.DataFrame) -> PreparedDataset:
    if LABEL_COLUMN not in data.columns or TARGET_COLUMN not in data.columns:
        raise ValueError("Los datos deben contener 'Label' y 'Clase'")

    source_rows = len(data)
    candidates = [
        column
        for column in data.columns
        if column not in EXCLUDED_FEATURES
        and not column.lower().startswith("unnamed")
    ]
    numeric = data[candidates].apply(pd.to_numeric, errors="coerce")
    numeric = numeric.replace([np.inf, -np.inf], np.nan)
    empty_columns = numeric.columns[numeric.isna().all()].tolist()
    numeric = numeric.drop(columns=empty_columns)

    duplicate_mask = pd.concat(
        [numeric, data[TARGET_COLUMN], data[ATTACK_COLUMN]], axis=1
    ).duplicated()
    valid_rows = numeric.notna().any(axis=1) & ~duplicate_mask
    numeric = numeric.loc[valid_rows].copy()
    target = data.loc[valid_rows, TARGET_COLUMN].astype(int).copy()
    attack_types = data.loc[valid_rows, ATTACK_COLUMN].copy()

    metadata_columns = [
        column for column in METADATA_COLUMNS + [SOURCE_COLUMN, ROW_COLUMN]
        if column in data.columns
    ]
    metadata = data.loc[valid_rows, metadata_columns].copy()

    return PreparedDataset(
        features=numeric,
        target=target,
        attack_types=attack_types,
        metadata=metadata,
        feature_names=numeric.columns.tolist(),
        dropped_columns=empty_columns,
        source_rows=source_rows,
    )


def create_flow_groups(metadata: pd.DataFrame) -> pd.Series:
    if "Timestamp" not in metadata.columns:
        return pd.Series(
            [f"ROW_{index}" for index in metadata.index],
            index=metadata.index,
            dtype="string",
        )

    timestamps = pd.to_datetime(metadata["Timestamp"], errors="coerce", utc=True)
    group_values = timestamps.dt.floor("5min").astype("string").fillna("SIN_FECHA")
    for column in [
        "Source IP",
        "Destination IP",
        "Source Port",
        "Destination Port",
        "Protocol",
    ]:
        if column in metadata.columns:
            group_values = (
                group_values
                + "|"
                + metadata[column].astype("string").fillna("DESCONOCIDO")
            )

    groups = pd.util.hash_pandas_object(
        pd.DataFrame({"group": group_values}), index=False
    ).astype("string")
    missing_time = timestamps.isna()
    if missing_time.any():
        groups.loc[missing_time] = [
            f"ROW_{index}" for index in metadata.index[missing_time]
        ]
    groups.name = "flow_group"
    return groups


def _fallback_split(target: pd.Series, random_state: int):
    indices = np.arange(len(target))
    trainval_indices, test_indices = train_test_split(
        indices,
        test_size=0.2,
        random_state=random_state,
        stratify=target,
    )
    train_indices, validation_indices = train_test_split(
        trainval_indices,
        test_size=0.25,
        random_state=random_state,
        stratify=target.iloc[trainval_indices],
    )
    return train_indices, validation_indices, test_indices, "estratificado_aleatorio"


def split_grouped(
    features: pd.DataFrame,
    target: pd.Series,
    groups: pd.Series,
    random_state: int = 42,
):
    grouped = pd.DataFrame({"group": groups.to_numpy(), "target": target.to_numpy()})
    groups_per_class = grouped.drop_duplicates().groupby("target")["group"].nunique()
    if len(groups_per_class) < 2 or groups_per_class.min() < 5:
        return _fallback_split(target, random_state)

    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=random_state)
    trainval_indices, test_indices = next(splitter.split(features, target, groups))
    remaining_features = features.iloc[trainval_indices]
    remaining_target = target.iloc[trainval_indices]
    remaining_groups = groups.iloc[trainval_indices]

    validation_splitter = StratifiedGroupKFold(
        n_splits=4, shuffle=True, random_state=random_state
    )
    relative_train, relative_validation = next(
        validation_splitter.split(
            remaining_features, remaining_target, remaining_groups
        )
    )
    train_indices = trainval_indices[relative_train]
    validation_indices = trainval_indices[relative_validation]
    return train_indices, validation_indices, test_indices, "grupos_temporales_5min"


def sample_per_label(
    data: pd.DataFrame,
    max_rows_per_label: int | None,
    random_state: int,
) -> pd.DataFrame:
    if max_rows_per_label is None:
        return data
    if max_rows_per_label < 1:
        raise ValueError("max_rows_per_label debe ser mayor que cero")
    samples = []
    for _, group in data.groupby(ATTACK_COLUMN, sort=False):
        count = min(max_rows_per_label, len(group))
        samples.append(group.sample(n=count, random_state=random_state))
    return (
        pd.concat(samples, ignore_index=True)
        .sample(frac=1, random_state=random_state)
        .reset_index(drop=True)
    )


def save_prepared_dataset(
    prepared: PreparedDataset,
    output_path: str | Path,
) -> None:
    output = prepared.features.copy()
    output[TARGET_COLUMN] = prepared.target
    output[ATTACK_COLUMN] = prepared.attack_types
    for column in prepared.metadata.columns:
        output[column] = prepared.metadata[column]
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(path, index=False)
