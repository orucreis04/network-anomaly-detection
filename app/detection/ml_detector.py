"""Machine-learning anomaly detector based on Isolation Forest."""

from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.config import settings
from app.utils.logging import get_logger


logger = get_logger(__name__)

NUMERIC_FEATURES = [
    "total_packets",
    "total_bytes",
    "unique_dst_ips",
    "unique_dst_ports",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "avg_packet_size",
    "connection_rate",
]

MODEL_PATH = settings.isolation_forest_model_path


def _validate_features(features_df: pd.DataFrame) -> None:
    """Validate that all numeric ML features exist."""
    missing_columns = set(NUMERIC_FEATURES).difference(features_df.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise ValueError(f"Missing required ML feature columns: {missing}")


def _prepare_numeric_features(features_df: pd.DataFrame) -> pd.DataFrame:
    """Return numeric feature matrix with safe missing-value handling."""
    if features_df.empty:
        return pd.DataFrame(columns=NUMERIC_FEATURES)

    _validate_features(features_df)

    numeric_df = features_df[NUMERIC_FEATURES].copy()
    for column in NUMERIC_FEATURES:
        numeric_df[column] = pd.to_numeric(numeric_df[column], errors="coerce")

    return numeric_df.replace([float("inf"), float("-inf")], pd.NA).fillna(0.0)


def _save_model(model: IsolationForest, model_path: Path = MODEL_PATH) -> None:
    """Persist a trained Isolation Forest model."""
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    logger.info("Isolation Forest model saved: %s", model_path)


def _load_model(model_path: Path = MODEL_PATH) -> IsolationForest | None:
    """Load a persisted Isolation Forest model if it exists."""
    if not model_path.exists():
        return None

    model = joblib.load(model_path)
    if not isinstance(model, IsolationForest):
        raise TypeError(f"Invalid model type loaded from {model_path}")

    logger.info("Isolation Forest model loaded: %s", model_path)
    return model


def train_model(features_df: pd.DataFrame) -> IsolationForest:
    """Train and persist an Isolation Forest model from IP-level features."""
    numeric_df = _prepare_numeric_features(features_df)
    if numeric_df.empty:
        raise ValueError("Cannot train Isolation Forest model with an empty feature DataFrame.")

    model = IsolationForest(
        contamination=settings.isolation_forest_contamination,
        random_state=settings.isolation_forest_random_state,
        n_estimators=100,
    )
    model.fit(numeric_df)
    _save_model(model)

    logger.info("Isolation Forest model trained: rows=%d", len(numeric_df))
    return model


def predict_anomalies(features_df: pd.DataFrame) -> pd.DataFrame:
    """Add ML anomaly score and prediction columns to IP-level features.

    If no persisted model exists, the function trains one from the provided
    feature DataFrame before prediction.
    """
    result_df = features_df.copy()
    if result_df.empty:
        result_df["ml_anomaly_score"] = pd.Series(dtype="float64")
        result_df["ml_prediction"] = pd.Series(dtype="int64")
        logger.warning("ML prediction skipped because feature DataFrame is empty.")
        return result_df

    numeric_df = _prepare_numeric_features(result_df)
    model = _load_model()
    if model is None:
        logger.info("No Isolation Forest model found. Training a new model.")
        model = train_model(result_df)

    # Lower raw decision scores are more anomalous. Negating them makes higher
    # ml_anomaly_score values easier to read as stronger anomaly signals.
    result_df["ml_anomaly_score"] = (-model.decision_function(numeric_df)).round(6)
    result_df["ml_prediction"] = model.predict(numeric_df)

    logger.info("ML anomaly prediction completed: rows=%d", len(result_df))
    return result_df


def get_model_metadata(model_path: Path = MODEL_PATH) -> dict[str, Any]:
    """Return lightweight metadata about the persisted ML model."""
    return {
        "model_path": str(model_path),
        "exists": model_path.exists(),
        "numeric_features": NUMERIC_FEATURES,
        "contamination": settings.isolation_forest_contamination,
        "random_state": settings.isolation_forest_random_state,
    }
