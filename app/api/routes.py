"""HTTP API routes."""

from pathlib import Path
from uuid import uuid4

import pandas as pd
from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.capture.pcap_reader import PcapReadError, read_pcap
from app.config import settings
from app.detection.rule_engine import detect_anomalies
from app.processing.feature_extractor import extract_ip_features
from app.utils.logging import get_logger


logger = get_logger(__name__)

router = APIRouter()

FEATURES_CSV = settings.processed_data_dir / "features.csv"
ANOMALIES_CSV = settings.processed_data_dir / "anomalies.csv"
UPLOAD_CHUNK_SIZE = 1024 * 1024


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Return service health status."""
    return {
        "status": "healthy",
        "environment": settings.environment,
        "version": settings.app_version,
    }


def _dataframe_to_records(dataframe: pd.DataFrame) -> list[dict[str, object]]:
    """Convert a DataFrame to JSON-safe records."""
    safe_dataframe = dataframe.astype(object).where(pd.notna(dataframe), None)
    return safe_dataframe.to_dict("records")


def _validate_pcap_upload(file: UploadFile) -> None:
    """Validate uploaded PCAP file metadata."""
    filename = file.filename or ""
    if not filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .pcap and .pcapng files are supported.",
        )


async def _save_uploaded_file(file: UploadFile) -> Path:
    """Save an uploaded PCAP file under data/raw with a unique name."""
    _validate_pcap_upload(file)
    settings.raw_data_dir.mkdir(parents=True, exist_ok=True)

    original_name = Path(file.filename or "upload.pcap").name
    target_path = settings.raw_data_dir / f"{uuid4().hex}_{original_name}"
    total_bytes = 0

    try:
        with target_path.open("wb") as destination:
            while chunk := await file.read(UPLOAD_CHUNK_SIZE):
                total_bytes += len(chunk)
                if total_bytes > settings.max_upload_size_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Uploaded PCAP file exceeds the configured size limit.",
                    )
                destination.write(chunk)
        if total_bytes == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded PCAP file is empty.",
            )
    except HTTPException:
        target_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        logger.exception("Failed to save uploaded PCAP file: %s", original_name)
        target_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Uploaded file could not be saved.",
        ) from exc
    finally:
        await file.close()

    logger.info("Uploaded PCAP saved: %s bytes=%d", target_path, total_bytes)
    return target_path


@router.post("/analyze-pcap")
async def analyze_pcap(file: UploadFile = File(...)) -> dict[str, object]:
    """Analyze an uploaded PCAP file and return features plus anomalies."""
    saved_path = await _save_uploaded_file(file)

    try:
        packets_df = read_pcap(str(saved_path))
        features_df = extract_ip_features(packets_df, save_to_csv=True, output_path=FEATURES_CSV)
        anomalies_df = detect_anomalies(features_df, save_to_csv=True, output_path=ANOMALIES_CSV)
    except PcapReadError as exc:
        logger.error("PCAP analysis failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        logger.error("Invalid analysis input: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected PCAP analysis error: %s", saved_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PCAP analysis failed unexpectedly.",
        ) from exc

    return {
        "status": "completed",
        "file": str(saved_path),
        "packet_count": int(len(packets_df)),
        "feature_count": int(len(features_df)),
        "anomaly_count": int(len(anomalies_df)),
        "features": _dataframe_to_records(features_df),
        "anomalies": _dataframe_to_records(anomalies_df),
    }


@router.get("/features")
async def get_latest_features() -> dict[str, object]:
    """Return the latest generated features.csv content."""
    if not FEATURES_CSV.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No features.csv file found. Analyze a PCAP file first.",
        )

    try:
        features_df = pd.read_csv(FEATURES_CSV)
    except Exception as exc:
        logger.exception("Failed to read features CSV: %s", FEATURES_CSV)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="features.csv could not be read.",
        ) from exc

    return {
        "file": str(FEATURES_CSV),
        "count": int(len(features_df)),
        "features": _dataframe_to_records(features_df),
    }


@router.get("/anomalies")
async def get_latest_anomalies() -> dict[str, object]:
    """Return the latest generated anomalies.csv content."""
    if not ANOMALIES_CSV.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No anomalies.csv file found. Analyze a PCAP file first.",
        )

    try:
        anomalies_df = pd.read_csv(ANOMALIES_CSV)
    except Exception as exc:
        logger.exception("Failed to read anomalies CSV: %s", ANOMALIES_CSV)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="anomalies.csv could not be read.",
        ) from exc

    return {
        "file": str(ANOMALIES_CSV),
        "count": int(len(anomalies_df)),
        "anomalies": _dataframe_to_records(anomalies_df),
    }
