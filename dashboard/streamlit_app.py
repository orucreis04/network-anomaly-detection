"""Streamlit dashboard for network anomaly analysis."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pandas as pd
import requests
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import settings  # noqa: E402


ANALYZE_ENDPOINT = f"{settings.backend_api_url}{settings.api_prefix}/analyze-pcap"


def configure_page() -> None:
    """Configure Streamlit page defaults and compact styling."""
    st.set_page_config(
        page_title="Network Anomaly Dashboard",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    st.markdown(
        """
        <style>
        .main .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
        }
        div[data-testid="stMetric"] {
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 14px 16px;
            background: #ffffff;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def post_pcap_to_backend(file_name: str, file_bytes: bytes) -> dict[str, Any]:
    """Send uploaded PCAP bytes to the FastAPI backend."""
    if not file_bytes:
        raise RuntimeError("Yuklenen PCAP dosyasi bos.")

    files = {"file": (file_name, file_bytes, "application/octet-stream")}
    try:
        response = requests.post(ANALYZE_ENDPOINT, files=files, timeout=120)
    except requests.RequestException as exc:
        raise RuntimeError(
            "Backend API'ye ulasilamadi. FastAPI servisinin calistigindan emin olun."
        ) from exc

    if response.status_code >= 400:
        detail = _extract_error_detail(response)
        raise RuntimeError(f"Analiz basarisiz: {detail}")

    return response.json()


def _extract_error_detail(response: requests.Response) -> str:
    """Extract a human-readable error message from API response."""
    try:
        payload = response.json()
    except ValueError:
        return response.text or f"HTTP {response.status_code}"
    return str(payload.get("detail", payload))


def dataframe_from_payload(payload: dict[str, Any], key: str) -> pd.DataFrame:
    """Build a DataFrame from a list field in the API payload."""
    records = payload.get(key, [])
    if not isinstance(records, list):
        return pd.DataFrame()
    return pd.DataFrame.from_records(records)


def render_metrics(payload: dict[str, Any], features_df: pd.DataFrame, anomalies_df: pd.DataFrame) -> None:
    """Render top-level analysis metrics."""
    total_packets = int(payload.get("packet_count", 0))
    total_ips = int(features_df["src_ip"].nunique()) if "src_ip" in features_df else 0
    anomaly_count = int(payload.get("anomaly_count", len(anomalies_df)))

    packet_col, ip_col, anomaly_col = st.columns(3)
    packet_col.metric("Toplam paket", f"{total_packets:,}")
    ip_col.metric("Toplam IP", f"{total_ips:,}")
    anomaly_col.metric("Anomali", f"{anomaly_count:,}")


def render_distribution_charts(anomalies_df: pd.DataFrame) -> None:
    """Render anomaly type and severity distribution charts."""
    type_col, severity_col = st.columns(2)

    with type_col:
        st.subheader("Anomaly type dagilimi")
        if anomalies_df.empty or "anomaly_type" not in anomalies_df:
            st.info("Anomali tipi dagilimi icin veri yok.")
        else:
            type_counts = anomalies_df["anomaly_type"].value_counts()
            st.bar_chart(type_counts)

    with severity_col:
        st.subheader("Severity dagilimi")
        if anomalies_df.empty or "severity" not in anomalies_df:
            st.info("Severity dagilimi icin veri yok.")
        else:
            severity_counts = anomalies_df["severity"].value_counts()
            st.bar_chart(severity_counts)


def render_tables(features_df: pd.DataFrame, anomalies_df: pd.DataFrame) -> None:
    """Render anomaly and feature tables."""
    st.subheader("Anomali tablosu")
    if anomalies_df.empty:
        st.success("Tespit edilen anomali yok.")
    else:
        st.dataframe(anomalies_df, use_container_width=True, hide_index=True)

    st.subheader("IP bazli feature tablosu")
    if features_df.empty:
        st.info("Feature verisi bulunamadi.")
    else:
        st.dataframe(features_df, use_container_width=True, hide_index=True)


def render_dashboard(payload: dict[str, Any]) -> None:
    """Render all analysis results."""
    features_df = dataframe_from_payload(payload, "features")
    anomalies_df = dataframe_from_payload(payload, "anomalies")

    render_metrics(payload, features_df, anomalies_df)
    st.divider()
    render_distribution_charts(anomalies_df)
    st.divider()
    render_tables(features_df, anomalies_df)


def main() -> None:
    """Run the Streamlit dashboard."""
    configure_page()

    st.title("Network Anomaly Detection")
    st.caption(f"Backend API: {settings.backend_api_url}")

    uploaded_file = st.file_uploader(
        "PCAP dosyasi yukle",
        type=["pcap", "pcapng"],
        accept_multiple_files=False,
    )

    analyze_clicked = st.button(
        "Analiz et",
        type="primary",
        disabled=uploaded_file is None,
        use_container_width=False,
    )

    if analyze_clicked and uploaded_file is not None:
        with st.spinner("PCAP dosyasi analiz ediliyor..."):
            try:
                payload = post_pcap_to_backend(uploaded_file.name, uploaded_file.getvalue())
            except RuntimeError as exc:
                st.error(str(exc))
                return

        st.success("Analiz tamamlandi.")
        st.session_state["latest_analysis"] = payload

    latest_payload = st.session_state.get("latest_analysis")
    if latest_payload:
        render_dashboard(latest_payload)
    else:
        st.info("Analiz sonuclarini gormek icin bir PCAP dosyasi yukleyin.")


if __name__ == "__main__":
    main()
