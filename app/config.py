"""Central application configuration."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables and .env files."""

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Network Anomaly Detection System"
    app_version: str = "0.1.0"
    environment: str = Field(default="development")
    api_prefix: str = "/api"
    backend_api_url: str = "http://127.0.0.1:8000"
    cors_allow_origins: list[str] = [
        "http://127.0.0.1:8501",
        "http://localhost:8501",
    ]

    log_level: str = "INFO"

    raw_data_dir: Path = DATA_DIR / "raw"
    processed_data_dir: Path = DATA_DIR / "processed"
    model_dir: Path = DATA_DIR / "models"
    sample_pcap_file: str = "sample.pcap"
    isolation_forest_model_file: str = "isolation_forest.pkl"

    max_packets_per_pcap: int = 100_000
    max_upload_size_bytes: int = 100 * 1024 * 1024
    suspicious_port_threshold: int = 1024
    high_packet_rate_threshold: int = 1_000

    port_scan_unique_dst_ports_threshold: int = 20
    high_traffic_packets_threshold: int = 1_000
    high_traffic_bytes_threshold: int = 5_000_000
    suspicious_connection_rate_threshold: float = 100.0
    multi_target_unique_dst_ips_threshold: int = 30

    isolation_forest_contamination: float = 0.05
    isolation_forest_random_state: int = 42

    @property
    def sample_pcap_path(self) -> Path:
        """Return the default sample PCAP path under data/raw."""
        return self.raw_data_dir / self.sample_pcap_file

    @property
    def isolation_forest_model_path(self) -> Path:
        """Return the persisted Isolation Forest model path."""
        return self.model_dir / self.isolation_forest_model_file


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()


settings = get_settings()
