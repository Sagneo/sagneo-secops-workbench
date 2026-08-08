import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("APP_DATABASE_URL", "sqlite:///./data/secops.db")
    session_cookie: str = os.getenv("APP_SESSION_COOKIE", "secops_session")
    idle_minutes: int = int(os.getenv("APP_SESSION_IDLE_MINUTES", "30"))
    absolute_hours: int = int(os.getenv("APP_SESSION_ABSOLUTE_HOURS", "8"))
    secure_cookie: bool = os.getenv("APP_SECURE_COOKIE", "false").lower() == "true"
    log_level: str = os.getenv("APP_LOG_LEVEL", "INFO")
    ingest_max_bytes: int = int(os.getenv("APP_INGEST_MAX_BYTES", "5242880"))
    ingest_max_line_bytes: int = int(os.getenv("APP_INGEST_MAX_LINE_BYTES", "16384"))
    source_stale_hours: int = int(os.getenv("APP_SOURCE_STALE_HOURS", "24"))
    evidence_root: str = os.getenv("APP_EVIDENCE_ROOT", "/data/evidence")
    collector_ssh_key: str = os.getenv("APP_COLLECTOR_SSH_KEY", "/collector/linux-ir-lite-v1")
    collector_known_hosts: str = os.getenv("APP_COLLECTOR_KNOWN_HOSTS", "/collector/known_hosts")


settings = Settings()
