import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _resolve_path(path_value: str) -> str:
    if os.path.isabs(path_value):
        return path_value
    return os.path.abspath(os.path.join(BASE_DIR, path_value))


class Config:
    APP_NAME = "VulnMicroScan"
    SECRET_KEY = os.getenv("VMS_SECRET_KEY", "change-me-in-production")

    _db_uri = os.getenv("DATABASE_URL", "sqlite:///vulnmicroscan.db")
    if _db_uri.startswith("sqlite:///") and not _db_uri.startswith("sqlite:////"):
        _db_rel = _db_uri.replace("sqlite:///", "", 1)
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{_resolve_path(_db_rel)}"
    else:
        SQLALCHEMY_DATABASE_URI = _db_uri

    DEFAULT_TIMEOUT = int(os.getenv("VMS_TIMEOUT", "8"))
    MAX_ENDPOINTS = int(os.getenv("VMS_MAX_ENDPOINTS", "100"))
    MAX_SCAN_SECONDS = int(os.getenv("VMS_MAX_SCAN_SECONDS", "30"))
    REPORTS_DIR = _resolve_path(os.getenv("VMS_REPORTS_DIR", "generated_reports"))

    AUTH_USERNAME = os.getenv("VMS_AUTH_USERNAME", "admin")
    AUTH_PASSWORD = os.getenv("VMS_AUTH_PASSWORD", "change-me")
    JWT_SECRET = os.getenv("VMS_JWT_SECRET", "change-me-jwt-secret")
    JWT_ALGORITHM = os.getenv("VMS_JWT_ALGORITHM", "HS256")
    JWT_EXP_MINUTES = int(os.getenv("VMS_JWT_EXP_MINUTES", "60"))

    RATE_LIMIT_REQUESTS = int(os.getenv("VMS_RATE_LIMIT_REQUESTS", "5"))
    RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("VMS_RATE_LIMIT_WINDOW_SECONDS", "60"))
