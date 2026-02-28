from datetime import datetime
from sqlalchemy import create_engine, Column, DateTime, Float, ForeignKey, Integer, String, Text, inspect, text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker


Base = declarative_base()


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True)
    source = Column(String(20), nullable=False)  # web or api
    triggered_by = Column(String(255), nullable=False)
    base_url = Column(String(500), nullable=True)
    dockerfile_path = Column(String(500), nullable=True)
    report_path = Column(String(500), nullable=False)
    risk_level = Column(String(20), nullable=False)
    total_score = Column(Integer, nullable=False)
    summary_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    findings = relationship("ScanResult", back_populates="scan_run", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    target = Column(String(500), nullable=False)
    category = Column(String(100), nullable=False)
    issue_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    cve_id = Column(String(64), nullable=True)
    cvss_score = Column(Float, nullable=True)
    description = Column(Text, nullable=False)
    payload = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan_run = relationship("ScanRun", back_populates="findings")


def init_db(db_url="sqlite:///vulnmicroscan.db"):
    connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
    engine = create_engine(db_url, connect_args=connect_args)
    Base.metadata.create_all(engine)
    _ensure_scan_result_columns(engine)
    return sessionmaker(bind=engine)


def _ensure_scan_result_columns(engine):
    # Lightweight migration for existing deployments.
    expected_columns = {
        "cve_id": "VARCHAR(64)",
        "cvss_score": "FLOAT",
    }
    inspector = inspect(engine)
    if "scan_results" not in inspector.get_table_names():
        return

    existing = {col["name"] for col in inspector.get_columns("scan_results")}
    missing = [name for name in expected_columns if name not in existing]
    if not missing:
        return

    with engine.begin() as conn:
        for name in missing:
            conn.execute(text(f"ALTER TABLE scan_results ADD COLUMN {name} {expected_columns[name]}"))
