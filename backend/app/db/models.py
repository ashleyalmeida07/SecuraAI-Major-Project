import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.db.session import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True, nullable=False)
    scan_type = Column(String, index=True, nullable=False)  # "url", "cli", "full"
    status = Column(String, default="running")  # "running", "completed", "failed"
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)

    flow_runs = relationship("FlowRun", back_populates="scan")
    findings = relationship("Finding", back_populates="scan")

class FlowRun(Base):
    __tablename__ = "flow_runs"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    flow_name = Column(String, nullable=False)  # "recon", "headers", "static_analysis"
    status = Column(String, default="running")
    duration_ms = Column(Integer, nullable=True)

    scan = relationship("Scan", back_populates="flow_runs")
    findings = relationship("Finding", back_populates="flow_run")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    flow_run_id = Column(Integer, ForeignKey("flow_runs.id"))
    issue_title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)  # "low", "medium", "high", "critical", "info"
    category = Column(String, nullable=True)  # OWASP category etc
    endpoint_or_file = Column(String, nullable=False)
    evidence = Column(Text, nullable=True)
    is_false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
    flow_run = relationship("FlowRun", back_populates="findings")
    fixes = relationship("Fix", back_populates="finding")

class Fix(Base):
    __tablename__ = "fixes"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    diff_text = Column(Text, nullable=False)
    explanation = Column(Text, nullable=True)
    applied = Column(Boolean, default=False)

    finding = relationship("Finding", back_populates="fixes")
