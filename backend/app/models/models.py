import uuid
import enum
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, Integer, Float, Text, DateTime,
    ForeignKey, Enum as SAEnum, JSON, ARRAY
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.database import Base


def gen_uuid():
    return str(uuid.uuid4())


# ─── ENUMS ──────────────────────────────────────────────────────────────────

class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ProtocolType(str, enum.Enum):
    HTTPS = "HTTPS"
    HTTP = "HTTP"
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    FTPS = "FTPS"
    SSH = "SSH"
    VPN = "VPN"
    UNKNOWN = "UNKNOWN"


class FindingType(str, enum.Enum):
    WEAK_CIPHER = "WEAK_CIPHER"
    QUANTUM_VULNERABLE_ALGO = "QUANTUM_VULNERABLE_ALGO"
    EXPIRED_CERT = "EXPIRED_CERT"
    WEAK_KEY_SIZE = "WEAK_KEY_SIZE"
    OUTDATED_TLS = "OUTDATED_TLS"
    HNDL_RISK = "HNDL_RISK"
    MISSING_PQC = "MISSING_PQC"
    OTHER = "OTHER"


class PQCReadiness(str, enum.Enum):
    QUANTUM_SAFE = "Quantum Safe"
    PARTIALLY_SAFE = "Partially Safe"
    VULNERABLE = "Vulnerable"
    CRITICAL = "Critical Risk"


class ComplianceStatus(str, enum.Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIAL = "PARTIAL"
    NOT_ASSESSED = "NOT_ASSESSED"


class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    COMPLIANCE_OFFICER = "COMPLIANCE_OFFICER"
    SOC_TEAM = "SOC_TEAM"
    MANAGEMENT = "MANAGEMENT"


# ─── USER ───────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=gen_uuid)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(200), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(SAEnum(UserRole), default=UserRole.SECURITY_ANALYST)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    scan_jobs = relationship("ScanJob", back_populates="created_by_user")


# ─── SCAN JOB ────────────────────────────────────────────────────────────────

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    scan_id = Column(String, primary_key=True, default=gen_uuid)
    org_name = Column(String(255), nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    authorized = Column(Boolean, default=False)
    celery_task_id = Column(String(255), nullable=True)
    progress = Column(Integer, default=0)  # 0-100
    created_by = Column(String, ForeignKey("users.id"), nullable=True)
    target_assets = Column(JSON, default=list)  # list of domains/IPs
    scan_config = Column(JSON, default=dict)

    created_by_user = relationship("User", back_populates="scan_jobs")
    assets = relationship("Asset", back_populates="scan_job", cascade="all, delete-orphan")
    cboms = relationship("CBOM", back_populates="scan_job", cascade="all, delete-orphan")


# ─── ASSET ───────────────────────────────────────────────────────────────────

class Asset(Base):
    __tablename__ = "assets"

    asset_id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scan_jobs.scan_id"), nullable=False)
    domain = Column(String(500), nullable=False)
    resolved_ips = Column(JSON, default=list)  # list of IP strings
    protocol = Column(SAEnum(ProtocolType), default=ProtocolType.UNKNOWN)
    is_cdn = Column(Boolean, default=False)
    cdn_provider = Column(String(100), nullable=True)
    is_waf = Column(Boolean, default=False)
    hndl_score = Column(Float, default=0.0)
    hndl_breakdown = Column(JSON, default=dict)
    is_pqc = Column(Boolean, default=False)
    pqc_readiness = Column(SAEnum(PQCReadiness), default=PQCReadiness.VULNERABLE)
    open_ports = Column(JSON, default=list)
    service_category = Column(String(50), nullable=True)
    server_software = Column(String(200), nullable=True)
    scan_method = Column(String(50), nullable=True)  # openssl_cli | python_ssl | testssl
    algorithm_confidence = Column(String(20), default="verified")  # verified | approximate | default
    discovered_at = Column(DateTime, default=datetime.utcnow)

    scan_job = relationship("ScanJob", back_populates="assets")
    certificates = relationship("Certificate", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")
    cipher_suites = relationship("CipherSuite", back_populates="asset", cascade="all, delete-orphan")


# ─── CERTIFICATE ─────────────────────────────────────────────────────────────

class Certificate(Base):
    __tablename__ = "certificates"

    cert_id = Column(String, primary_key=True, default=gen_uuid)
    asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=False)
    domain = Column(String(500), nullable=False)
    subject = Column(String(500), nullable=True)
    issuer = Column(String(500), nullable=True)
    algorithm = Column(String(100), nullable=True)
    key_size = Column(Integer, nullable=True)
    hndl_score = Column(Float, default=0.0)
    expires_at = Column(DateTime, nullable=True)
    is_pqc = Column(Boolean, default=False)
    is_approximate = Column(Boolean, default=False)  # True if algorithm was inferred from issuer, not from leaf cert
    san_domains = Column(JSON, default=list)
    serial_number = Column(String(255), nullable=True)
    fingerprint = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("Asset", back_populates="certificates")


# ─── CIPHER SUITE ─────────────────────────────────────────────────────────────

class CipherSuite(Base):
    __tablename__ = "cipher_suites"

    suite_id = Column(String, primary_key=True, default=gen_uuid)
    asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=False)
    name = Column(String(255), nullable=False)
    tls_version = Column(String(20), nullable=True)
    key_exchange = Column(String(100), nullable=True)
    quantum_risk = Column(Float, default=0.0)
    is_quantum_vulnerable = Column(Boolean, default=False)
    strength = Column(String(20), nullable=True)  # strong, medium, weak

    asset = relationship("Asset", back_populates="cipher_suites")


# ─── FINDING ─────────────────────────────────────────────────────────────────

class Finding(Base):
    __tablename__ = "findings"

    finding_id = Column(String, primary_key=True, default=gen_uuid)
    asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=False)
    type = Column(SAEnum(FindingType), default=FindingType.OTHER)
    severity = Column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    hndl_score = Column(Float, default=0.0)
    cwe_id = Column(String(50), nullable=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    quantum_risk = Column(Float, default=0.0)
    details = Column(JSON, default=dict)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("Asset", back_populates="findings")
    remediation_plan = relationship("Remediation", back_populates="finding", cascade="all, delete-orphan")
    compliance_tags = relationship("ComplianceTag", back_populates="finding", cascade="all, delete-orphan")


# ─── REMEDIATION ─────────────────────────────────────────────────────────────

class Remediation(Base):
    __tablename__ = "remediations"

    playbook_id = Column(String, primary_key=True, default=gen_uuid)
    finding_id = Column(String, ForeignKey("findings.finding_id"), nullable=False)
    priority = Column(Integer, default=5)  # 1-10
    steps = Column(JSON, default=list)  # list of step strings
    status = Column(String(50), default="OPEN")
    created_at = Column(DateTime, default=datetime.utcnow)
    pqc_alternative = Column(String(500), nullable=True)

    finding = relationship("Finding", back_populates="remediation_plan")


# ─── CBOM ─────────────────────────────────────────────────────────────────────

class CBOM(Base):
    __tablename__ = "cboms"

    cbom_id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scan_jobs.scan_id"), nullable=False)
    format = Column(String(50), default="CycloneDX")
    generated_at = Column(DateTime, default=datetime.utcnow)
    content = Column(JSON, default=dict)  # full CycloneDX JSON
    version = Column(String(10), default="1.4")

    scan_job = relationship("ScanJob", back_populates="cboms")


# ─── COMPLIANCE TAG ───────────────────────────────────────────────────────────

class ComplianceTag(Base):
    __tablename__ = "compliance_tags"

    tag_id = Column(String, primary_key=True, default=gen_uuid)
    finding_id = Column(String, ForeignKey("findings.finding_id"), nullable=False)
    framework = Column(String(100), nullable=False)  # NIST-PQC, CERT-IN, RBI, NIST-IR-8547
    control_ref = Column(String(200), nullable=True)
    status = Column(SAEnum(ComplianceStatus), default=ComplianceStatus.NOT_ASSESSED)
    description = Column(Text, nullable=True)

    finding = relationship("Finding", back_populates="compliance_tags")


# ─── AUDIT LOG ───────────────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_logs"

    log_id = Column(String, primary_key=True, default=gen_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String(200), nullable=False)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(255), nullable=True)
    details = Column(JSON, default=dict)
    ip_address = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
