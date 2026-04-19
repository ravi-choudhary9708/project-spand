"""
Assets Router - Asset inventory management
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models.models import Asset, Finding, Certificate, CipherSuite, ComplianceTag
from app.auth.auth import get_current_user

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get(
    "", 
    summary="List Global Asset Inventory", 
    description="""
Provides a filterable inventory of all unique domains and infrastructure discovered across organization scans.

**Supported Filters:**
- **Protocol**: Filter by service category (e.g., `https`, `ssh`, `dns`).
- **Min HNDL**: Filter by risk threshold (e.g., `7.5` for critical only).
- **PQC Readiness**: Filter by state (`Quantum Safe`, `Vulnerable`, etc.).
- **CDN Status**: View assets with or without CDN protection.

**Security Insights:**
Each asset includes computed `network_type` (Internal vs Public) and `algorithm_confidence` (Direct Scan vs Inferred).
"""
)
async def list_assets(
    protocol: Optional[str] = Query(None),
    min_hndl: Optional[float] = Query(None),
    is_cdn: Optional[bool] = Query(None),
    pqc_readiness: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    query = db.query(Asset)
    if protocol:
        query = query.filter(Asset.service_category == protocol.lower())
    if min_hndl is not None:
        query = query.filter(Asset.hndl_score >= min_hndl)
    if is_cdn is not None:
        query = query.filter(Asset.is_cdn == is_cdn)
    if pqc_readiness:
        query = query.filter(Asset.pqc_readiness.ilike(f"%{pqc_readiness}%"))

    total = query.count()
    assets = query.order_by(Asset.hndl_score.desc()).offset(offset).limit(limit).all()
    return {"total": total, "assets": [_serialize_asset(a) for a in assets]}


@router.get("/{asset_id}", summary="Get Asset Details", description="Retrieves comprehensive details about a specific asset, including certificates, ciphers, and findings.")
async def get_asset(asset_id: str, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {
        **_serialize_asset(asset),
        "certificates": [_serialize_cert(c) for c in asset.certificates],
        "cipher_suites": [_serialize_suite(s) for s in asset.cipher_suites],
        "findings": [_serialize_finding(f) for f in asset.findings],
        "tls_data": {"scan_method": asset.scan_method},
    }


@router.get("/{asset_id}/findings", summary="Get Asset Findings", description="Retrieves only the vulnerability findings associated with a specific asset.")
async def get_asset_findings(asset_id: str, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return [_serialize_finding(f) for f in asset.findings]


def _serialize_asset(a: Asset, include_first_cert: bool = False) -> dict:
    base = {
        "asset_id": a.asset_id,
        "scan_id": a.scan_id,
        "domain": a.domain,
        "resolved_ips": a.resolved_ips or [],
        "protocol": a.protocol.value if a.protocol else None,
        "is_cdn": a.is_cdn,
        "cdn_provider": a.cdn_provider,
        "is_waf": a.is_waf,
        "hndl_score": a.hndl_score,
        "is_pqc": a.is_pqc,
        "pqc_readiness": a.pqc_readiness.value if a.pqc_readiness else None,
        "open_ports": a.open_ports or [],
        "service_category": a.service_category,
        "server_software": a.server_software,
        "findings_count": len(a.findings),
        # ── Real scan data fields ──
        # algorithm & key_size are pulled from the first stored certificate
        # so the asset list table can show them without a detail round-trip.
        "algorithm": None,
        "key_size":   None,
        "issuer":     None,
        "algorithm_confidence": a.algorithm_confidence,
        "network_type": a.network_type or "public",
    }
    # Attach first-cert data to every list item for the table columns
    if a.certificates:
        first = a.certificates[0]
        base["algorithm"] = first.algorithm
        base["key_size"]   = first.key_size
        base["issuer"]     = first.issuer
    return base


def _serialize_cert(c: Certificate) -> dict:
    return {
        "cert_id": c.cert_id,
        "subject": c.subject,
        "issuer": c.issuer,
        "algorithm": c.algorithm,
        "key_size": c.key_size,
        "hndl_score": c.hndl_score,
        "expires_at": c.expires_at.isoformat() if c.expires_at else None,
        "is_pqc": c.is_pqc,
        "is_approximate": c.is_approximate,
    }


def _serialize_suite(s: CipherSuite) -> dict:
    return {
        "suite_id": s.suite_id,
        "name": s.name,
        "tls_version": s.tls_version,
        "key_exchange": s.key_exchange,
        "quantum_risk": s.quantum_risk,
        "is_quantum_vulnerable": s.is_quantum_vulnerable,
        "strength": s.strength,
        # Port is stored in the suite name or as part of tls_version for multi-port scans
        "port": getattr(s, 'port', None),
    }


def _serialize_finding(f: Finding) -> dict:
    tags = [{"framework": t.framework, "control_ref": t.control_ref, "status": t.status.value} for t in f.compliance_tags]
    playbooks = [{"steps": r.steps, "priority": r.priority, "pqc_alternative": r.pqc_alternative, "detailed_report": r.detailed_report, "status": r.status} for r in f.remediation_plan]
    return {
        "finding_id": f.finding_id,
        "type": f.type.value,
        "severity": f.severity,
        "hndl_score": f.hndl_score,
        "cwe_id": f.cwe_id,
        "title": f.title,
        "description": f.description,
        "remediation": f.remediation,
        "quantum_risk": f.quantum_risk,
        "compliance_tags": tags,
        "remediation_plan": playbooks,
    }
