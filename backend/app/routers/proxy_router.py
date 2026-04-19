"""
PQC Proxy Router — Generate deployable PQC sidecar proxy configs

Provides endpoints to generate Docker + Nginx deployment packages
that wrap legacy servers in quantum-safe TLS termination.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import Asset, Certificate
from app.auth.auth import get_current_user, require_roles
from app.engines.pqc_proxy_generator import generate_proxy_config_zip
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/proxy", tags=["pqc-proxy"])


@router.get(
    "/generate/{asset_id}",
    summary="Generate PQC Proxy Config",
    description="""
Generates a deployment-ready PQC sidecar proxy configuration package for a specific asset.

Returns a **ZIP file** containing:
- `docker-compose.yml` — OQS Nginx proxy + network setup
- `nginx-pqc.conf` — TLS 1.3 termination with ML-KEM/Kyber
- `generate-pqc-cert.sh` — PQC certificate generation script
- `README.md` — Deployment instructions

The proxy acts as a **Cryptographic Bridge**: it terminates Quantum-Safe TLS (ML-KEM)
on the outside and forwards Classical TLS/HTTP to the legacy backend internally.

**Access**: ADMIN and SECURITY_ANALYST roles only.
""",
)
async def generate_proxy_config(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
):
    # Look up the asset
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Get certificate data for algorithm detection
    algorithm = None
    key_size = None
    cert = db.query(Certificate).filter(Certificate.asset_id == asset_id).first()
    if cert:
        algorithm = cert.algorithm
        key_size = cert.key_size

    # Build the open_ports list for port detection
    open_ports = asset.open_ports or []

    logger.info(
        f"Generating PQC proxy config for {asset.domain} "
        f"(algo={algorithm}, key={key_size}, hndl={asset.hndl_score})"
    )

    # Generate the ZIP
    try:
        zip_bytes = generate_proxy_config_zip(
            domain=asset.domain,
            algorithm=algorithm,
            key_size=key_size,
            hndl_score=asset.hndl_score or 0.0,
            open_ports=open_ports,
        )
    except Exception as e:
        logger.error(f"Failed to generate proxy config: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate proxy configuration")

    filename = f"pqc-proxy-{asset.domain.replace('.', '-')}.zip"

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/preview/{asset_id}",
    summary="Preview PQC Proxy Config",
    description="Returns a JSON preview of what the PQC proxy config would contain, without generating the ZIP.",
)
async def preview_proxy_config(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    cert = db.query(Certificate).filter(Certificate.asset_id == asset_id).first()
    algorithm = cert.algorithm if cert else None
    key_size = cert.key_size if cert else None

    from app.engines.pqc_proxy_generator import _get_pqc_config
    pqc = _get_pqc_config(algorithm)

    return {
        "domain": asset.domain,
        "current_algorithm": algorithm,
        "current_key_size": key_size,
        "current_hndl": asset.hndl_score,
        "pqc_replacement": {
            "kem": pqc["kem"],
            "sig": pqc["sig"],
            "nist_standard": pqc["nist"],
        },
        "estimated_post_hndl": 0.5,
        "proxy_image": "openquantumsafe/nginx:latest",
        "status": "ready_to_generate",
    }
