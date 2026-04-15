# 07 — Developer Onboarding & Contribution Guide

Welcome to the QuantumShield development team. This guide covers the repository structure, the security model, and how to get started with code contributions.

##  Repository Atlas

| Directory | Purpose |
| :--- | :--- |
| **`backend/`** | FastAPI source code and Celery tasks. |
| **`frontend/`** | React JS source code and Recharts visualizations. |
| **`nginx/`** | Reverse proxy and SSL configuration. |
| **`docs/`** | This documentation library. |
| **`scripts/`** | Helper scripts for migrations and system diagnostics. |

### Core Logic Files
- `backend/app/scanning/scanner.py`: The heart of the network analyzer.
- `backend/app/tasks/scan_tasks.py`: Orchestrates Parallel paths A/B/C.
- `backend/app/engines/`: Contains HNDL, Compliance, CBOM, and AI logic.

---

##  The RBAC Security Model

QuantumShield uses a 5-role Role-Based Access Control system (`UserRole` enum).

| Role | Access Level |
| :--- | :--- |
| **ADMIN** | Full system access, User management, Deleting scans. |
| **SECURITY_ANALYST** | Full scan visibility, Starting new scans, CBOM export. |
| **SOC_TEAM** | Priority access to Findings, Remediation playbooks, Asset inventory. |
| **COMPLIANCE_OFFICER** | Compliance heatmap, Framework mapping, Regulatory reports. |
| **MANAGEMENT** | Executive Dashboard (Read-only), Aggregate HNDL trends. |

The security is enforced via the `require_roles` dependency in FastAPI:
```python
@router.post("", summary="...")
def start_scan(current_user=Depends(require_roles(UserRole.ADMIN, UserRole.SECURITY_ANALYST))):
    ...
```

---

##  Getting Started (Development)

1. **Environment Setup**: Copy `.env.example` to `.env`.
2. **Docker Dev**: Use `docker-compose up --build`. The backend code is synced via volumes.
3. **Database Migrations**: Update `models.py` and run `python scripts/migrate_db.py`.
4. **API Testing**: Visit `http://localhost/docs` for the interactive Swagger UI.

---

*Thank you for contributing to the post-quantum security mission!*
