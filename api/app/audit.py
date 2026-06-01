# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Audit logging — explicit helper called at each write endpoint.
# Writes to the audit_log PostgreSQL table.

import json
import logging

from sqlmodel import Session, text

from app.auth import AuthContext

log = logging.getLogger(__name__)


def log_audit(
    session: Session,
    auth: AuthContext,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict | None = None,
) -> None:
    """
    Write an audit log entry to PostgreSQL.

    Called explicitly at each write endpoint — no middleware magic.
    Failures are logged but do not block the request.
    """
    try:
        session.exec(
            text(
                "INSERT INTO audit_log (user_id, email, action, resource_type, resource_id, details) "
                "VALUES (:user_id, :email, :action, :resource_type, :resource_id, :details)"
            ),
            params={
                "user_id": auth.user_id,
                "email": auth.email,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "details": json.dumps(details) if details else None,
            },
        )
        session.commit()
    except Exception as e:
        log.error("Audit log write failed: %s", e)
