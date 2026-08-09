from functools import wraps
from typing import Any, Dict, Optional

from wafinstaller.models import AuditEntry


def _client_ip(request) -> Optional[str]:
    value = request.META.get("REMOTE_ADDR")
    return value if value else None


def record_audit(
    request,
    *,
    action: str,
    outcome: str,
    target: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Record non-secret metadata for a security-sensitive operation."""
    actor = request.user if getattr(request.user, "is_authenticated", False) else None
    AuditEntry.objects.create(
        actor=actor,
        action=action,
        target=(target or request.path)[:500],
        outcome=outcome,
        remote_addr=_client_ip(request),
        details=details or {},
    )


def mark_audit_failure(request) -> None:
    request._wafcontrol_audit_failed = True


def audit_mutation(action):
    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            try:
                response = view(request, *args, **kwargs)
            except Exception as exc:
                record_audit(
                    request,
                    action=action,
                    outcome=AuditEntry.Outcome.FAILED,
                    details={"error_type": type(exc).__name__},
                )
                raise
            record_audit(
                request,
                action=action,
                outcome=(
                    AuditEntry.Outcome.FAILED
                    if response.status_code >= 400
                    or not getattr(request.user, "is_authenticated", False)
                    or getattr(request, "_wafcontrol_audit_failed", False)
                    else AuditEntry.Outcome.SUCCEEDED
                ),
                details={"status_code": response.status_code},
            )
            return response

        return wrapper

    return decorator


class AuditedMutationMixin:
    """Record every unsafe request reaching an authenticated class-based view."""

    audit_action = "security.mutation"

    def dispatch(self, request, *args, **kwargs):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            try:
                response = super().dispatch(request, *args, **kwargs)
            except Exception as exc:
                record_audit(
                    request,
                    action=self.audit_action,
                    outcome=AuditEntry.Outcome.FAILED,
                    details={"error_type": type(exc).__name__},
                )
                raise
            record_audit(
                request,
                action=self.audit_action,
                outcome=(
                    AuditEntry.Outcome.FAILED
                    if response.status_code >= 400
                    or not getattr(request.user, "is_authenticated", False)
                    or getattr(request, "_wafcontrol_audit_failed", False)
                    else AuditEntry.Outcome.SUCCEEDED
                ),
                details={"status_code": response.status_code},
            )
            return response
        return super().dispatch(request, *args, **kwargs)
