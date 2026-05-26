class AuditLogError(Exception):
    """Base exception for the audit log package."""


class AppendOnlyViolationError(AuditLogError):
    """Raised when an attempt to update or delete a stored record is made."""


class TamperDetectedError(AuditLogError):
    """Raised when hash chain verification finds a broken link."""


class WriterSignatureMismatchError(AuditLogError):
    """Raised when the stored writer_signature_hash does not match the recomputed value."""


class UnknownEventTypeError(AuditLogError, ValueError):
    """Raised when event_type is not in the closed enumeration from event_types.json."""
