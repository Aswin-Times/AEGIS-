class AegisError(Exception):
    """An error safe to show to callers. Anything else becomes a generic 500."""

    status_code = 500
    code = "INTERNAL_ERROR"
    message = "An internal error occurred."

    def __init__(self, message: str | None = None, code: str | None = None) -> None:
        super().__init__(message or self.message)
        self.message = message or self.message
        self.code = code or self.code


class Unauthenticated(AegisError):
    status_code = 401
    code = "UNAUTHENTICATED"
    message = "Authentication failed."


class Forbidden(AegisError):
    status_code = 403
    code = "FORBIDDEN"
    message = "You do not have permission to perform this action."


class NotFound(AegisError):
    status_code = 404
    code = "NOT_FOUND"
    message = "The requested item was not found."


class Conflict(AegisError):
    status_code = 409
    code = "CONFLICT"
    message = "The request conflicts with the current state."


class ValidationFailed(AegisError):
    status_code = 422
    code = "VALIDATION_ERROR"
    message = "The request is not valid."


class ServiceUnavailable(AegisError):
    status_code = 503
    code = "SERVICE_UNAVAILABLE"
    message = "The service is temporarily unavailable. The action was not performed."
