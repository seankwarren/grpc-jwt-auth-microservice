import enum

@enum.unique
class StatusMessage(enum.Enum):
    """Status message class for gRPC responses."""

    REGISTRATION_SUCCEEDED = "Registration succeeded"
    REGISTRATION_FAILED = "Registration failed"
    LOGIN_SUCCEEDED = "Login succeeded"
    LOGIN_FAILED = "Login failed"
    VALIDATE_TOKEN_SUCCEEDED = "Validate token succeeded"
    REFRESH_TOKEN_SUCCEEDED = "Refresh token succeeded"
    EXPIRED_TOKEN = "Token is expired"
    INVALID_TOKEN = "Token is invalid"
    INTERNAL_ERROR = "Internal server error"
    USER_EXISTS = "User already exists"
    USER_NOT_FOUND = "User not found"
    INVALID_PASSWORD = "Invalid password"
