"""gRPC authentication server testing"""
from datetime import datetime, timezone, timedelta
from jwt_utils import JWTUtils
from protos import auth_service_pb2, auth_service_pb2_grpc
from status import StatusMessage
import grpc
import logging
import os
import pytest

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s') # (line %(lineno)d)')

dummy_user = {
    "user_id": 0,
    "username": "dummy_username",
}

@pytest.fixture(scope="session")
def stub():
    """Create a gRPC stub fixture for testing."""
    # Set up the channel and stub here. Adjust the address and port as necessary.
    channel = grpc.insecure_channel(f"localhost:{os.environ.get('SERVER_PORT', 50051)}")
    test_stub = auth_service_pb2_grpc.AuthenticationServiceStub(channel)

    yield test_stub  # This provides the stub to your test functions.

    # Teardown code after yield
    channel.close()

def test_register_user(stub):
    user_credentials = {"username": "test_user", "password": "test_password"}
    response = stub.RegisterUser(auth_service_pb2.RegisterUserRequest(**user_credentials))

    assert response.tokens.accessToken != "", "Access token should not be empty"
    assert response.tokens.refreshToken != "", "Refresh token should not be empty"

    decoded_access_token = JWTUtils.decode(response.tokens.accessToken)
    decoded_refresh_token = JWTUtils.decode(response.tokens.refreshToken)

    assert decoded_access_token.get("username") == "test_user", "Access token username mismatch"
    assert decoded_refresh_token.get("username") == "test_user", "Refresh token username mismatch"

    logging.info("Register user test succeeded.")

def test_login_user(stub):
    user_data = {**dummy_user, "password": "test_password"}
    response = stub.LoginUser(auth_service_pb2.LoginUserRequest(**user_data))

    # Direct assertions without try-except
    assert response.tokens.accessToken != "", "Access token should not be empty"
    assert response.tokens.refreshToken != "", "Refresh token should not be empty"

    decoded_access_token = JWTUtils.decode(response.tokens.accessToken)
    decoded_refresh_token = JWTUtils.decode(response.tokens.refreshToken)

    assert decoded_access_token.get("username") == dummy_user["username"], "Access token username mismatch"
    assert decoded_refresh_token.get("username") == dummy_user["username"], "Refresh token username mismatch"
    logging.info("Login user test succeeded.")

@pytest.mark.parametrize("token_status, expected_status, expected_detail", [
    ("valid", grpc.StatusCode.OK, StatusMessage.VALIDATE_TOKEN_SUCCEEDED.value),
    ("expired", grpc.StatusCode.UNAUTHENTICATED, StatusMessage.EXPIRED_TOKEN.value),
    ("invalid", grpc.StatusCode.UNAUTHENTICATED, StatusMessage.INVALID_TOKEN.value),
])
def test_token_validation(stub, token_status, expected_status, expected_detail):
    if token_status == "valid":
        token = JWTUtils.encode(dummy_user, minutes=1)
    elif token_status == "expired":
        token = JWTUtils.encode(dummy_user, milliseconds=1)
    else:
        token = "invalid_token"

    if token_status != "valid":
        with pytest.raises(grpc.RpcError) as exc_info:
            stub.ValidateToken(auth_service_pb2.ValidateTokenRequest(user_id=dummy_user["user_id"], token=token))
        assert exc_info.value.code() == expected_status, f"Expected {expected_status} status but got: {exc_info.value.code()}"
        assert expected_detail in exc_info.value.details(), f"Expected '{expected_detail}' but got {exc_info.value.details()}"
    else:
        stub.ValidateToken(auth_service_pb2.ValidateTokenRequest(user_id=dummy_user["user_id"], token=token))
    logging.info(f"Token validation test succeeded with {token_status} token.")

@pytest.mark.parametrize("token_status, expected_status, expected_detail", [
    ("valid", grpc.StatusCode.OK, StatusMessage.REFRESH_TOKEN_SUCCEEDED.value),
    ("expired", grpc.StatusCode.UNAUTHENTICATED, StatusMessage.EXPIRED_TOKEN.value),
    ("invalid", grpc.StatusCode.UNAUTHENTICATED, StatusMessage.INVALID_TOKEN.value),
])
def test_token_refresh(stub, token_status, expected_status, expected_detail):
    if token_status == "valid":
        token = JWTUtils.encode(dummy_user, minutes=10000)
    elif token_status == "expired":
        token = JWTUtils.encode(dummy_user, milliseconds=1)
    else:  # invalid
        token = "invalid_token"

    if token_status != "valid":
        with pytest.raises(grpc.RpcError) as exc_info:
            stub.RefreshToken(auth_service_pb2.RefreshTokenRequest(user_id=dummy_user["user_id"], token=token))
        assert exc_info.value.code() == expected_status, f"Expected {expected_status} status but got: {exc_info.value.code()}"
        assert expected_detail in exc_info.value.details(), f"Expected '{expected_detail}' but got {exc_info.value.details()}"
    else:
        stub.RefreshToken(auth_service_pb2.RefreshTokenRequest(user_id=dummy_user["user_id"], token=token))
    logging.info(f"Refresh token test succeeded with {token_status} token.")
