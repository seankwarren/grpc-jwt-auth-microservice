from concurrent import futures
import threading
from _pytest.compat import STRING_TYPES
import grpc
import pytest
from grpc_testing import server_from_dictionary, strict_real_time
import os

from protos import auth_service_pb2, auth_service_pb2_grpc
from server import AuthenticationService, serve
import status

@pytest.fixture(scope="module", autouse=True)
def start_server():
    """Starts the gRPC server before tests are run and stops it afterward."""
    server_thread = threading.Thread(target=serve, args=(), daemon=True)
    server_thread.start()
    yield

@pytest.fixture(scope="module")
def grpc_add_to_server():
    return auth_service_pb2_grpc.add_AuthenticationServiceServicer_to_server

@pytest.fixture(scope="module")
def grpc_servicer():
    return AuthenticationService()

@pytest.fixture(scope="module")
def grpc_channel():
    channel = grpc.insecure_channel(f"localhost:{os.environ.get('SERVER_PORT', 50051)}")

    yield channel

    channel.close()

@pytest.fixture(scope="module")
def grpc_server(grpc_add_to_server, grpc_servicer):
    server = server_from_dictionary(
        {
            auth_service_pb2.DESCRIPTOR.services_by_name['AuthenticationService']: grpc_servicer
        },
        strict_real_time()
    )
    return server

@pytest.fixture(scope="module")
def grpc_stub(grpc_channel):
    return auth_service_pb2_grpc.AuthenticationServiceStub(grpc_channel)

def test_register_user(grpc_stub):
    request = auth_service_pb2.RegisterUserRequest(username="testuser", password="password")
    response = grpc_stub.RegisterUser(request)
    assert isinstance(response.tokens.accessToken, str), "Should return access token"
    assert isinstance(response.tokens.refreshToken, str), "Should return refresh token"

def test_login_user(grpc_stub):
    request = auth_service_pb2.LoginUserRequest(username="testuser", password="password")
    response = grpc_stub.LoginUser(request)
    assert isinstance(response.tokens.accessToken, str), "Should return access token"
    assert isinstance(response.tokens.refreshToken, str), "Should return refresh token"

def test_validate_token(grpc_stub):
    login_request = auth_service_pb2.LoginUserRequest(username="testuser", password="password")
    login_response = grpc_stub.LoginUser(login_request)
    access_token = login_response.tokens.accessToken
    user_id = login_response.user_id
    validate_request = auth_service_pb2.ValidateTokenRequest(user_id=user_id, token=access_token)
    validate_response = grpc_stub.ValidateToken(validate_request)

def test_validate_token_invalid(grpc_stub):
    validate_request = auth_service_pb2.ValidateTokenRequest(user_id=1, token="invalid_token")
    with pytest.raises(grpc.RpcError) as e:
        grpc_stub.ValidateToken(validate_request)
        assert e.value.code() == grpc.StatusCode.UNAUTHENTICATED, "Should return UNAUTHENTICATED status"
        assert e.value.details() == status.StatusMessage.INVALID_TOKEN.value, "Should return INVALID_TOKEN status message"

def test_refresh_token(grpc_stub):
    login_request = auth_service_pb2.LoginUserRequest(username="testuser", password="password")
    login_response = grpc_stub.LoginUser(login_request)
    refresh_token = login_response.tokens.refreshToken
    user_id = login_response.user_id
    refresh_request = auth_service_pb2.RefreshTokenRequest(user_id=user_id, token=refresh_token)
    refresh_response = grpc_stub.RefreshToken(refresh_request)
    assert isinstance(refresh_response.tokens.accessToken, str), "Access token should be a string"
    assert isinstance(refresh_response.tokens.refreshToken, str), "Refresh token should be a string"
