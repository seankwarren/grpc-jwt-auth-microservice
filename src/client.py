import logging
from jwt_utils import JWTUtils
from datetime import datetime, timezone, timedelta
from protos import auth_service_pb2, auth_service_pb2_grpc

import grpc

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s') # (line %(lineno)d)')

def test_register_user(stub):
    logging.info("Running register user test...")
    response = stub.RegisterUser(auth_service_pb2.RegisterUserRequest(username="test_user", password="test_password"))
    assert response.success == True
    assert response.message == "User registered successfully."
    assert response.tokens.accessToken != ""
    assert response.tokens.refreshToken != ""
    decoded_access_token = JWTUtils.decode(response.tokens.accessToken)
    decoded_refresh_token = JWTUtils.decode(response.tokens.refreshToken)
    assert decoded_access_token.get("username", "None") == "test_user"
    assert decoded_refresh_token.get("username", "None") == "test_user"
    assert decoded_access_token.get("exp", -1) > 0
    assert decoded_refresh_token.get("exp", -1) > 0
    logging.info("Register user test succeeded.")

def test_login_user(stub):
    logging.info("Running login user test...")
    response = stub.LoginUser(auth_service_pb2.LoginUserRequest(username="test_user", user_id=0, password="test_password"))
    assert response.success == True
    assert response.message == "User logged in successfully."
    assert response.tokens.accessToken != ""
    assert response.tokens.refreshToken != ""
    decoded_access_token = JWTUtils.decode(response.tokens.accessToken)
    decoded_refresh_token = JWTUtils.decode(response.tokens.refreshToken)
    assert decoded_access_token.get("username", "None") == "test_user"
    assert decoded_refresh_token.get("username", "None") == "test_user"
    assert decoded_access_token.get("user_id", "None") == 0
    assert decoded_refresh_token.get("user_id", "None") == 0
    assert decoded_access_token.get("exp", -1) > 0
    assert decoded_refresh_token.get("exp", -1) > 0
    logging.info("Login user test succeeded.")

def test_validate_token(stub, token):
    logging.info("Running validate token test...")
    data = {
        "user_id": 0,
        "username": "test_user",
    }
    token = JWTUtils.encode(data, milliseconds=1)
    response = stub.ValidateToken(auth_service_pb2.ValidateTokenRequest(user_id=0, token=token))
    assert response.success == False
    assert response.message == "Token is expired."
    token = JWTUtils.encode(data, minutes=1)
    response = stub.ValidateToken(auth_service_pb2.ValidateTokenRequest(token=token))
    assert response.success == True
    assert response.message == "Token validated successfully."
    logging.info("Validate token test succeeded.")

def test_refresh_token(stub, token):
    logging.info("Running refresh token test...")
    response = stub.RefreshToken(auth_service_pb2.RefreshTokenRequest(token=token))
    assert response.success == True
    assert response.message == "Token refreshed successfully."
    token = JWTUtils.encode({"user_id": 0, "username": "test_user"}, milliseconds=1)
    response = stub.RefreshToken(auth_service_pb2.RefreshTokenRequest(token=token))
    assert response.success == False
    assert response.message == "Token is expired."
    logging.info("Refresh token test succeeded.")

def run():
    """Run the test client"""
    # Assuming the server is running on localhost at port 50051
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = auth_service_pb2_grpc.AuthenticationServiceStub(channel)

        # Test each service method
        test_register_user(stub)
        test_login_user(stub)

        jwt_data = {
            "user_id": "dummy_user_id",
            "username": "dummy_username",
            "exp": datetime.utcnow() + timedelta(milliseconds=1000)
        }

        access_token = JWTUtils.encode(jwt_data)
        refresh_token = JWTUtils.encode(jwt_data)

        test_validate_token(stub, access_token)
        test_refresh_token(stub, refresh_token)

if __name__ == '__main__':
    run()
