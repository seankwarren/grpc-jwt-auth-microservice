"""gRPC authentication server"""
from concurrent import futures
from datetime import timedelta
from dotenv import load_dotenv
from jwt.exceptions import ExpiredSignatureError
import grpc
import jwt
import logging
import os

from protos import auth_service_pb2, auth_service_pb2_grpc
from jwt_utils import JWTUtils

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s') # (line %(lineno)d)')

MAX_WORKERS = 10

class AuthenticationService(auth_service_pb2_grpc.AuthenticationServiceServicer):
    """gRPC authentication service implementation."""

    ACCESS_TOKEN_LIFETIME = int(os.getenv("ACCESS_TOKEN_LIFETIME", 30))  # minutes
    REFRESH_TOKEN_LIFETIME = int(os.getenv("REFRESH_TOKEN_LIFETIME", 30))  # days

    def __init__(self):
        self.num_users = 0

    def RegisterUser(self, request, context):
        """
        Registers a new user.

        Args:
            request (authentication_service_pb2.RegisterUserRequest): The incoming request object with the username and password
            context (grpc.ServicerContext): The context of the current RPC call

        Returns:
            authentication_service_pb2.RegisterUserResponse: The response object with access and refresh tokens
        """
        logging.info("RegisterUser endpoint called.")
        logging.debug(f"Request: {request}")

        try:
            # Generate new tokens
            data = {"user_id": self.num_users, "username": request.username}
            logging.debug(data)
            access_token = JWTUtils.encode(data, minutes=self.ACCESS_TOKEN_LIFETIME)
            refresh_token = JWTUtils.encode(data, days=self.REFRESH_TOKEN_LIFETIME)

            # Build response object
            response = auth_service_pb2.RegisterUserResponse(
                success=True,
                tokens=auth_service_pb2.AuthTokens(
                    accessToken=access_token,
                    refreshToken=refresh_token,
                ),
                message="User registered successfully.",
            )

            logging.debug(f"Response: {response}")
            self.num_users += 1
            return response

        except Exception as e:
            logging.error(f"Error occurred: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('Internal server error occurred while registering user.')
            return auth_service_pb2.RegisterUserResponse(success=False, message='Failed to register user.')

    def LoginUser(self, request, context):
        """
        Logs in a user and generates new access and refresh tokens.

        Args:
            request (authentication_service_pb2.LoginUserRequest): The request object with the username and password
            context (grpc.ServicerContext): The context of the current RPC call

        Returns:
            authentication_service_pb2.LoginUserResponse: The response object with access and refresh tokens
        """
        logging.info("LoginUser endpoint called.")
        logging.debug(f"Request: {request} ")

        try:
            # Generate new tokens
            data = {"user_id": request.user_id, "username": request.username}
            # TODO: user_id above should not be coming from the request or from the token, but from the database
            access_token = JWTUtils.encode(data, minutes=self.ACCESS_TOKEN_LIFETIME)
            refresh_token = JWTUtils.encode(data, days=self.REFRESH_TOKEN_LIFETIME)

            # Build response object
            response = auth_service_pb2.LoginUserResponse(
                success=True,
                tokens=auth_service_pb2.AuthTokens(
                    accessToken=access_token,
                    refreshToken=refresh_token,
                ),
                message="User logged in successfully.",
            )

            logging.debug(f"Response: {response}")
            return response

        except Exception as e:
            logging.error(f"Error occurred: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('Internal server error occurred while logging in user.')
            return auth_service_pb2.LoginUserResponse(success=False, message='Failed to login user.')

    def ValidateToken(self, request, context):
        """
        Validates a token.

        Args:
            request (authentication_service_pb2.ValidateTokenRequest): The request object with the token to validate, and the user requesting validation
            context (grpc.ServicerContext): The context of the current RPC call

        Returns:
            authentication_service_pb2.ValidateTokenResponse: The response object indicating whether the token is valid or expired
        """
        logging.info("ValidateToken endpoint called.")
        logging.debug(f"Request: {request}")
        try:
            # Decode and validate the token
            decoded_token = JWTUtils.decode(request.token)
            logging.debug(f"Decoded token: {decoded_token}")
            logging.debug(f"User ID: {request.user_id}")

            # Verify that the user_id in the token matches the user_id in the request
            user_id = decoded_token.get("user_id", "None")
            if (decoded_token.get("user_id") != request.user_id):
                raise Exception("Invalid token")

            # Build response object
            response = auth_service_pb2.ValidateTokenResponse(
                success=True,
                message="Token validated successfully.",
            )

            logging.debug(f"Response: {response}")
            return response

        except ExpiredSignatureError:
            return auth_service_pb2.ValidateTokenResponse(
                success=False,
                message="Token is expired.",
            )

        except Exception as e:
            logging.error("Token validation failed: %s", e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('Internal server error occurred while validating token.')
            return auth_service_pb2.ValidateTokenResponse(success=False, message='Failed to validate token.')

    def RefreshToken(self, request, context):
        """
        Refreshes a token.

        Args:
            request (authentication_service_pb2.RefreshTokenRequest): The request object with the token to refresh and the user requesting the refresh
            context (grpc.ServicerContext): The context of the current RPC call

        Returns:
            authentication_service_pb2.RefreshTokenResponse: The response object with the refreshed access and refresh tokens
        """
        logging.info("RefreshToken endpoint called.")
        logging.debug(f"Request: {request}")
        try:
            # Decode and validate the token
            decoded_token = JWTUtils.decode(request.token)
            # Verify that the user_id in the token matches the user_id in the request
            username = decoded_token.get("username", "None")
            user_id = decoded_token.get("user_id", "None")
            if (decoded_token.get("user_id") != user_id):
                raise Exception("Invalid token: user_id in token does not match user_id in request.")

            # Generate new tokens
            data = {"user_id": user_id, "username": username}
            access_token = JWTUtils.encode(data, minutes=self.ACCESS_TOKEN_LIFETIME)
            refresh_token = JWTUtils.encode(data, days=self.REFRESH_TOKEN_LIFETIME)

            # Build response object
            response = auth_service_pb2.RefreshTokenResponse(
                success=True,
                tokens=auth_service_pb2.AuthTokens(
                    accessToken=access_token,
                    refreshToken=refresh_token,
                ),
                message="Token refreshed successfully.",
            )

            logging.debug(f"Response: {response}")
            return response

        except ExpiredSignatureError:
            return auth_service_pb2.RefreshTokenResponse(success=False, message="Token is expired.")

        except Exception as e:
            logging.error("Token refresh failed: %s", e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('Internal server error occurred while refreshing token.')
            return auth_service_pb2.RefreshTokenResponse(success=False, message="Token refresh failed.")

def serve():
    service = AuthenticationService()
    port = 50051
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=MAX_WORKERS))
    auth_service_pb2_grpc.add_AuthenticationServiceServicer_to_server(service, server)

    server_address = f'[::]:{port}'
    server.add_insecure_port(server_address)
    logging.info(f'Starting server on {server_address}')
    server.start()

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logging.info('Shutting down server')
        server.stop(0)

if __name__ == '__main__':
    serve()
