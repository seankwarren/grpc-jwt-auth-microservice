"""gRPC authentication server"""
from concurrent import futures
from datetime import timedelta
from dotenv import load_dotenv
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from DAO import UserDAO
from jwt_utils import JWTUtils
from protos import auth_service_pb2, auth_service_pb2_grpc
from status import StatusMessage
import grpc
import jwt
import logging
import os

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s') # (line %(lineno)d)')
MAX_WORKERS = 10

class AuthenticationService(auth_service_pb2_grpc.AuthenticationServiceServicer):
    """gRPC authentication service implementation."""

    ACCESS_TOKEN_LIFETIME = int(os.getenv("ACCESS_TOKEN_LIFETIME", 30))  # minutes
    REFRESH_TOKEN_LIFETIME = int(os.getenv("REFRESH_TOKEN_LIFETIME", 30))  # days

    def __init__(self):
        self.dao = UserDAO()
        pass

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
        try:
            user_id, access_token, refresh_token = self.dao.RegisterUser(request.username, request.password)
            response = auth_service_pb2.RegisterUserResponse(
                user_id=user_id,
                tokens=auth_service_pb2.AuthTokens(
                    accessToken=access_token,
                    refreshToken=refresh_token,
                ),
            )
            return response
        except Exception as e:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"{StatusMessage.REGISTRATION_FAILED}: {e}")
            logging.error(f"{StatusMessage.REGISTRATION_FAILED}: {e}")
            return auth_service_pb2.RegisterUserResponse()

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
        try:
            user_id, access_token, refresh_token = self.dao.LoginUser(request.username, request.password)
            response = auth_service_pb2.LoginUserResponse(
                user_id=user_id,
                tokens=auth_service_pb2.AuthTokens(
                    accessToken=access_token,
                    refreshToken=refresh_token,
                ),
            )
            return response
        except Exception as e:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"{StatusMessage.LOGIN_FAILED.value}: {e}")
            logging.error(f"{StatusMessage.LOGIN_FAILED.value}: {e}")
            return auth_service_pb2.LoginUserResponse()

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
        try:
            success = self.dao.ValidateToken(request.user_id, request.token)
            if not success:
                raise InvalidTokenError("ValidateToken failed.")
            decoded_token = JWTUtils.decode(request.token)
            user_id = decoded_token.get("user_id", "None")
            # Verify that the user in the token matches the user in the request
            if user_id != request.user_id:
                logging.info("User in token does not match the user in the request.")
                raise InvalidTokenError("User in token does not match the user in the request.")
            context.set_code(grpc.StatusCode.OK)
            context.set_details(StatusMessage.VALIDATE_TOKEN_SUCCEEDED.value)
            logging.info(StatusMessage.VALIDATE_TOKEN_SUCCEEDED.value)
        except ExpiredSignatureError as e:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details(StatusMessage.EXPIRED_TOKEN.value)
            logging.info(f"{StatusMessage.EXPIRED_TOKEN}: {e}")
        except InvalidTokenError as e:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details(StatusMessage.INVALID_TOKEN.value)
            print(e.args)
            logging.info(f"{StatusMessage.INVALID_TOKEN}: {e.args[0]}")
        except Exception as e:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(StatusMessage.INTERNAL_ERROR.value)
            logging.info(f"{StatusMessage.INTERNAL_ERROR}: {e}")
        finally:
            # Return response
            return auth_service_pb2.ValidateTokenResponse()

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
        try:
            decoded_token = JWTUtils.decode(request.token)
            username = decoded_token.get("username", "None")
            user_id = decoded_token.get("user_id", "None")
            # Verify that the user_id in the token matches the user_id in the request
            if (user_id != request.user_id):
                raise InvalidTokenError("User in token does not match the user in the request.")
            # Generate new tokens using user data extracted from token
            data = {"user_id": user_id, "username": username}
            access_token = JWTUtils.encode(data, minutes=self.ACCESS_TOKEN_LIFETIME)
            refresh_token = JWTUtils.encode(data, days=self.REFRESH_TOKEN_LIFETIME)
            # Return the new tokens
            response = auth_service_pb2.RefreshTokenResponse(
                tokens=auth_service_pb2.AuthTokens(
                    accessToken=access_token,
                    refreshToken=refresh_token,
                ),
            )
            context.set_code(grpc.StatusCode.OK)
            context.set_details(StatusMessage.REFRESH_TOKEN_SUCCEEDED.value)
            return response
        except ExpiredSignatureError:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details(StatusMessage.EXPIRED_TOKEN.value)
            return auth_service_pb2.RefreshTokenResponse()
        except InvalidTokenError:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details(StatusMessage.INVALID_TOKEN.value)
            return auth_service_pb2.RefreshTokenResponse()
        except Exception as e:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"{StatusMessage.INTERNAL_ERROR.value}: {e}")
            return auth_service_pb2.RefreshTokenResponse()


def serve():
    service = AuthenticationService()
    port = os.getenv('SERVER_PORT', 50051)
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
