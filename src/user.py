import os

from jwt.exceptions import InvalidTokenError
from jwt_utils import JWTUtils
from status import StatusMessage

class User:
    def __init__(self, user_id: int, username: str, password: str):
        self.user_id = user_id
        self.username = username
        self.password = password
        data = self.get_jwt_data()
        self.access_token = JWTUtils.encode(data, minutes=JWTUtils.get_access_token_lifetime())
        self.refresh_token = JWTUtils.encode(data, days=JWTUtils.get_access_token_lifetime())

    def compare_password(self, password: str):
        return password == self.password

    def compare_user_id(self, user_id: int):
        return user_id == self.user_id

    def compare_access_token(self, access_token: str):
        return access_token == self.access_token

    def compare_refresh_token(self, refresh_token: str):
        return refresh_token == self.refresh_token

    def login(self, password: str):
        if not self.compare_password(password):
            raise ValueError(StatusMessage.INVALID_PASSWORD)
        return self.user_id, self.access_token, self.refresh_token

    def validate_token(self, token: str):
        decoded = JWTUtils.decode(token)
        if not self.compare_user_id(decoded["user_id"]):
            raise InvalidTokenError("User mismatch")
        if not self.compare_access_token(token):
            raise InvalidTokenError("Does not match access token on record")
        return True

    def refresh_tokens(self, token: str):
        if not self.compare_refresh_token(token):
            raise InvalidTokenError("Does not match refresh token on record")
        data = self.get_jwt_data()
        self.access_token = JWTUtils.encode(data, minutes=JWTUtils.get_access_token_lifetime())
        self.refresh_token = JWTUtils.encode(data, days=JWTUtils.get_refresh_token_lifetime())
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token
        }

    def get_jwt_data(self):
        return {
            "user_id": self.user_id,
            "username": self.username
        }

    def tokens(self):
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token
        }
