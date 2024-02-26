from datetime import datetime, timezone, timedelta
from typing import Any
import jwt
import os
import dotenv
import logging

dotenv.load_dotenv()

class JWTUtils:

    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "JWT_SECRET_KEY")
    ALGORITHM = "HS256"

    DATA_SCHEMA = {
        "user_id": int,
        "username": str,
    }

    @staticmethod
    def encode(data: "dict[Any, Any]", **kwargs) -> str:
        # use the exp parameter if present, otherwise use the current time + timedelta
        payload = {
            **data,
            "exp": data.get("exp", datetime.utcnow() + timedelta(**kwargs))
        }
        token = jwt.encode(payload, JWTUtils.JWT_SECRET_KEY, algorithm=JWTUtils.ALGORITHM)
        logging.debug(token)
        return token

    @staticmethod
    def decode(token: str) -> "dict[str, Any]":
        return jwt.decode(token, JWTUtils.JWT_SECRET_KEY, algorithms=[JWTUtils.ALGORITHM])

    @staticmethod
    def to_human_readable(data: "dict[str, Any]") -> "dict[str, str]":
        return {
            "user_id": f"{data.get('user_id', 'None')}",
            "username": f"{data.get('username', 'None')}",
            "exp": datetime.utcfromtimestamp(data.get('exp', 0)).strftime("%Y-%m-%d %H:%M:%S")
        }

    @staticmethod
    def validate_jwt_data_schema(data: "dict[str, Any]") -> bool:
        is_valid = [isinstance(data.get(key), value) for key, value in JWTUtils.DATA_SCHEMA.items()]
        if not all(is_valid):
            logging.error(f"Invalid JWT data schema: {data}")

        return all(is_valid)

    @staticmethod
    def get_access_token_lifetime():
        return int(os.getenv("ACCESS_TOKEN_LIFETIME", 30))

    @staticmethod
    def get_refresh_token_lifetime():
        return int(os.getenv("REFRESH_TOKEN_LIFETIME", 30))
