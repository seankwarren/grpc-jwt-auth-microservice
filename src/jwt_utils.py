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
        """
        Encodes a dict into a JWT token.

        Args:
            data (dict): The user_id to encode into the token

        Returns:
            str: The JWT token
        """
        # logging.debug(data)
        # is_valid = JWTUtils.validate_jwt_data_schema(data)
        # logging.debug(f"JWT data schema is {'valid' if is_valid else 'invalid'}")

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
        """
        Decodes a JWT token.

        Args:
            token (str): The JWT token to decode

        Returns:
            dict: The decoded token
        """
        return jwt.decode(token, JWTUtils.JWT_SECRET_KEY, algorithms=[JWTUtils.ALGORITHM])

    @staticmethod
    def to_human_readable(data: "dict[str, Any]") -> "dict[str, str]":
        """
        Converts JWT token data into a human-readable format based on the defined schema.

        Args:
            data (dict): The JWT token to convert

        Returns:
            dict: The human-readable token
        """
        return {
            "user_id": f"{data.get('user_id', 'None')}",
            "username": f"{data.get('username', 'None')}",
            "exp": datetime.utcfromtimestamp(data.get('exp', 0)).strftime("%Y-%m-%d %H:%M:%S")
        }

    @staticmethod
    def validate_jwt_data_schema(data: "dict[str, Any]") -> bool:
        """
        Validates the schema of the decoded JWT token.

        Args:
            data (dict): The decoded JWT token

        Returns:
            bool: True if the schema is valid, False otherwise
        """
        is_valid = [isinstance(data.get(key), value) for key, value in JWTUtils.DATA_SCHEMA.items()]
        if not all(is_valid):
            logging.error(f"Invalid JWT data schema: {data}")

        return all(is_valid)
