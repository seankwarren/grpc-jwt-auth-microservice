import logging

from jwt.exceptions import InvalidTokenError
from status import StatusMessage
from user import User


class UserDAO:
    def __init__(self, initial_users: list[User] = []):
        self.users: list[User] = initial_users

    def GetUserById(self, user_id: int):
        for user in self.users:
            if user.user_id == user_id:
                return user
        logging.debug(StatusMessage.USER_NOT_FOUND)
        return None

    def GetUserByUsername(self, username: str):
        for user in self.users:
            if user.username == username:
                return user
        logging.debug(StatusMessage.USER_NOT_FOUND)
        return None

    def RegisterUser(self, username: str, password: str):
        user_id = len(self.users)
        user = self.GetUserByUsername(username)
        if user is not None:
            logging.debug(StatusMessage.USER_EXISTS.value)
            raise ValueError(StatusMessage.USER_EXISTS.value)
        user = User(user_id, username, password)
        self.users.append(user)
        return user.user_id, user.access_token_list[0], user.refresh_token_list[0]

    def LoginUser(self, username: str, password: str):
        user = self.GetUserByUsername(username)
        if user is None:
            logging.debug(StatusMessage.USER_NOT_FOUND.value)
            raise ValueError(StatusMessage.USER_NOT_FOUND.value)
        return user.login(password)

    def ValidateToken(self, user_id: int, token: str):
        user = self.GetUserById(user_id)
        if user is None:
            logging.debug(StatusMessage.USER_NOT_FOUND.value)
            raise ValueError(StatusMessage.USER_NOT_FOUND.value)
        return user.validate_token(token)

    def RefreshTokens(self, user_id: int, token: str):
        user = self.GetUserById(user_id)
        if user is None:
            logging.debug(StatusMessage.USER_NOT_FOUND.value)
            raise ValueError(StatusMessage.USER_NOT_FOUND.value)
        return user.refresh_tokens(token)

    def DeleteUser(self, user_id: int, token: str):
        user = self.GetUserById(user_id)
        if user is None:
            logging.debug(StatusMessage.USER_NOT_FOUND.value)
            raise ValueError(StatusMessage.USER_NOT_FOUND.value)
        if not user.compare_access_token(token):
            logging.debug(StatusMessage.INVALID_TOKEN.value)
            raise InvalidTokenError(StatusMessage.INVALID_TOKEN.value)
        self.users.remove(user)
        return True
