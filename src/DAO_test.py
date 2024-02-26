import pytest
from DAO import UserDAO
from user import User
from jwt_utils import JWTUtils  # Ensure this utility is correctly implemented for token encoding/decoding
from jwt.exceptions import InvalidTokenError
from status import StatusMessage

@pytest.fixture
def user_dao():
    return UserDAO()

@pytest.fixture
def sample_user(user_dao: UserDAO):
    username = "testuser"
    password = "password"
    user_id, access_token, refresh_token = user_dao.RegisterUser(username, password)
    user = user_dao.GetUserByUsername(username)
    return user

def test_register_user(user_dao: UserDAO):
    username = "newuser"
    password = "newpass"
    user_id, access_token, refresh_token = user_dao.RegisterUser(username, password)
    assert isinstance(access_token, str), "Should return access token for newly registered user."
    assert isinstance(refresh_token, str), "Should return refresh token for newly registered user."
    assert user_id is not None, "Should return user ID for newly registered user."

def test_register_existing_user(user_dao: UserDAO, sample_user):
    with pytest.raises(ValueError) as exc_info:
        user_dao.RegisterUser(sample_user.username, "any_password")
    assert str(StatusMessage.USER_EXISTS.value) in str(exc_info.value), "Should raise ValueError for existing user."

def test_login_user_success(user_dao: UserDAO, sample_user):
    user_id, access_token, refresh_token = user_dao.LoginUser(sample_user.username, sample_user.password)
    assert isinstance(access_token, str), "Should return access token for logged in user."
    assert isinstance(refresh_token, str), "Should return refresh token for logged in user."
    assert isinstance(user_id, int), "Should return user ID for newly registered user."

def test_login_user_failure(user_dao: UserDAO):
    with pytest.raises(ValueError) as exc_info:
        user_dao.LoginUser("nonexistent", "password")
    assert str(StatusMessage.USER_NOT_FOUND.value) in str(exc_info.value), "Should raise ValueError for non-existent user."

def test_validate_token_success(user_dao: UserDAO, sample_user):
    assert user_dao.ValidateToken(sample_user.user_id, sample_user.access_token), "Token validation should succeed."

def test_validate_token_failure(user_dao: UserDAO, sample_user):
    with pytest.raises(InvalidTokenError):
        user_dao.ValidateToken(sample_user.user_id, "incorrect_token")

def test_refresh_tokens_success(user_dao: UserDAO, sample_user):
    new_tokens = user_dao.RefreshTokens(sample_user.user_id, sample_user.refresh_token)
    assert new_tokens, "Should return new tokens on refresh."

def test_refresh_tokens_failure(user_dao: UserDAO, sample_user):
    with pytest.raises(InvalidTokenError):
        user_dao.RefreshTokens(sample_user.user_id, "incorrect_token")

def test_delete_user_success(user_dao: UserDAO, sample_user):
    result = user_dao.DeleteUser(sample_user.user_id, sample_user.access_token)
    assert result, "User should be successfully deleted."

def test_delete_nonexistent_user(user_dao: UserDAO):
    with pytest.raises(ValueError) as exc_info:
        user_dao.DeleteUser(9999, "some_token")
    assert str(StatusMessage.USER_NOT_FOUND.value) in str(exc_info.value), "Should raise ValueError for non-existent user."
