import pytest
from jwt.exceptions import InvalidTokenError
from status import StatusMessage
from user import User
from jwt_utils import JWTUtils

TEST_USER_ID = 1
TEST_USERNAME = "testuser"
TEST_PASSWORD = "password123"
@pytest.fixture
def test_user() -> User:
    return User(TEST_USER_ID, TEST_USERNAME, TEST_PASSWORD)

def test_user_creation(test_user):
    assert test_user.user_id == TEST_USER_ID
    assert test_user.username == TEST_USERNAME
    assert test_user.password == TEST_PASSWORD
    assert test_user.access_token is not None
    assert test_user.refresh_token is not None

def test_user_login_success(test_user):
    user_id, access_token, refresh_token = test_user.login(TEST_PASSWORD)
    assert user_id == test_user.user_id
    assert access_token is not None
    assert refresh_token is not None
    assert access_token == test_user.access_token
    assert refresh_token == test_user.refresh_token

def test_user_login_failure(test_user):
    with pytest.raises(ValueError) as e:
        assert test_user.login("wrongpassword") is None
        assert StatusMessage.INVALID_PASSWORD.value in str(e.value), "Should raise ValueError for invalid password."

def test_validate_token_success(test_user):
    assert test_user.validate_token(test_user.access_token) == 1

def test_validate_token_failure(test_user):
    with pytest.raises(InvalidTokenError):
        test_user.validate_token("invalidtoken")

def test_refresh_tokens_success(test_user):
    new_access_token, new_refresh_token = test_user.refresh_tokens(test_user.refresh_token)
    assert new_access_token is not None
    assert new_refresh_token is not None
    assert new_access_token != test_user.access_token
    assert new_refresh_token != test_user.refresh_token

def test_refresh_tokens_failure(test_user):
    with pytest.raises(InvalidTokenError) as e:
        assert test_user.refresh_tokens("invalidtoken") is None
        assert StatusMessage.INVALID_TOKEN.value in str(e.value), "Should raise InvalidTokenError for token not matching one on record."
