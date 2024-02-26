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
    assert test_user.user_id == TEST_USER_ID, "User ID should match."
    assert test_user.username == TEST_USERNAME, "Username should match."
    assert test_user.password == TEST_PASSWORD, "Password should match."
    assert len(test_user.access_token_list) == 1, "Should have one access token on creation."
    assert len(test_user.refresh_token_list) == 1, "Should have one refresh token on creation."
    assert isinstance(test_user.access_token_list[0], str), "Access token should be a string."
    assert isinstance(test_user.refresh_token_list[0], str), "Refresh token should be a string."


def test_user_login_success(test_user):
    user_id, access_token, refresh_token = test_user.login(TEST_PASSWORD)
    assert user_id == test_user.user_id, "User ID should match."
    assert isinstance(access_token, str), "Access token should be a string."
    assert isinstance(refresh_token, str), "Refresh token should be a string."
    assert access_token in test_user.access_token_list, "Access token should be added to list."
    assert refresh_token in test_user.refresh_token_list, "Refresh token should be added to list."

def test_user_login_failure(test_user):
    with pytest.raises(ValueError) as e:
        assert test_user.login("wrongpassword") is None, "Should raise ValueError for invalid password."
        assert StatusMessage.INVALID_PASSWORD.value in str(e.value), "Should raise ValueError for invalid password."

def test_validate_token_success(test_user: User):
    assert test_user.validate_token(test_user.access_token_list[0]) == 1

def test_validate_token_failure(test_user: User):
    with pytest.raises(InvalidTokenError):
        test_user.validate_token("invalidtoken")

def test_refresh_tokens_success(test_user: User):
    old_refresh_token = test_user.refresh_token_list[0]
    new_access_token, new_refresh_token = test_user.refresh_tokens(old_refresh_token)
    assert isinstance(new_access_token, str), "Access token should be a string."
    assert isinstance(new_refresh_token, str), "Refresh token should be a string."
    assert not old_refresh_token in test_user.refresh_token_list, "Old refresh token should be removed."
    assert new_access_token in test_user.access_token_list, "New access token should be added to list."

def test_refresh_tokens_failure(test_user):
    with pytest.raises(InvalidTokenError) as e:
        assert test_user.refresh_tokens("invalidtoken") is None, "Should raise InvalidTokenError for invalid token."
        assert StatusMessage.INVALID_TOKEN.value in str(e.value), "Should raise InvalidTokenError for token not matching one on record."
