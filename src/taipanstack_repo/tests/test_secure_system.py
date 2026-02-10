"""Tests for the secure_system module."""

import logging
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr, ValidationError

from app.secure_system import (
    InMemoryUserRepository,
    UserCreate,
    UserCreationError,
    UserNotFoundError,
    UserRepository,
    UserService,
)
from taipanstack.core.result import Err, Ok


def test_create_user_success(caplog: pytest.LogCaptureFixture) -> None:
    """Test creating a user with valid data."""
    repository = InMemoryUserRepository()
    service = UserService(repository)
    user_create = UserCreate(
        username="valid_user",
        email="user@example.com",
        password=SecretStr("secure_password"),
        ip_address=None,
    )

    with caplog.at_level(logging.INFO):
        result = service.create_user(user_create)

    user = result.unwrap()
    assert user.username == "valid_user"
    assert user.email == "user@example.com"
    assert user.is_active is True

    # Test get_user with Result pattern
    result_get = service.get_user(user.id)
    match result_get:
        case Ok(found_user):
            assert found_user == user
        case Err():
            pytest.fail("Expected Ok but got Err")

    assert f"User created successfully: {user.id}" in caplog.text


def test_create_user_failure(caplog: pytest.LogCaptureFixture) -> None:
    """Test user creation failure handled gracefully."""

    # Mock repository to raise an error
    class FailingRepository(UserRepository):
        def save(self, user: object) -> None:
            raise ValueError("Database error")

        def get_by_id(self, user_id: UUID) -> None:
            return None

    service = UserService(FailingRepository())
    user_create = UserCreate(
        username="fail_user",
        email="fail@example.com",
        password=SecretStr("password"),
        ip_address=None,
    )

    result = service.create_user(user_create)
    match result:
        case Err(UserCreationError(message=msg)):
            assert "Database error" in msg
        case _:
            pytest.fail("Expected Err(UserCreationError)")


def test_create_user_invalid_email() -> None:
    """Test creating a user with an invalid email raises ValidationError."""
    with pytest.raises(ValidationError):
        UserCreate(
            username="valid_user",
            email="invalid-email",
            password=SecretStr("secure_password"),
        )


def test_create_user_invalid_username() -> None:
    """Test creating a user with an invalid username raises ValidationError."""
    with pytest.raises(ValidationError):
        UserCreate(
            username="invalid user name",  # Spaces not allowed
            email="user@example.com",
            password=SecretStr("secure_password"),
        )


def test_get_non_existent_user(caplog: pytest.LogCaptureFixture) -> None:
    """Test retrieving a non-existent user returns Err with UserNotFoundError."""
    repository = InMemoryUserRepository()
    service = UserService(repository)
    user_id = uuid4()

    with caplog.at_level(logging.WARNING):
        result = service.get_user(user_id)

    # Verify Result is Err
    assert result.is_err()
    match result:
        case Err(error):
            assert isinstance(error, UserNotFoundError)
            assert error.user_id == user_id
        case Ok():
            pytest.fail("Expected Err but got Ok")

    assert f"User lookup failed for ID: {user_id}" in caplog.text
