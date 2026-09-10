"""
Tests for utils.py
"""

import pytest
from django.http import HttpRequest, HttpResponse
from django.urls import NoReverseMatch
from django_saml2_auth.errors import (GENERAL_EXCEPTION, INACTIVE_USER,
                                      NO_SAML_RESPONSE_FROM_CLIENT,
                                      SHOULD_NOT_CREATE_USER)
from django_saml2_auth.exceptions import SAMLAuthError
from django_saml2_auth.utils import (exception_handler, get_error_redirect_url, get_reverse,
                                     is_jwt_well_formed, run_hook)
# pytest-django renamed SettingsWrapper to Settings in 4.6; alias to keep the diff small.
from pytest_django.fixtures import Settings as SettingsWrapper  # noqa: F401


def divide(a: int, b: int = 1) -> int:
    """Simple division function for testing run_hook

    Args:
        a (int): Dividend
        b (int, optional): Divisor. Defaults to 1.

    Returns:
        int: Quotient
    """
    return int(a/b)


def hello(_: HttpRequest) -> HttpResponse:
    """Simple view function for testing exception_handler

    Args:
        _ (HttpRequest): Incoming HTTP request (not used)

    Returns:
        HttpResponse: Outgoing HTTP response
    """
    return HttpResponse(content="Hello, world!")


def goodbye(_: HttpRequest) -> None:
    """Simple view function for testing exception_handler

    Args:
        _ (HttpRequest): Incoming HTTP request (not used)

    Raises:
        SAMLAuthError: Goodbye, world!
    """
    raise SAMLAuthError("Goodbye, world!", extra={
        "exc": RuntimeError("World not found!"),
        "exc_type": RuntimeError,
        "error_code": 0,
        "reason": "Internal world error!",
        "status_code": 500
    })


def test_run_hook_success():
    """Test run_hook function against divide function imported from current module."""
    result = run_hook("django_saml2_auth.tests.test_utils.divide", 2, b=2)
    assert result == 1


def test_run_hook_no_function_path():
    """Test run_hook function by passing invalid function path and checking if it raises."""
    with pytest.raises(SAMLAuthError) as exc_info:
        run_hook("")
        run_hook(None)

    assert str(exc_info.value) == "function_path isn't specified"


def test_run_hook_nothing_to_import():
    """Test run_hook function by passing function name only (no path) and checking if it raises."""
    with pytest.raises(SAMLAuthError) as exc_info:
        run_hook("divide")

    assert str(exc_info.value) == "There's nothing to import. Check your hook's import path!"


def test_run_hook_import_error():
    """Test run_hook function by passing correct path, but nonexistent function and
    checking if it raises."""
    with pytest.raises(SAMLAuthError) as exc_info:
        run_hook("django_saml2_auth.tests.test_utils.nonexistent_divide", 2, b=2)

    assert str(exc_info.value) == (
        "module 'django_saml2_auth.tests.test_utils' has no attribute 'nonexistent_divide'")
    assert isinstance(exc_info.value.extra["exc"], AttributeError)
    assert exc_info.value.extra["exc_type"] == AttributeError


def test_run_hook_division_by_zero():
    """Test function imported by run_hook to verify if run_hook correctly captures the exception."""
    with pytest.raises(SAMLAuthError) as exc_info:
        run_hook("django_saml2_auth.tests.test_utils.divide", 2, b=0)

    assert str(exc_info.value) == "division by zero"
    # Actually a ZeroDivisionError wrapped in SAMLAuthError
    assert isinstance(exc_info.value.extra["exc"], ZeroDivisionError)
    assert exc_info.value.extra["exc_type"] == ZeroDivisionError


def test_get_reverse_success():
    """Test get_reverse with existing view."""
    result = get_reverse("acs")
    assert result == "/acs/"


def test_get_reverse_no_reverse_match():
    """Test get_reverse with nonexistent view."""
    with pytest.raises(SAMLAuthError) as exc_info:
        get_reverse("nonexistent_view")

    assert str(exc_info.value) == "We got a URL reverse issue: ['nonexistent_view']"
    assert issubclass(exc_info.value.extra["exc_type"], NoReverseMatch)


def test_exception_handler_success():
    """Test exception_handler decorator with a normal view function that returns response."""
    decorated_hello = exception_handler(hello)
    result = decorated_hello(HttpRequest())
    assert result.content.decode("utf-8") == "Hello, world!"


def test_exception_handler_handle_exception():
    """Test exception_handler decorator with a view function that raises exception and see if the
    exception_handler catches and returns the correct errors response."""
    decorated_goodbye = exception_handler(goodbye)
    result = decorated_goodbye(HttpRequest())
    contents = result.content.decode("utf-8")
    assert result.status_code == 500
    assert "Reason: Internal world error!" in contents


def test_jwt_well_formed():
    """Test if passed RelayState is a well formed JWT"""
    token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MjQyIiwibmFtZSI6Ikplc3NpY2EgVGVtcG9yYWwiLCJuaWNrbmFtZSI6Ikplc3MifQ.EDkUUxaM439gWLsQ8a8mJWIvQtgZe0et3O3z4Fd_J8o'  # noqa
    res = is_jwt_well_formed(token)  # True
    assert res is True
    res = is_jwt_well_formed('/')  # False
    assert res is False


def test_get_error_redirect_url_no_mapping_for_error_code(settings: "SettingsWrapper"):
    """Test get_error_redirect_url with an error code that is never redirected."""
    settings.SAML2_AUTH["ERROR_REDIRECTS"] = {"NO_METADATA": "/login/sso/"}
    exc = SAMLAuthError("Boom", extra={"error_code": GENERAL_EXCEPTION})
    assert get_error_redirect_url(exc) is None


def test_get_error_redirect_url_unconfigured_key_keeps_error_page(settings: "SettingsWrapper"):
    """Test get_error_redirect_url leaves the error page in place when the key is unset."""
    settings.SAML2_AUTH["ERROR_REDIRECTS"] = {}
    exc = SAMLAuthError("Inactive", extra={"error_code": INACTIVE_USER})
    assert get_error_redirect_url(exc) is None


def test_get_error_redirect_url_uses_path_as_given(settings: "SettingsWrapper"):
    """Test get_error_redirect_url passes a path or absolute URL through untouched."""
    settings.SAML2_AUTH["ERROR_REDIRECTS"] = {
        "USER_NOT_FOUND": "/login/?sso_login_no_user=true"}
    exc = SAMLAuthError("Cannot create user.", extra={"error_code": SHOULD_NOT_CREATE_USER})
    assert get_error_redirect_url(exc) == "/login/?sso_login_no_user=true"


def test_get_error_redirect_url_reverses_a_url_name(settings: "SettingsWrapper"):
    """Test get_error_redirect_url reverses a value that is a URL pattern name."""
    settings.SAML2_AUTH["ERROR_REDIRECTS"] = {"NO_SAML_RESPONSE": "denied"}
    exc = SAMLAuthError("No response", extra={"error_code": NO_SAML_RESPONSE_FROM_CLIENT})
    assert get_error_redirect_url(exc) == "/denied/"


def test_get_error_redirect_url_unreversible_name_keeps_error_page(settings: "SettingsWrapper"):
    """Test get_error_redirect_url falls back to the error page for an unknown URL name."""
    settings.SAML2_AUTH["ERROR_REDIRECTS"] = {"NO_SAML_RESPONSE": "nonexistent_view"}
    exc = SAMLAuthError("No response", extra={"error_code": NO_SAML_RESPONSE_FROM_CLIENT})
    assert get_error_redirect_url(exc) is None


def test_get_error_redirect_url_ignores_a_plain_exception():
    """Test get_error_redirect_url ignores anything that is not a SAMLAuthError."""
    assert get_error_redirect_url(RuntimeError("Boom")) is None


def redirect_me(_: HttpRequest) -> HttpResponse:
    """Simple view function raising a redirectable SAMLAuthError.

    Args:
        _ (HttpRequest): Incoming HTTP request (not used)

    Raises:
        SAMLAuthError: The target user is inactive.
    """
    raise SAMLAuthError("The target user is inactive.", extra={
        "exc_type": Exception,
        "error_code": INACTIVE_USER,
        "reason": "User is inactive.",
        "status_code": 500
    })


def test_exception_handler_redirects_a_recoverable_failure(settings: "SettingsWrapper"):
    """Test exception_handler redirects instead of rendering the error page when configured."""
    settings.SAML2_AUTH["ERROR_REDIRECTS"] = {"INACTIVE_USER": "denied"}
    decorated_redirect_me = exception_handler(redirect_me)
    result = decorated_redirect_me(HttpRequest())
    assert result.status_code == 302
    assert result["Location"] == "/denied/"
