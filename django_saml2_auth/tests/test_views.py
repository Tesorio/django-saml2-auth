"""
Tests for views.py
"""

from copy import deepcopy
from typing import Any, Dict, List, Optional

import pytest
import responses
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client
from django_saml2_auth.tests.test_saml import (
    METADATA1,
    METADATA_URL1,
    get_user_identity,
    mock_parse_authn_request_response,
)

# pytest-django renamed SettingsWrapper to Settings in 4.6; alias to keep the diff small.
from pytest_django.fixtures import Settings as SettingsWrapper
from saml2.client import Saml2Client


BEFORE_LOGIN_CALLS: List[Any] = []


def record_before_login(user_identity: Any) -> None:
    """BEFORE_LOGIN trigger that records whatever it was handed.

    Args:
        user_identity (Any): Whatever the acs view passes to the trigger
    """
    BEFORE_LOGIN_CALLS.append(user_identity)


@pytest.fixture(autouse=True)
def clear_before_login_calls():
    """Empty the BEFORE_LOGIN recorder so one test cannot see another's call."""
    BEFORE_LOGIN_CALLS.clear()
    yield
    BEFORE_LOGIN_CALLS.clear()


def saml2_auth_settings(**overrides: Any) -> Dict[str, Any]:
    """Build a SAML2_AUTH dict for an acs request, with the given top-level overrides.

    The settings fixture only restores top-level attributes, so the nested dicts are deep
    copied rather than mutated in place.

    Args:
        **overrides: Top-level SAML2_AUTH keys to set

    Returns:
        Dict[str, Any]: A SAML2_AUTH settings dict
    """
    saml2_settings: Dict[str, Any] = deepcopy(settings.SAML2_AUTH)
    saml2_settings["TRIGGER"]["GET_METADATA_AUTO_CONF_URLS"] = (
        "django_saml2_auth.tests.test_saml.get_metadata_auto_conf_urls"
    )
    # The shipped test settings name a BEFORE_LOGIN function that does not exist.
    saml2_settings["TRIGGER"]["BEFORE_LOGIN"] = (
        "django_saml2_auth.tests.test_views.record_before_login"
    )
    saml2_settings["USE_JWT"] = False
    saml2_settings.update(overrides)
    return saml2_settings


def post_assertion(monkeypatch: Any, client: Optional[Client] = None) -> Any:
    """POST a (mocked) valid SAML assertion to the acs endpoint.

    Args:
        monkeypatch (MonkeyPatch): PyTest monkeypatch fixture
        client (Client, optional): Client to post with, so the caller can inspect the session
            it is left holding. Defaults to a throwaway client.

    Returns:
        HttpResponse: The acs response
    """
    responses.add(responses.GET, METADATA_URL1, body=METADATA1)
    monkeypatch.setattr(
        Saml2Client, "parse_authn_request_response", mock_parse_authn_request_response
    )
    return (client or Client()).post("/acs/", {"SAMLResponse": "SAML RESPONSE"})


@responses.activate
@pytest.mark.django_db
def test_acs_before_login_trigger_gets_the_raw_saml_identity(
    settings: SettingsWrapper, monkeypatch: Any
):
    """Test acs hands BEFORE_LOGIN the identity keyed by SAML attribute name.

    Args:
        settings (SettingsWrapper): Fixture for django settings
        monkeypatch (MonkeyPatch): PyTest monkeypatch fixture
    """
    settings.SAML2_AUTH = saml2_auth_settings()
    User.objects.create_user("test@example.com", "test@example.com")

    response = post_assertion(monkeypatch)

    assert response.status_code == 302
    assert BEFORE_LOGIN_CALLS == [get_user_identity()]


@responses.activate
@pytest.mark.django_db
def test_acs_finds_the_user_by_user_lookup_field(
    settings: SettingsWrapper, monkeypatch: Any
):
    """Test acs logs in a user whose username has nothing to do with the asserted email.

    Args:
        settings (SettingsWrapper): Fixture for django settings
        monkeypatch (MonkeyPatch): PyTest monkeypatch fixture
    """
    settings.SAML2_AUTH = saml2_auth_settings(
        USER_LOOKUP_FIELD="email", CREATE_USER=False
    )
    target_user = User.objects.create_user("local_handle", "test@example.com")
    client = Client()

    response = post_assertion(monkeypatch, client)

    assert response.status_code == 302
    assert client.session["_auth_user_id"] == str(target_user.pk)
    assert User.objects.count() == 1


@responses.activate
@pytest.mark.django_db
def test_acs_redirects_when_the_user_should_not_be_created(
    settings: SettingsWrapper, monkeypatch: Any
):
    """Test acs redirects rather than rendering the error page for an unknown user.

    Args:
        settings (SettingsWrapper): Fixture for django settings
        monkeypatch (MonkeyPatch): PyTest monkeypatch fixture
    """
    settings.SAML2_AUTH = saml2_auth_settings(
        CREATE_USER=False,
        ERROR_REDIRECTS={"USER_NOT_FOUND": "/login/?sso_login_no_user=true"},
    )

    response = post_assertion(monkeypatch)

    assert response.status_code == 302
    assert response["Location"] == "/login/?sso_login_no_user=true"
    assert User.objects.count() == 0


@responses.activate
@pytest.mark.django_db
def test_acs_renders_the_error_page_when_no_redirect_is_configured(
    settings: SettingsWrapper, monkeypatch: Any
):
    """Test acs keeps the upstream error page when ERROR_REDIRECTS is unset.

    Args:
        settings (SettingsWrapper): Fixture for django settings
        monkeypatch (MonkeyPatch): PyTest monkeypatch fixture
    """
    settings.SAML2_AUTH = saml2_auth_settings(CREATE_USER=False)

    response = post_assertion(monkeypatch)

    assert response.status_code == 500


@responses.activate
@pytest.mark.django_db
def test_acs_redirects_when_the_target_user_is_inactive(
    settings: SettingsWrapper, monkeypatch: Any
):
    """Test acs redirects rather than rendering the error page for an inactive user.

    Args:
        settings (SettingsWrapper): Fixture for django settings
        monkeypatch (MonkeyPatch): PyTest monkeypatch fixture
    """
    settings.SAML2_AUTH = saml2_auth_settings(
        USER_LOOKUP_FIELD="email",
        CREATE_USER=False,
        ERROR_REDIRECTS={"INACTIVE_USER": "denied"},
    )
    User.objects.create_user("local_handle", "test@example.com", is_active=False)

    response = post_assertion(monkeypatch)

    assert response.status_code == 302
    assert response["Location"] == "/denied/"


@pytest.mark.django_db
def test_acs_redirects_when_there_is_no_saml_response(settings: SettingsWrapper):
    """Test acs redirects rather than rendering the error page for an empty POST.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = saml2_auth_settings(
        ERROR_REDIRECTS={"NO_SAML_RESPONSE": "denied"}
    )

    response = Client().post("/acs/", {})

    assert response.status_code == 302
    assert response["Location"] == "/denied/"


@pytest.mark.django_db
def test_acs_redirects_when_the_request_carries_no_metadata(settings: SettingsWrapper):
    """Test acs redirects to the SSO login when the request identifies no tenant.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    saml2_settings = saml2_auth_settings(ERROR_REDIRECTS={"NO_METADATA": "/login/sso/"})
    saml2_settings["TRIGGER"]["GET_METADATA_FROM_REQUEST"] = (
        "django_saml2_auth.tests.test_saml.get_metadata_from_request"
    )
    settings.SAML2_AUTH = saml2_settings

    response = Client().post("/acs/", {"SAMLResponse": "SAML RESPONSE"})

    assert response.status_code == 302
    assert response["Location"] == "/login/sso/"
