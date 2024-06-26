#!/usr/bin/env python

import logging

from django import get_version
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template import TemplateDoesNotExist
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import csrf_exempt
from pkg_resources import parse_version
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

# default User or custom User. Now both will work.
User = get_user_model()

logger = logging.getLogger(__name__)

if parse_version(get_version()) >= parse_version("1.7"):
    from django.utils.module_loading import import_string
else:
    from django.utils.module_loading import import_by_path as import_string


def get_current_domain(r):
    if "ASSERTION_URL" in settings.SAML2_AUTH:
        return settings.SAML2_AUTH["ASSERTION_URL"]
    return "{scheme}://{host}".format(
        scheme="https" if r.is_secure() else "http",
        host=r.get_host(),
    )


def get_reverse(objs):
    """In order to support different django version, I have to do this"""
    if parse_version(get_version()) >= parse_version("2.0"):
        from django.urls import reverse
    else:
        from django.urls import reverse
    if objs.__class__.__name__ not in ["list", "tuple"]:
        objs = [objs]

    for obj in objs:
        try:
            return reverse(obj)
        except:
            pass
    raise Exception(
        "We got a URL reverse issue: %s. This is a known issue but please still submit a ticket at https://github.com/fangli/django-saml2-auth/issues/new"
        % str(objs)
    )


def _get_metadata():
    # BEGIN TESORIO CHANGES
    if "METADATA_INLINE" in settings.SAML2_AUTH:
        # Inline is another option provided by pySAML2 for providing a metadata
        # The other two options are: file path and auto conf url
        # There is a PR on django-saml2-auth, for adding this feature:
        # https://github.com/fangli/django-saml2-auth/pull/67/files
        return {"inline": [settings.SAML2_AUTH["METADATA_INLINE"]]}
    elif "METADATA_LOCAL_FILE_PATH" in settings.SAML2_AUTH:
        # END TESORIO CHANGES
        return {"local": [settings.SAML2_AUTH["METADATA_LOCAL_FILE_PATH"]]}
    else:
        return {
            "remote": [
                {
                    "url": settings.SAML2_AUTH["METADATA_AUTO_CONF_URL"],
                },
            ]
        }


# BEGIN TESORIO CHANGES
# def _get_saml_client(domain):
def _get_saml_client(domain, metadata_conf_url, metadata_conf_raw=None):
    #
    # Discussion:
    # https://github.com/Tesorio/django-saml2-auth/commit/1c6326e33135807aa513c18dd2f4eeff674d1a41
    #
    # > the reason we did this was because django-saml2-auth was built for
    # > only 1 SSO company to use it. Like as if it was an internal
    # > application. We wanted to provide SAML for our customers, so we used
    # > this as a way to do that.
    #
    # We are also stopping using the _get_metadata function altogether.
    # Since our support is for SAML 2.0 and not a specific company, changing
    # the settings object everytime could lead to issues due to concurrency.
    # For now, we won't be supporting the LOCAL_FILE_PATH setting.
    # Related:
    # https://github.com/Tesorio/django-saml2-auth/pull/11#pullrequestreview-704613069
    # We will give priority to the raw XML file if it exist
    # settings.SAML2_AUTH['METADATA_AUTO_CONF_URL'] = metadata_conf_url
    if metadata_conf_raw:
        metadata = {"inline": [metadata_conf_raw]}
    elif "METADATA_INLINE" in settings.SAML2_AUTH:
        metadata = {"inline": [settings.SAML2_AUTH["METADATA_INLINE"]]}
    else:
        metadata = {
            "remote": [
                {"url": metadata_conf_url},
            ]
        }
    # metadata = _get_metadata()
    # END TESORIO CHANGES
    acs_url = domain + get_reverse([acs, "acs", "django_saml2_auth:acs"])

    saml_settings = {
        "metadata": metadata,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST),
                    ],
                },
                "allow_unsolicited": True,
                "authn_requests_signed": False,
                "logout_requests_signed": True,
                "want_assertions_signed": True,
                "want_response_signed": False,
            },
        },
    }

    # BEGIN TESORIO CHANGES
    # if 'ENTITY_ID' in settings.SAML2_AUTH:
    #     saml_settings['entityid'] = settings.SAML2_AUTH['ENTITY_ID']
    #
    # pysaml2>4.5 requires EntityId to be set
    saml_settings["entityid"] = acs_url
    # END TESORIO CHANGES

    if "NAME_ID_FORMAT" in settings.SAML2_AUTH:
        saml_settings["service"]["sp"]["name_id_format"] = settings.SAML2_AUTH[
            "NAME_ID_FORMAT"
        ]

    spConfig = Saml2Config()
    spConfig.load(saml_settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client


@login_required
def welcome(r):
    try:
        return render(r, "django_saml2_auth/welcome.html", {"user": r.user})
    except TemplateDoesNotExist:
        return HttpResponseRedirect(
            settings.SAML2_AUTH.get("DEFAULT_NEXT_URL", get_reverse("admin:index"))
        )


def denied(r):
    return render(r, "django_saml2_auth/denied.html")


def _create_new_user(username, email, firstname, lastname):
    user = User.objects.create_user(username, email)
    user.first_name = firstname
    user.last_name = lastname
    groups = [
        Group.objects.get(name=x)
        for x in settings.SAML2_AUTH.get("NEW_USER_PROFILE", {}).get("USER_GROUPS", [])
    ]
    if parse_version(get_version()) >= parse_version("2.0"):
        user.groups.set(groups)
    else:
        user.groups = groups
    user.is_active = settings.SAML2_AUTH.get("NEW_USER_PROFILE", {}).get(
        "ACTIVE_STATUS", True
    )
    user.is_staff = settings.SAML2_AUTH.get("NEW_USER_PROFILE", {}).get(
        "STAFF_STATUS", True
    )
    user.is_superuser = settings.SAML2_AUTH.get("NEW_USER_PROFILE", {}).get(
        "SUPERUSER_STATUS", False
    )
    user.save()
    return user


@csrf_exempt
def acs(r):
    # BEGIN TESORIO CHANGES
    # saml_client = _get_saml_client(get_current_domain(r))
    saml_metadata_conf_url = r.session.get("saml_metadata_conf_url")
    saml_metadata_conf_raw = r.session.get("saml_metadata_conf_raw")
    if not saml_metadata_conf_url and not saml_metadata_conf_raw:
        logger.info("No saml_metadata_conf found", extra={"session": dict(r.session)})
        return HttpResponseRedirect(get_reverse("sso_login"))

    saml_client = _get_saml_client(
        get_current_domain(r), saml_metadata_conf_url, saml_metadata_conf_raw
    )
    # END TESORIO CHANGES
    resp = r.POST.get("SAMLResponse", None)
    next_url = r.session.get(
        "login_next_url",
        settings.SAML2_AUTH.get("DEFAULT_NEXT_URL", get_reverse("admin:index")),
    )

    if not resp:
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_saml2_auth:denied"])
        )

    authn_response = saml_client.parse_authn_request_response(
        resp, entity.BINDING_HTTP_POST
    )
    if authn_response is None:
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_saml2_auth:denied"])
        )

    user_identity = authn_response.get_identity()
    if user_identity is None:
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_saml2_auth:denied"])
        )

    user_email = user_identity[
        settings.SAML2_AUTH.get("ATTRIBUTES_MAP", {}).get("email", "Email")
    ][0]
    user_name = user_identity[
        settings.SAML2_AUTH.get("ATTRIBUTES_MAP", {}).get("username", "UserName")
    ][0]
    user_first_name = user_identity[
        settings.SAML2_AUTH.get("ATTRIBUTES_MAP", {}).get("first_name", "FirstName")
    ][0]
    user_last_name = user_identity[
        settings.SAML2_AUTH.get("ATTRIBUTES_MAP", {}).get("last_name", "LastName")
    ][0]

    try:
        # BEGIN TESORIO CHANGES
        # target_user = User.objects.get(username=user_name)
        target_user = User.objects.get(email__iexact=user_email)
        # END TESORIO CHANGES
        if settings.SAML2_AUTH.get("TRIGGER", {}).get("BEFORE_LOGIN", None):
            import_string(settings.SAML2_AUTH["TRIGGER"]["BEFORE_LOGIN"])(user_identity)
    except User.DoesNotExist:
        # BEGIN TESORIO CHANGES
        # new_user_should_be_created = settings.SAML2_AUTH.get('CREATE_USER', True)
        # if new_user_should_be_created:
        #     target_user = _create_new_user(user_name, user_email, user_first_name, user_last_name)
        #     if settings.SAML2_AUTH.get('TRIGGER', {}).get('CREATE_USER', None):
        #         import_string(settings.SAML2_AUTH['TRIGGER']['CREATE_USER'])(user_identity)
        #     is_new_user = True
        # else:
        #     return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))
        logger.warning(f"SSO user was not found: {user_email}")
        return HttpResponseRedirect("/login/?sso_login_no_user=true")

    r.session.flush()

    if target_user.is_active:
        target_user.backend = "django.contrib.auth.backends.ModelBackend"
        login(r, target_user)
    else:
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_saml2_auth:denied"])
        )

    # BEGIN TESORIO CHANGES
    # if settings.SAML2_AUTH.get('USE_JWT') is True:
    #     # We use JWT auth send token to frontend
    #     jwt_token = jwt_encode(target_user)
    #     query = '?uid={}&token={}'.format(target_user.id, jwt_token)

    #     frontend_url = settings.SAML2_AUTH.get(
    #         'FRONTEND_URL', next_url)

    #     return HttpResponseRedirect(frontend_url+query)

    # if is_new_user:
    #     try:
    #         return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
    #     except TemplateDoesNotExist:
    #         return HttpResponseRedirect(next_url)
    # else:
    #     return HttpResponseRedirect(next_url)
    # END TESORIO CHANGES
    return HttpResponseRedirect(next_url)


def signin(r):
    try:
        from urllib import unquote

        import urlparse as _urlparse
    except:
        import urllib.parse as _urlparse
        from urllib.parse import unquote
    next_url = r.GET.get(
        "next", settings.SAML2_AUTH.get("DEFAULT_NEXT_URL", get_reverse("admin:index"))
    )

    try:
        if "next=" in unquote(next_url):
            next_url = _urlparse.parse_qs(_urlparse.urlparse(unquote(next_url)).query)[
                "next"
            ][0]
    except:
        next_url = r.GET.get(
            "next",
            settings.SAML2_AUTH.get("DEFAULT_NEXT_URL", get_reverse("admin:index")),
        )

    # Only permit signin requests where the next_url is a safe URL
    if parse_version(get_version()) >= parse_version("2.0"):
        url_ok = url_has_allowed_host_and_scheme(next_url, None)
    else:
        url_ok = url_has_allowed_host_and_scheme(next_url)

    if not url_ok:
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_saml2_auth:denied"])
        )

    r.session["login_next_url"] = next_url

    # BEGIN TESORIO CHANGES
    # saml_client = _get_saml_client(get_current_domain(r))
    saml_client = _get_saml_client(
        get_current_domain(r),
        r.session.get("saml_metadata_conf_url"),
        r.session.get("saml_metadata_conf_raw"),
    )
    # END TESORIO CHANGES
    _, info = saml_client.prepare_for_authenticate()

    redirect_url = None

    for key, value in info["headers"]:
        if key == "Location":
            redirect_url = value
            break

    return HttpResponseRedirect(redirect_url)


def signout(r):
    logout(r)
    return render(r, "django_saml2_auth/signout.html")
