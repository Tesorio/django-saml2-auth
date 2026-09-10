"""Utility functions for dealing with various parts of the library.
E.g. creating SAML client, creating user, exception handling, etc.
"""

import base64
from functools import wraps
from importlib import import_module
import logging
from typing import (Any, Callable, Dict, Iterable, Mapping, Optional, Tuple,
                    Union)

from dictor import dictor  # type: ignore
from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import NoReverseMatch, reverse
from django.utils.module_loading import import_string
from django_saml2_auth.errors import (EMPTY_FUNCTION_PATH, GENERAL_EXCEPTION,
                                      IMPORT_ERROR, INACTIVE_USER,
                                      NO_METADATA_URL_ASSOCIATED,
                                      NO_REVERSE_MATCH,
                                      NO_SAML_RESPONSE_FROM_CLIENT, PATH_ERROR,
                                      SHOULD_NOT_CREATE_USER)
from django_saml2_auth.exceptions import SAMLAuthError

# The recoverable login failures that answer with a redirect instead of the error page. A user
# in an SSO-only tenant has no password to fall back on, so an error page strands them where a
# redirect puts them back on a route they can act on. Each value names the key to read under
# SAML2_AUTH["ERROR_REDIRECTS"]; an unset key keeps the error page.
ERROR_REDIRECT_KEYS: Dict[int, str] = {
    NO_SAML_RESPONSE_FROM_CLIENT: "NO_SAML_RESPONSE",
    NO_METADATA_URL_ASSOCIATED: "NO_METADATA",
    SHOULD_NOT_CREATE_USER: "USER_NOT_FOUND",
    INACTIVE_USER: "INACTIVE_USER",
}


def run_hook(function_path: str,
             *args: Optional[Tuple[Any]],
             **kwargs: Optional[Mapping[str, Any]]) -> Optional[Any]:
    """Runs a hook function with given args and kwargs. For example, given
    "models.User.create_new_user", the "create_new_user" function is imported from
    the "models.User" module and run with args and kwargs. Functions can be
    imported directly from modules, without having to be inside any class.

    Args:
        function_path (str): A path to a hook function,
            e.g. models.User.create_new_user (static method)

    Raises:
        SAMLAuthError: function_path isn't specified
        SAMLAuthError: There's nothing to import. Check your hook's import path!
        SAMLAuthError: Import error
        SAMLAuthError: Re-raise any exception caused by the called function

    Returns:
        Optional[Any]: Any result returned from running the hook function. None is returned in case
            of any exceptions, errors in arguments and related issues.
    """
    if not function_path:
        raise SAMLAuthError("function_path isn't specified", extra={
            "exc_type": ValueError,
            "error_code": EMPTY_FUNCTION_PATH,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    path = function_path.split(".")
    if len(path) < 2:
        # Nothing to import
        raise SAMLAuthError("There's nothing to import. Check your hook's import path!", extra={
            "exc_type": ValueError,
            "error_code": PATH_ERROR,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    module_path = ".".join(path[:-1])
    result = None
    try:
        cls = import_module(module_path)
    except ModuleNotFoundError:
        try:
            cls = import_string(module_path)
        except ImportError as exc:
            raise SAMLAuthError(str(exc), extra={
                "exc": exc,
                "exc_type": type(exc),
                "error_code": IMPORT_ERROR,
                "reason": "There was an error processing your request.",
                "status_code": 500
            })
    try:
        result = getattr(cls, path[-1])(*args, **kwargs)
    except SAMLAuthError as exc:
        # Re-raise the exception
        raise exc
    except AttributeError as exc:
        raise SAMLAuthError(str(exc), extra={
            "exc": exc,
            "exc_type": type(exc),
            "error_code": IMPORT_ERROR,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })
    except Exception as exc:
        raise SAMLAuthError(str(exc), extra={
            "exc": exc,
            "exc_type": type(exc),
            "error_code": GENERAL_EXCEPTION,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    return result


def get_reverse(objects: Union[Any, Iterable[Any]]) -> Optional[str]:
    """Given one or a list of views/urls(s), returns the corresponding URL to that view.

    Args:
        objects (Union[Any, Iterable[Any]]): One or many views/urls representing a resource

    Raises:
        SAMLAuthError: We got a URL reverse issue: [...]

    Returns:
        Optional[str]: The URL to the resource or None.
    """
    if not isinstance(objects, (list, tuple)):
        objects = [objects]

    for obj in objects:
        try:
            return reverse(obj)
        except NoReverseMatch:
            pass
    raise SAMLAuthError(f"We got a URL reverse issue: {str(objects)}", extra={
        "exc_type": NoReverseMatch,
        "error_code": NO_REVERSE_MATCH,
        "reason": "There was an error processing your request.",
        "status_code": 500
    })


def get_error_redirect_url(exc: Exception) -> Optional[str]:
    """Resolve where a recoverable login failure should redirect to, if anywhere.

    Args:
        exc (Exception): The exception raised by the view

    Returns:
        Optional[str]: A URL to redirect to, or None to render the error page instead
    """
    if not isinstance(exc, SAMLAuthError) or not exc.extra:
        return None

    error_code = exc.extra.get("error_code")
    redirect_key = ERROR_REDIRECT_KEYS.get(error_code) if isinstance(error_code, int) else None
    if not redirect_key:
        return None

    target = dictor(settings.SAML2_AUTH, f"ERROR_REDIRECTS.{redirect_key}")
    if not target:
        return None

    # A path or an absolute URL is used as given; anything else is a URL pattern name.
    if target.startswith("/") or "://" in target:
        return target

    try:
        return get_reverse(target)
    except SAMLAuthError:
        return None


def exception_handler(
    function: Callable[..., Union[HttpResponse, HttpResponseRedirect]]) -> \
        Callable[..., Union[HttpResponse, HttpResponseRedirect]]:
    """This decorator can be used by view function to handle exceptions

    Args:
        function (Callable[..., Union[HttpResponse, HttpResponseRedirect]]):
            View function to decorate

    Returns:
        Callable[..., Union[HttpResponse, HttpResponseRedirect]]:
            Decorated view function with exception handling
    """
    def handle_exception(exc: Exception, request: HttpRequest) -> HttpResponse:
        """Render page with exception details

        Args:
            exc (Exception): An exception
            request (HttpRequest): Incoming http request object

        Returns:
            HttpResponse: Rendered error page with details
        """
        logger = logging.getLogger(__name__)
        logger.debug(exc)

        redirect_url = get_error_redirect_url(exc)
        if redirect_url:
            return HttpResponseRedirect(redirect_url)

        context: Optional[Dict[str, Any]] = exc.extra if isinstance(exc, SAMLAuthError) else {}
        if isinstance(exc, SAMLAuthError) and exc.extra:
            status = exc.extra.get("status_code")
        else:
            status = 500

        return render(request,
                      "django_saml2_auth/error.html",
                      context=context,
                      status=status)

    @wraps(function)
    def wrapper(request: HttpRequest) -> HttpResponse:
        """Decorated function is wrapped and called here

        Args:
            request ([type]): [description]

        Returns:
            HttpResponse: Either a redirect or a response with error details
        """
        result = None
        try:
            result = function(request)
        except (SAMLAuthError, Exception) as exc:
            result = handle_exception(exc, request)
        return result
    return wrapper


def is_jwt_well_formed(jwt: str):
    """Check if JWT is well formed

    Args:
        jwt (str): Json Web Token

    Returns:
        Boolean: True if JWT is well formed, otherwise False
    """
    if isinstance(jwt, str):
        # JWT should contain three segments, separated by two period ('.') characters.
        jwt_segments = jwt.split('.')
        if len(jwt_segments) == 3:
            jose_header = jwt_segments[0]
            # base64-encoded string length should be a multiple of 4
            if len(jose_header) % 4 == 0:
                try:
                    jh_decoded = base64.b64decode(jose_header).decode('utf-8')
                    if jh_decoded and jh_decoded.find('JWT') > -1:
                        return True
                except Exception:
                    return False
    # If tests not passed return False
    return False
