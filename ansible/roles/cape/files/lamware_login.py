# Managed by Ansible (cape role, web-login.yml). V13.
"""Every CAPE web page needs a login, except the login page, static files and the API.

CAPE's [web_auth] guards only the views that carry its decorator (36 of 65 in
analysis/, 4 of 12 in submission/, 0 of 4 in apikey/, measured 2026-11-16), so
turning it on alone leaves pages open. This applies Django's own
LoginRequiredMiddleware to everything, with three exceptions:

- the login and logout pages, which must be reachable to log in;
- static files;
- Django REST Framework views (CAPE's /apiv2/). They authenticate per request with
  a token, and with token_auth_enabled their default permission is IsAuthenticated;
  a session-based redirect would break the pipeline's token calls.
"""
from django.contrib.auth.middleware import LoginRequiredMiddleware

try:
    from rest_framework.views import APIView
except ImportError:  # pragma: no cover - CAPE always ships DRF
    APIView = None

OPEN_PATHS = ("/accounts/login/", "/accounts/logout/", "/static/")


def is_api_view(view_func) -> bool:
    """True for a DRF view: its own authentication and permissions apply."""
    cls = getattr(view_func, "cls", None)
    return APIView is not None and isinstance(cls, type) and issubclass(cls, APIView)


class LamwareLoginRequired(LoginRequiredMiddleware):
    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.path.startswith(OPEN_PATHS) or is_api_view(view_func):
            return None
        return super().process_view(request, view_func, view_args, view_kwargs)
