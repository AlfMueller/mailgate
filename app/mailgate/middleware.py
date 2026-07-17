# SPDX-License-Identifier: AGPL-3.0-only

from django.conf import settings


class LocalNullOriginMiddleware:
    """Allow sandboxed desktop webviews on loopback without disabling CSRF tokens."""

    LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "[::1]"}

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.ENVIRONMENT == "development" and request.META.get("HTTP_ORIGIN") == "null":
            host = request.get_host()
            hostname = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
            if hostname in self.LOOPBACK_HOSTS:
                request.META["HTTP_ORIGIN"] = f"{request.scheme}://{host}"
        return self.get_response(request)


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'; style-src 'self'",
        )
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
        )
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        response.headers.setdefault("Cache-Control", "no-store")
        return response
