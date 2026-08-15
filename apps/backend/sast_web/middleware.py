from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest, HttpResponse


class SimpleCorsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.method == "OPTIONS":
            response = HttpResponse(status=204)
        else:
            response = self.get_response(request)

        origin = request.headers.get("Origin")
        if origin in settings.SAST_WEB_CORS_ORIGINS:
            response["Access-Control-Allow-Origin"] = origin
            response["Vary"] = "Origin"
            response["Access-Control-Allow-Credentials"] = "true"
            response["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
            response["Access-Control-Allow-Headers"] = "Content-Type,X-Requested-With"
        return response
