"""
Regression tests for the admin routes which are included in the EXEMPT lists found under auth.py.
Normally, all new routes that are added are protected by default with admin permissions but those
placed under the EXEMPT lists are expected to implement their own permission checks. These tests
ensure permissions remain consistent and are not unexpectedly opened/closed.
"""

import asyncio
import os
import re
from collections.abc import Callable
from unittest.mock import patch

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.routing import BaseRoute

from frigate.const import JWT_SECRET_ENV_VAR
from frigate.models import User
from frigate.test.http_api.base_http_test import BaseTestHttp

ADMIN_ROUTES: list[tuple[str, str]] = [
    # app.py
    ("GET", "/stats/history"),
    ("GET", "/logs/{service}"),
    # auth.py
    ("DELETE", "/users/{username}"),
    ("PUT", "/users/{username}/role"),
    # camera.py
    ("PUT", "/go2rtc/streams/{stream_name}"),
    ("DELETE", "/go2rtc/streams/{stream_name}"),
    ("GET", "/go2rtc/streams/{stream_name}/bitrate"),
    # event.py
    ("POST", "/events/{event_id}/retain"),
    ("POST", "/events/{event_id}/plus"),
    ("PUT", "/events/{event_id}/false_positive"),
    ("DELETE", "/events/{event_id}/retain"),
    ("POST", "/events/{event_id}/sub_label"),
    ("POST", "/events/{event_id}/recognized_license_plate"),
    ("POST", "/events/{event_id}/attributes"),
    ("POST", "/events/{event_id}/description"),
    ("PUT", "/events/{event_id}/description/regenerate"),
    ("DELETE", "/events/{event_id}"),
    ("DELETE", "/events/"),
    ("POST", "/events/{camera_name}/{label}/create"),
    ("PUT", "/events/{event_id}/end"),
    # export.py
    ("POST", "/cases"),
    ("PATCH", "/cases/{case_id}"),
    ("DELETE", "/cases/{case_id}"),
    ("PATCH", "/export/{event_id}/rename"),
    ("POST", "/exports/delete"),
    ("POST", "/exports/reassign"),
    # record.py
    ("GET", "/recordings/storage"),
    # review.py
    ("POST", "/reviews/delete"),
    ("PUT", "/review/{review_id}/regenerate_description"),
]

DENIED_CASES: tuple[tuple[str, dict[str, str]], ...] = (
    (
        "viewer",
        {"remote-user": "viewer_user", "remote-role": "viewer"},
    ),
    (
        "custom role with every camera",
        {"remote-user": "operator_user", "remote-role": "operator"},
    ),
    (
        "role missing from config",
        {"remote-user": "misc", "remote-role": "superuser"},
    ),
    (
        "no role header",
        {"remote-user": "misc"},
    ),
)

ALLOWED_ROLE_HEADERS = (
    "admin",
    "viewer,admin",
)


def _get_api_routes(routes: list[BaseRoute]) -> list[APIRoute]:
    flat: list[APIRoute] = []
    for route in routes:
        if isinstance(route, APIRoute):
            flat.append(route)
        elif (router := getattr(route, "original_router", None)) is not None:
            flat.extend(_get_api_routes(router.routes))

    return flat


def _get_required_dependency_on_route(route: APIRoute) -> Callable | None:
    """Return the require_role dependency attached to a route, if any."""
    for dependency in route.dependant.dependencies:
        if "role_checker" in getattr(dependency.call, "__qualname__", ""):
            return dependency.call

    return None


def _create_dummy_path_values(path: str) -> str:
    """Default every path parameter to 1."""
    return re.sub(r"\{[^}]+\}", "1", path)


def _build_fast_api_route_map(api_routes: APIRoute) -> dict[tuple[str, str], APIRoute]:
    mapped_routes: dict[tuple[str, str], APIRoute] = {}
    for route in _get_api_routes(api_routes):
        for method in route.methods:
            mapped_routes[(method, route.path)] = route
    return mapped_routes


@patch.dict(os.environ, {JWT_SECRET_ENV_VAR: "test-secret"})
class TestAdminRouteAuthorization(BaseTestHttp):
    def setUp(self):
        super().setUp([User])
        self.minimal_config["auth"] = {"roles": {"operator": ["front_door"]}}
        self.app = super().create_app()

    def test_non_admin_roles_are_denied(self):
        with TestClient(self.app) as client:
            for method, path in ADMIN_ROUTES:
                stubbed_path = _create_dummy_path_values(path)
                for case, headers in DENIED_CASES:
                    with self.subTest(method=method, path=path, case=case):
                        response = client.request(method, stubbed_path, headers=headers)
                        self.assertEqual(response.status_code, 403)

    def test_admin_role_passes_route_guard(self):
        routes_map = _build_fast_api_route_map(self.app.router.routes)
        for method, path in ADMIN_ROUTES:
            role_dependency_check = _get_required_dependency_on_route(
                routes_map[(method, path)]
            )
            for role in ALLOWED_ROLE_HEADERS:
                with self.subTest(method=method, path=path, role=role):
                    request = Request(
                        {
                            "type": "http",
                            "method": method,
                            "path": _create_dummy_path_values(path),
                            "headers": Headers(
                                {"remote-user": "admin_user", "remote-role": role}
                            ).raw,
                            "app": self.app,
                        }
                    )
                    self.assertEqual(
                        asyncio.run(role_dependency_check(request)), "admin"
                    )
