"""
Regression tests for the camera routes which are included in the EXEMPT lists found under auth.py.
Normally, all new routes that are added are protected by default with admin permissions but those
placed under the EXEMPT lists are expected to implement their own permission checks. These tests
ensure camera permissions remain consistent and are not unexpectedly opened/closed.
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

from frigate.api.auth import (
    get_allowed_cameras_for_filter,
    require_camera_access,
    require_full_camera_access,
    require_go2rtc_stream_access,
)
from frigate.const import JWT_SECRET_ENV_VAR
from frigate.models import User
from frigate.test.http_api.base_http_test import BaseTestHttp

CAMERA_ROUTES: dict[Callable, list[tuple[str, str]]] = {
    require_camera_access: [
        # export.py
        ("POST", "/export/{camera_name}/start/{start_time}/end/{end_time}"),
        ("POST", "/export/custom/{camera_name}/start/{start_time}/end/{end_time}"),
        # media.py
        ("GET", "/vod/{camera_name}/start/{start_ts}/end/{end_ts}"),
        ("GET", "/vod/{year_month}/{day}/{hour}/{camera_name}"),
        ("GET", "/vod/{year_month}/{day}/{hour}/{camera_name}/{tz_name}"),
        ("GET", "/vod/clip/{camera_name}/start/{start_ts}/end/{end_ts}"),
        ("GET", "/vod/{camera_name}/{stream}/start/{start_ts}/end/{end_ts}"),
        # preview.py
        ("GET", "/preview/{camera_name}/start/{start_ts}/end/{end_ts}/frames"),
    ],
    require_go2rtc_stream_access: [
        # camera.py
        ("GET", "/go2rtc/streams/{stream_name}"),
    ],
    require_full_camera_access: [
        # classification.py
        ("GET", "/classification/attributes"),
        # review.py
        ("POST", "/review/summarize/start/{start_ts}/end/{end_ts}"),
    ],
}

# Default camera target, front_door_only cannot see
CAMERA = "back_door"

DENIED_CASES: tuple[tuple[str, dict[str, str]], ...] = (
    (
        "role restricted to another camera",
        {"remote-user": "front_door_user", "remote-role": "front_door_only"},
    ),
    (
        "no role header",
        {"remote-user": "misc"},
    ),
    (
        "no auth headers",
        {},
    ),
)

ALLOWED_ROLE_HEADERS = (
    "admin",
    "viewer",
    "all_cameras",
)


def _get_api_routes(routes: list[BaseRoute]) -> list[APIRoute]:
    flat: list[APIRoute] = []
    for route in routes:
        if isinstance(route, APIRoute):
            flat.append(route)
        elif (router := getattr(route, "original_router", None)) is not None:
            flat.extend(_get_api_routes(router.routes))

    return flat


def _get_camera_dependency_on_route(route: APIRoute) -> Callable | None:
    """Return the require_role dependency attached to a route, if any."""
    for dependency in route.dependant.dependencies:
        if dependency.call in CAMERA_ROUTES:
            return dependency.call

    return None


def _create_dummy_path_values(path: str) -> str:
    """point camera to CAMERA const and default url params to 1"""
    path = path.replace("{camera_name}", CAMERA).replace("{stream_name}", CAMERA)
    return re.sub(r"\{[^}]+\}", "1", path)


def _build_fast_api_route_map(
    routes: list[BaseRoute],
) -> dict[tuple[str, str], APIRoute]:
    mapped_routes: dict[tuple[str, str], APIRoute] = {}
    for route in _get_api_routes(routes):
        for method in route.methods:
            mapped_routes[(method, route.path)] = route
    return mapped_routes


@patch.dict(os.environ, {JWT_SECRET_ENV_VAR: "test-secret"})
class TestCameraRouteAuthorization(BaseTestHttp):
    def setUp(self):
        super().setUp([User])
        self.minimal_config["cameras"][CAMERA] = {
            "ffmpeg": {
                "inputs": [{"path": "rtsp://10.0.0.2:554/video", "roles": ["detect"]}]
            },
            "detect": {"height": 1080, "width": 1920, "fps": 5},
        }
        self.minimal_config["auth"] = {
            "roles": {
                "front_door_only": ["front_door"],
                "all_cameras": ["front_door", CAMERA],
            }
        }
        self.app = super().create_app()

        # Base app uses get_allowwed_cameras_for_filter as a stand in, this clears it to
        # use implemented dependencies
        self.app.dependency_overrides.clear()

    def test_insufficient_roles_are_denied(self):
        with TestClient(self.app, raise_server_exceptions=False) as client:
            for routes in CAMERA_ROUTES.values():
                for method, path in routes:
                    stubbed_path = _create_dummy_path_values(path)
                    for case, headers in DENIED_CASES:
                        with self.subTest(method=method, path=path, case=case):
                            response = client.request(
                                method, stubbed_path, headers=headers
                            )
                            self.assertIn(response.status_code, (401, 403))

    def test_permitted_roles_pass_route_guard(self):
        routes_map = _build_fast_api_route_map(self.app.router.routes)
        for dependency, routes in CAMERA_ROUTES.items():
            for method, path in routes:
                camera_dependency_check = _get_camera_dependency_on_route(
                    routes_map[(method, path)]
                )
                for role in ALLOWED_ROLE_HEADERS:
                    with self.subTest(method=method, path=path, role=role):
                        self.assertIs(camera_dependency_check, dependency)
                        request = Request(
                            {
                                "type": "http",
                                "method": method,
                                "path": _create_dummy_path_values(path),
                                "headers": Headers(
                                    {"remote-user": "test_user", "remote-role": role}
                                ).raw,
                                "app": self.app,
                            }
                        )
                        if dependency is require_full_camera_access:
                            args = (
                                request,
                                asyncio.run(get_allowed_cameras_for_filter(request)),
                            )
                        else:
                            args = (CAMERA, request)

                        self.assertIsNone(asyncio.run(camera_dependency_check(*args)))
