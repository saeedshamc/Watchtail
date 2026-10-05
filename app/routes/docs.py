"""Human-readable API documentation at /docs.

Renders the OpenAPI spec from app.openapi as a static, dependency-free
HTML page: one section per endpoint with method, path, auth
requirement, parameters and response summary. A small link exposes the
raw spec for tools like Swagger UI or Postman import.
"""

from flask import Blueprint, Response, render_template

from ..auth import login_required
from ..openapi import API_SPEC

bp = Blueprint("docs", __name__)


@bp.get("/docs")
@login_required
def docs():
    endpoints = []
    for path, operations in API_SPEC["paths"].items():
        for method, operation in operations.items():
            endpoints.append(
                {
                    "method": method.upper(),
                    "path": f"/api/v1{path}",
                    "summary": operation.get("summary", ""),
                    "write": "write token" in operation.get("summary", "").lower(),
                    "parameters": operation.get("parameters", []),
                    "responses": sorted(operation.get("responses", {}).keys()),
                }
            )
    return render_template("docs.html", endpoints=endpoints, spec=API_SPEC)


@bp.get("/docs/openapi.json")
@login_required
def openapi_raw():
    body = _json_dumps()
    return Response(body, mimetype="application/json")


def _json_dumps():
    import json

    return json.dumps(API_SPEC, indent=2)
