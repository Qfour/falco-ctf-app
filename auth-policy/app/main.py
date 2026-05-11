"""falco-ctf auth-policy.

Tiny auth subrequest endpoint that combines oauth2-proxy authentication
with a host↔email binding check:

  ingress  ── /check?host=<expected-username> ──►  this service
                                                     │
                                                     └─► oauth2-proxy /oauth2/auth
                                                            (cookie forwarded)
                                                         returns X-Auth-Request-Email
                                                     │
                                                     ├ email startswith "<host>@" → 200
                                                     ├ email otherwise            → 403
                                                     └ no auth at all             → 401

Plain `auth-url: oauth2-proxy/oauth2/auth` would let any logged-in user reach
any user's workspace. This service closes that gap without requiring
ingress-nginx snippet annotations (which the admission webhook blocks).
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response

OAUTH2_PROXY_URL = os.environ.get(
    "OAUTH2_PROXY_AUTH_URL",
    "http://oauth2-proxy.oauth2-proxy.svc.cluster.local:80/oauth2/auth",
)
EMAIL_DOMAIN = os.environ.get("EXPECTED_EMAIL_DOMAIN", "ctf.local")

app = FastAPI(title="falco-ctf auth-policy")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"ok": True, "oauth2_proxy": OAUTH2_PROXY_URL, "domain": EMAIL_DOMAIN}


@app.get("/check")
async def check(request: Request, host: str = "") -> Response:
    if not host:
        return Response(status_code=400, content="missing ?host= query param")

    # Forward the original request's cookie to oauth2-proxy. Other auth
    # headers (Authorization, etc.) too, in case bearer tokens are in play.
    cookie = request.headers.get("cookie", "")
    auth_hdr = request.headers.get("authorization", "")
    fwd_headers = {}
    if cookie:
        fwd_headers["Cookie"] = cookie
    if auth_hdr:
        fwd_headers["Authorization"] = auth_hdr

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(OAUTH2_PROXY_URL, headers=fwd_headers)
    except httpx.HTTPError as e:
        return Response(status_code=502, content=f"oauth2-proxy unreachable: {e}")

    if resp.status_code == 401:
        # Not authenticated — let ingress-nginx auth-signin redirect to /oauth2/start
        return Response(status_code=401, content="not authenticated")
    if resp.status_code != 202:
        return Response(
            status_code=resp.status_code,
            content=f"oauth2-proxy returned {resp.status_code}",
        )

    email = resp.headers.get("x-auth-request-email", "")
    expected_prefix = f"{host}@"
    if not email.startswith(expected_prefix):
        # Authenticated but wrong user — return 403 (no redirect).
        return Response(
            status_code=403,
            content=f"forbidden: '{email}' does not match host '{host}'",
        )

    # Pass identity headers back so the upstream (ttyd) can see them too.
    return Response(
        status_code=200,
        headers={
            "X-Auth-Request-Email": email,
            "X-Auth-Request-User": resp.headers.get("x-auth-request-user", ""),
            "X-Auth-Request-Preferred-Username": resp.headers.get(
                "x-auth-request-preferred-username", ""
            ),
        },
    )
