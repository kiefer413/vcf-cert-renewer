"""VCF API-token exchange."""

from __future__ import annotations

import requests

from .config import Settings


class TokenExchangeError(RuntimeError):
    """Raised when the OAuth response does not contain an access token."""


def exchange_token(settings: Settings) -> str:
    """Exchange a long-lived VCF API token for a short-lived bearer token."""
    response = requests.post(
        settings.token_url,
        data={
            "grant_type": "urn:custom:vcf:params:oauth:grant-type:api-token",
            "api_token": settings.require_api_token(),
        },
        headers={"Accept": "application/json"},
        timeout=settings.timeout_seconds,
        verify=settings.verify_tls,
    )
    response.raise_for_status()
    payload = response.json()
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise TokenExchangeError("OAuth response did not contain access_token")
    return token
