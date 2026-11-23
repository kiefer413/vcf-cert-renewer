import json
from subprocess import CalledProcessError

import pytest

from vcf_cert_renewer.diagnostics import attach_diagnostic, diagnostic_for_exception
from vcf_cert_renewer.signer import _classify_lego_failure


HOST = "acme-v02.api.letsencrypt.org"


def header(url=None, status=403, method="POST", code="unauthorized"):
    context = "" if url is None else f" :: {method} :: {url}"
    return (f"CSR: obtain failed: acme: error: {status}{context} :: "
            f"urn:ietf:params:acme:error:{code} :: "
            "credential=fixture-secret account=12345 challenge=fixture-token")


def classify(text):
    return _classify_lego_failure(CalledProcessError(1, ["lego"], stderr=text))


@pytest.mark.parametrize(("path", "operation"), [
    ("/acme/new-order", "NEW_ORDER"),
    ("/acme/authz-v3/12345", "AUTHORIZATION"),
    ("/acme/authz/12345/67890", "AUTHORIZATION"),
    ("/acme/chall-v3/12345/fixture-token", "CHALLENGE"),
    ("/acme/chall/12345/67890/fixture-token", "CHALLENGE"),
    ("/acme/finalize/12345/67890", "FINALIZE"),
    ("/acme/acct/12345", "ACCOUNT"),
    ("/acme/new-acct", "ACCOUNT"),
])
def test_recognized_routes_and_serialization(path, operation):
    exc = classify(header(f"https://{HOST}{path}"))
    expected = {"legoExit": 1, "category": "ACME_AUTHORIZATION_FAILURE",
                "problem": "unauthorized", "operation": operation,
                "httpContext": "RECOGNIZED_ROUTE", "problemStatus": 403}
    for attach in (False, True):
        if attach:
            attach_diagnostic(exc, {"operation": "ACME_SIGNING"})
        event = diagnostic_for_exception(exc, component="SDDC_MANAGER", target=None,
                                         phase="RENEW", operation="ACME_SIGNING")
        assert event["acme"] == expected
        assert event["operation"] == "ACME_SIGNING"
        for secret in ("fixture-secret", "fixture-token", "12345", HOST):
            assert secret not in str(exc)
            assert secret not in json.dumps(event)


@pytest.mark.parametrize("url", [
    f"https://{HOST}/acme/authz/12345",
    f"https://{HOST}/acme/order/12345/67890",
    "https://[broken",
    "https://wrong.invalid/acme/new-order",
    f"http://{HOST}/acme/new-order",
    f"https://{HOST}/acme/new-order?q=fixture-secret",
    f"https://{HOST}/acme/new-order#",
    f"https://{HOST}:443/acme/new-order",
    f"https://user@{HOST}/acme/new-order",
    f"https://{HOST}/acme/%6eew-order",
    f"https://{HOST}.wrong.invalid/acme/new-order",
])
def test_reject_untrusted_or_unknown_routes(url):
    e = classify(header(url))
    assert e.operation is None
    assert e.http_context == "UNRECOGNIZED_ROUTE"
    assert url not in str(e)


@pytest.mark.parametrize("status", [0, 403])
def test_no_http_context(status):
    e = classify(header(status=status))
    assert e.problem == "unauthorized"
    assert e.http_context == "NO_HTTP_CONTEXT"
    assert e.problem_status is None
    assert e.operation is None


def test_partial_context_is_not_absent():
    e = classify(header("", method="POST"))
    assert e.http_context == "UNRECOGNIZED_ROUTE"
    assert e.problem_status is None


@pytest.mark.parametrize("status", [0, 200, 600, 999])
def test_invalid_http_problem_status_is_not_exported(status):
    assert classify(header(f"https://{HOST}/acme/new-order", status=status)).problem_status is None


def test_conflicts_and_unrecognized_problem_are_ambiguous():
    for text in (
        header(code="privateProblem"),
        header(f"https://{HOST}/acme/new-order") + "\n" + header(),
        header(f"https://{HOST}/acme/new-order", 401) + "\n" +
        header(f"https://{HOST}/acme/new-order", 403),
        "authorization failed",
    ):
        assert classify(text).safe_fields() == {"legoExit": 1, "category": "UNKNOWN_ACME_ERROR"}
