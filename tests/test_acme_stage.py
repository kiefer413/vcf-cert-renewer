import json
from subprocess import CalledProcessError

import pytest

from vcf_cert_renewer.diagnostics import attach_diagnostic, diagnostic_for_exception
from vcf_cert_renewer.signer import _classify_lego_failure

PROBLEM = "acme: error: 0 :: urn:ietf:params:acme:error:unauthorized :: secret-placeholder"
HTTP = ("acme: error: 403 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-order :: "
        "urn:ietf:params:acme:error:unauthorized :: secret-placeholder")


def classify(text):
    return _classify_lego_failure(CalledProcessError(1, ["lego"], stderr=text))


@pytest.mark.parametrize(("text", "stage"), [
    ("registration: resolve account by key: " + PROBLEM, "ACCOUNT"),
    ("set up account: open opaque file: denied", "ACCOUNT"),
    ("registration: could not complete registration: " + PROBLEM, "ACCOUNT"),
    ("invalid authorization: " + PROBLEM, "AUTHORIZATION_VALIDATION"),
    ("invalid challenge: " + PROBLEM, "CHALLENGE_VALIDATION"),
    ("failed to initiate the challenge: " + PROBLEM, "CHALLENGE_ACCEPTANCE"),
    ("dns01: error presenting token (sddc.example.test): dnsupdate: failed to insert: refused",
     "DNS_PRESENTATION"),
    ("dns01: time limit exceeded: last error: authoritative nameservers: missing TXT",
     "DNS_PROPAGATION"),
    ("renew certificate: CSR: could not obtain the certificate: resolver: one or more domains "
     "had a problem: [secret-host.example: invalid authorization: " + PROBLEM + "]",
     "AUTHORIZATION_VALIDATION"),
    (json.dumps({"level": "ERROR", "msg": "Error", "error": "invalid challenge: " + PROBLEM}),
     "CHALLENGE_VALIDATION"),
    ('time=2026-11-23T08:20:00Z level=ERROR msg=Error error=' +
     json.dumps("registration: " + PROBLEM), "ACCOUNT"),
    ('2026-11-23T08:20:00Z \x1b[31mERROR\x1b[0m Error error=' +
     json.dumps("invalid challenge: " + PROBLEM), "CHALLENGE_VALIDATION"),
])
def test_supported_wrappers(text, stage):
    exc = classify(text)
    assert exc.stage == stage
    assert exc.operation is None
    assert "stage=" + stage in str(exc)
    attach_diagnostic(exc, {"operation": "ACME_SIGNING"})
    result = diagnostic_for_exception(exc, component="SDDC_MANAGER", target=None, phase="RENEW")
    assert result["operation"] == "ACME_SIGNING"
    assert result["acme"]["stage"] == stage
    for value in (str(exc), json.dumps(result)):
        assert "secret-placeholder" not in value
        assert "secret-host.example" not in value


@pytest.mark.parametrize("text", [
    "obtain certificate: " + PROBLEM,
    "CSR: could not obtain the certificate: " + PROBLEM,
    "certificates: one or more domains had a problem: [example.test: " + PROBLEM + "]",
    "invalid order: " + PROBLEM,
    "acme: time limit exceeded: last error: " + PROBLEM,
    "unrelated credential=registration: resolve account by key: " + PROBLEM,
    PROBLEM + " invalid challenge: secret-placeholder",
    "invalid authorization:",
    "ERROR Error error=\"invalid challenge:",
    "invalid authorization: invalid challenge: " + PROBLEM,
    "invalid authorization: " + PROBLEM + "\ninvalid challenge: " + PROBLEM,
    "resolver: one or more domains had a problem: [a: invalid authorization: " +
    PROBLEM + "] [b: invalid challenge: missing]",
])
def test_ambiguous_unproven_and_truncated_wrappers(text):
    assert classify(text).stage is None


def test_http_route_is_independent_and_b9_fields_are_preserved():
    plain = classify(HTTP)
    staged = classify("failed to initiate the challenge: " + HTTP.replace(
        "/acme/new-order", "/acme/chall/123/456/fixture-token"))
    assert plain.operation == "NEW_ORDER" and plain.stage is None
    assert staged.operation == "CHALLENGE" and staged.stage == "CHALLENGE_ACCEPTANCE"
    assert (staged.problem, staged.http_context, staged.problem_status) == (
        "unauthorized", "RECOGNIZED_ROUTE", 403)
    assert "fixture-token" not in str(staged)
    embedded = classify("invalid authorization: " + PROBLEM)
    assert embedded.http_context == "NO_HTTP_CONTEXT"
    assert embedded.problem_status is None and embedded.operation is None


def test_dns_categories_remain_distinct_and_conflicting_evidence_is_unknown():
    assert classify("dns01: error presenting token (x): DNS update failed: REFUSED").category == "DNS_UPDATE_FAILURE"
    assert classify("dns01: time limit exceeded: last error: propagation: time limit exceeded").category == "DNS_PROPAGATION_FAILURE"
    e = classify("invalid challenge: " + PROBLEM + "\nDNS update failed: REFUSED")
    assert e.category == "UNKNOWN_ACME_ERROR" and e.stage is None
