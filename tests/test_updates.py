from io import BytesIO
import json
import ssl
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

import pytest

from vcf_cert_renewer import cli, monitoring, updates
from vcf_cert_renewer.sddc_install import _locked_state, _write


@pytest.mark.parametrize("old,new", [
    ("1.5.0", "v1.5.1"), ("1.9.0", "1.10.0"), ("1.5.0", "2.0.0"),
    ("1.5.1-rc.2", "1.5.1-rc.10"), ("1.5.1-rc.10", "1.5.1"),
])
def test_semver_order(old, new):
    assert updates.version(old) < updates.version(new)
    assert updates.version(new) > updates.version(old)


@pytest.mark.parametrize("invalid", ["", "beta", "1.5", "1.05.2", "1.5.0-rc.01", "1.5.0\n", None])
def test_invalid_versions(invalid):
    with pytest.raises(updates.CheckError, match="INVALID_VERSION"):
        updates.version(invalid)


def test_build_metadata_and_prefix_do_not_affect_precedence():
    assert updates.version("v1.5.1+build.9") == updates.version("1.5.1")


def release(tag="v1.5.2", **kwargs):
    return dict({"tag_name": tag, "published_at": "2026-11-24T13:00:00Z",
                 "draft": False, "prerelease": False,
                 "html_url": "https://ignored.invalid/untrusted"}, **kwargs)


def response(data, **headers):
    mock = Mock()
    mock.__enter__ = Mock(return_value=mock)
    mock.__exit__ = Mock(return_value=False)
    mock.read.return_value = data
    mock.headers = headers
    return mock


def test_stable_api_is_unauthenticated_and_uses_safe_canonical_url(monkeypatch):
    opener = Mock()
    opener.open.return_value = response(json.dumps(release()).encode(), ETag='"release"')
    monkeypatch.setattr(updates, "build_opener", lambda *_: opener)
    result, etag = updates.fetch(10, False, '"previous"')
    request = opener.open.call_args.args[0]
    assert request.full_url == updates.API + "/latest"
    assert request.get_header("If-none-match") == '"previous"'
    assert request.get_header("Authorization") is None
    assert request.get_header("User-agent").startswith("vcf-cert-renewer/")
    assert etag == '"release"'
    assert result["release_url"] == updates.WEB + "v1.5.2"


def test_prerelease_channel_ignores_drafts_and_selects_across_pages(monkeypatch):
    opener = Mock()
    opener.open.side_effect = [
        response(json.dumps([release("v8.0.0", draft=True), release("v1.5.2")]).encode(),
                 Link='<https://ignored.invalid>; rel="next"'),
        response(json.dumps([release("v2.0.0-rc.1", prerelease=True), release("junk")]).encode()),
    ]
    monkeypatch.setattr(updates, "build_opener", lambda *_: opener)
    result, _ = updates.fetch(10, True, None)
    assert result["latest_version"] == "2.0.0-rc.1"
    assert all(call.args[0].full_url.startswith(updates.API) for call in opener.open.call_args_list)


@pytest.mark.parametrize("body,code", [
    (b"bad json", "INVALID_JSON"), (b"[]", "INVALID_RELEASE_RESPONSE"),
    (b'{"draft":false}', "INVALID_RELEASE_RESPONSE"),
    (b"x" * (1024 * 1024 + 1), "RESPONSE_TOO_LARGE"),
    (json.dumps(release("v2.0.0-rc.1", prerelease=True)).encode(), "NO_ELIGIBLE_RELEASE"),
])
def test_invalid_api_replies(monkeypatch, body, code):
    monkeypatch.setattr(updates, "build_opener", lambda *_: Mock(open=Mock(return_value=response(body))))
    with pytest.raises(updates.CheckError, match=code):
        updates.fetch(10, False, None)


@pytest.mark.parametrize("status,headers,code", [
    (403, {}, "HTTP_403"), (403, {"X-RateLimit-Remaining": "0"}, "RATE_LIMITED"),
    (404, {}, "HTTP_404"), (429, {}, "RATE_LIMITED"), (500, {}, "HTTP_500"),
    (302, {}, "HTTP_302"),
])
def test_http_errors(monkeypatch, status, headers, code):
    error = HTTPError(updates.API, status, "sensitive", headers, BytesIO(b"external payload"))
    monkeypatch.setattr(updates, "build_opener", lambda *_: Mock(open=Mock(side_effect=error)))
    with pytest.raises(updates.CheckError, match=code):
        updates.fetch(10, False, None)


@pytest.mark.parametrize("error", [TimeoutError("timeout"), URLError("dns"),
                                   ssl.SSLCertVerificationError("tls")])
def test_network_errors(monkeypatch, error):
    monkeypatch.setattr(updates, "build_opener", lambda *_: Mock(open=Mock(side_effect=error)))
    with pytest.raises(updates.CheckError, match="NETWORK_OR_TLS_ERROR"):
        updates.fetch(10, False, None)


def test_304(monkeypatch):
    error = HTTPError(updates.API, 304, "", {}, BytesIO())
    monkeypatch.setattr(updates, "build_opener", lambda *_: Mock(open=Mock(side_effect=error)))
    assert updates.fetch(10, False, '"fixture"') == (None, '"fixture"')


def test_interval_dedup_outage_recovery_and_upgrade(tmp_path, monkeypatch):
    events = Mock()
    def parsed(tag):
        return updates._release(release(tag), False)
    fetch = Mock(side_effect=[
        (parsed("v1.5.2"), '"2"'), (None, '"2"'), updates.CheckError("RATE_LIMITED"),
        updates.CheckError("RATE_LIMITED"), (parsed("v1.5.3"), '"3"'), (None, '"3"'),
    ])
    monkeypatch.setattr(updates, "_bounded_fetch", fetch)
    updates.check(tmp_path, events, {})
    updates.check(tmp_path, events, {})
    assert fetch.call_count == 1
    for _ in range(3):
        updates.check(tmp_path, events, {}, force=True)
    cached = updates.status(tmp_path, {})
    assert cached["status"] == "CHECK_FAILED" and cached["update_available"]
    assert cached["latest_version"] == "1.5.2" and cached["cache_may_be_stale"]
    updates.check(tmp_path, events, {}, force=True)
    monkeypatch.setattr(updates, "__version__", "1.5.3")
    assert updates.status(tmp_path, {})["status"] == "UP_TO_DATE"
    updates.check(tmp_path, events, {}, force=True)
    assert [c.args[0] for c in events.emit.call_args_list] == [
        "VCF-6000", "VCF-6020", "VCF-6030", "VCF-6000", "VCF-6010"]
    assert updates.status(tmp_path, {})["consecutive_failures"] == 0


def test_manual_status_and_invalid_optional_configuration(tmp_path, monkeypatch, capsys):
    settings = SimpleNamespace(output_dir=tmp_path, renew_before_days=30)
    monkeypatch.setattr(cli.Settings, "load", lambda **_: settings)
    monkeypatch.setattr(monitoring, "scheduled", Mock(return_value=0))
    fetch = Mock(return_value=(updates._release(release(), False), None))
    monkeypatch.setattr(updates, "_bounded_fetch", fetch)
    assert cli.main(["check-update", "--json"]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["software_update"]["update_available"]
    assert json.loads(out.err)["event_id"] == "VCF-6000"
    monitoring.scheduled.assert_not_called()
    assert cli.main(["status", "--all", "--json"]) == 1
    assert "software_update" in json.loads(capsys.readouterr().out)
    assert fetch.call_count == 1
    monkeypatch.setenv("UPDATE_CHECK_ENABLED", "false")
    assert cli.main(["check-update", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["software_update"]["status"] == "DISABLED"
    assert fetch.call_count == 1
    monkeypatch.setenv("UPDATE_CHECK_ENABLED", "true")
    monkeypatch.setenv("UPDATE_CHECK_TIMEOUT_SECONDS", "99999")
    assert cli.main(["check-update", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["software_update"]["error_code"] == "INVALID_UPDATE_CHECK_TIMEOUT_SECONDS"


def test_scheduler_health_is_independent_of_update_failures(tmp_path, monkeypatch, capsys):
    settings = SimpleNamespace(output_dir=tmp_path, renew_before_days=30)
    monkeypatch.setattr(cli.Settings, "load", lambda **_: settings)
    with _locked_state(tmp_path, ".scheduler") as fd:
        _write(fd, {"version": 1, "targets": {}, "last_completion": monitoring.now()})
    steps = []
    monkeypatch.setattr(monitoring, "scheduled", lambda *a: steps.append("reconciled") or 0)
    def fail(*_):
        steps.append("advisory")
        raise updates.CheckError("NETWORK_OR_TLS_ERROR")
    monkeypatch.setattr(updates, "_bounded_fetch", fail)
    assert cli.main(["scheduled"]) == 0
    assert steps == ["reconciled", "advisory"]
    assert monitoring.status(settings, {})["healthy"]
    assert json.loads(capsys.readouterr().out)["event_id"] == "VCF-6020"
