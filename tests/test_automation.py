"""Offline Automation coverage; no production configuration or network is used."""
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch
import json

import pytest

from vcf_cert_renewer import cli, renewer
from vcf_cert_renewer.certificates import (
    AmbiguousCertificateError, CertificateNotFoundError,
    find_automation_certificate, resolve_fleet_certificate)
from vcf_cert_renewer.client import (CsrNotFoundError, VcfApiClient, WorkflowFailedError)
from vcf_cert_renewer.renewer import RenewalExecutionError
from vcf_cert_renewer.components import adapter_for, discover_inventory
from vcf_cert_renewer.config import Settings
from vcf_cert_renewer.importer import CertificateChainInfo, import_certificate_chain
from vcf_cert_renewer.replacer import TlsVerificationError, replace_certificate


def record(host="vcfa.example.com", key="external-resource", **changes):
    value = {
        "certificateResourceKey": key, "appliance": "VCF_AUTOMATION",
        "applianceFqdn": host, "issuedToCommonName": host,
        "vcfComponent": "ARIA", "vcfEndpoint": "service.example.test",
        "category": "TLS_CERT", "type": "EXTERNAL_CA",
        "subjectAlternativeNames": {"dns": [host], "ip": []},
        "daysToExpire": 691, "expiryDate": 1850893336000,
        "autoRenewState": "NOT_SUPPORTED",
        "certificateMetadata": {"certificatePurpose": "TLS_CERT",
                                "certificateChainRole": "LEAF",
                                "managementLevel": "CUSTOMER_MANAGED_FULL_MANAGEMENT"},
    }
    value.update(changes)
    return value


def internal_records():
    root = record("service.example.test", "root", type="VMCA", category="ROOT_CERT")
    root["certificateMetadata"]["certificateChainRole"] = "ROOT"
    return [root, record("service.example.test", "internal", type="VMCA")]


@pytest.mark.parametrize("hostname", ["vcfa.example.com", "ops.example.test",
                                      "nsxt.example.test", "idbroker.example.test",
                                      "catalog.other.test"])
def test_selection_is_semantic_regardless_of_hostname(hostname):
    external = record(hostname)
    assert find_automation_certificate([*internal_records(), external]) == external
    assert adapter_for(external).name == "automation"
    for internal in internal_records():
        assert adapter_for(internal).capability.value == "DISCOVER_ONLY"


@pytest.mark.parametrize("changes", [{"type": "VMCA"}, {"category": "ROOT_CERT"},
                                     {"appliance": "VCF_SERVICES_RUNTIME"},
                                     {"certificateMetadata": {}},
                                     {"appliance": "LOG_MANAGEMENT"}])
def test_out_of_scope_records_are_not_selected(changes):
    with pytest.raises(CertificateNotFoundError):
        find_automation_certificate([record(**changes)])


def test_no_matching_certificate():
    with pytest.raises(CertificateNotFoundError):
        find_automation_certificate(internal_records())


@pytest.mark.parametrize("same_host", [True, False])
def test_ambiguous_certificates_fail_even_for_explicit_hostname(same_host):
    first = record()
    second = record(first["applianceFqdn"] if same_host else "other.example.test", "other-key")
    with pytest.raises(AmbiguousCertificateError):
        resolve_fleet_certificate([first, second], first["applianceFqdn"])


@pytest.mark.parametrize("host", ["../bad", "https://vcfa.example.com", "127.0.0.1", "", "bad/name"])
def test_invalid_endpoint_fails_closed(host):
    with pytest.raises(ValueError):
        find_automation_certificate([record(host)])


def test_monitor_only_fails_closed():
    item = record()
    item["certificateMetadata"]["managementLevel"] = "CUSTOMER_MANAGED_MONITOR_ONLY"
    with pytest.raises(ValueError):
        find_automation_certificate([item])


def test_selected_resource_is_revalidated_and_internal_hostname_refused():
    with pytest.raises(ValueError, match="identity changed"):
        resolve_fleet_certificate([record(key="new-key")], "vcfa.example.com",
                                  expected_certificate=record())
    with pytest.raises(ValueError, match="not the external"):
        resolve_fleet_certificate([record(), *internal_records()], "service.example.test")


@pytest.mark.parametrize("days,force,expected", [(31, False, "NO_RENEWAL_NEEDED"),
                                                (30, False, "RENEWAL_REQUIRED"),
                                                (29, False, "RENEWAL_REQUIRED"),
                                                (90, True, "RENEWAL_REQUIRED")])
def test_same_live_threshold(days, force, expected):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    settings = Settings("token", "https://ops.example.test", True, 30, "test")
    result = renewer.renewal_plan(settings, record()["applianceFqdn"], force=force, now=now,
                                 inspect=Mock(return_value={"notAfter": (now + timedelta(days=days)).isoformat()}))
    assert result["result"] == expected


def test_inventory_marks_ambiguity_as_plan_only():
    client = Mock()
    client.query_certificates.return_value = [record(), record("other.example.test", "other")]
    inventory = discover_inventory(client, verifier=Mock(return_value={}))
    assert all(item["renewalCapability"] == "PLAN_ONLY" for item in inventory)
    assert all(not item["supportsReplace"] for item in inventory)
    assert inventory[0]["certificateType"] == "EXTERNAL_CA"


@pytest.fixture
def batch(monkeypatch):
    monkeypatch.setenv("ACME_MODE", "production")
    monkeypatch.setenv("VCF_VERIFY_TLS", "true")
    monkeypatch.setenv("ACME_EMAIL", "unit@localhost")
    monkeypatch.setenv("DNSUPDATE_NAMESERVER", "192.0.2.53:53")
    monkeypatch.setenv("DNSUPDATE_TSIG_KEY", "unit-key")
    monkeypatch.setenv("DNSUPDATE_TSIG_SECRET", "unit-secret")
    monkeypatch.setattr(cli, "_discover_automation", Mock(return_value=record()))
    planner = Mock(side_effect=lambda settings, fqdn, force=False: {
        "targetFqdn": fqdn, "result": "RENEWAL_REQUIRED", "force": force})
    executor = Mock(return_value={"result": "RENEWED"})
    monkeypatch.setattr(cli, "renewal_plan", planner)
    monkeypatch.setattr(cli, "_execute_supported_renewal", executor)
    return planner, executor


def test_all_includes_discovered_automation(batch, capsys):
    planner, executor = batch
    assert cli.main(["renew", "--all", "--yes"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["counts"]["RENEWED"] == 5
    assert executor.call_args.kwargs["certificate"] == record()
    assert all("notice" not in plan for plan in result["plans"])
    assert result["plans"][-1]["componentDisplayName"] == "VCF Automation"
    assert planner.call_args.kwargs["force"] is False


def test_batch_no_match_does_not_fail_others(batch, capsys):
    cli._discover_automation.side_effect = CertificateNotFoundError("none")
    assert cli.main(["renew", "--all", "--yes"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["discovery"]["status"] == "NOT_DISCOVERED"
    assert result["counts"]["RENEWED"] == 4


def test_batch_ambiguity_does_not_block_others(batch, capsys):
    cli._discover_automation.side_effect = AmbiguousCertificateError("ambiguous")
    assert cli.main(["renew", "--all", "--yes"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["counts"] == {"RENEWED": 4, "FAILED": 1, "SKIPPED": 0}
    assert "Ambiguous" in result["summary"][0]["reason"]


def test_batch_skip_and_approval_gate(batch, capsys):
    planner, executor = batch
    assert cli.main(["renew", "--all"]) == 0
    executor.assert_not_called()
    assert json.loads(capsys.readouterr().out)["result"] == "PLAN_ONLY"
    planner.side_effect = lambda settings, fqdn, force=False: {
        "targetFqdn": fqdn, "result": "NO_RENEWAL_NEEDED"}
    assert cli.main(["renew", "--all", "--yes"]) == 0
    executor.assert_not_called()
    assert json.loads(capsys.readouterr().out)["counts"]["SKIPPED"] == 5


def test_explicit_discovered_fqdn_uses_metadata(batch, capsys):
    _, executor = batch
    assert cli.main(["renew", "vcfa.example.com", "--yes"]) == 0
    assert executor.call_args.kwargs["certificate"] == record()


@pytest.fixture
def workflow(monkeypatch, tmp_path):
    settings = Settings("token", "https://ops.example.test", True, 30, "test", output_dir=tmp_path)
    client = Mock()
    client.query_certificates.return_value = [record(), *internal_records()]
    client.create_csr.return_value = ("csr-job", {"state": "COMPLETED"})
    client._state.side_effect = VcfApiClient._state
    client.fetch_csr.side_effect = [CsrNotFoundError("none"), "FAKE CSR"]
    mocks = {}
    for name in ("sign_csr", "build_vcf_fullchain", "import_certificate_chain",
                 "replace_certificate", "verify_https_certificate", "poll_workflow"):
        mocks[name] = Mock()
        monkeypatch.setattr(renewer, name, mocks[name])
    mocks["sign_csr"].return_value = {"leafPath": str(tmp_path / "leaf"),
        "issuerPath": str(tmp_path / "issuer"), "sha256Thumbprint": "new-fingerprint"}
    (tmp_path / "vcfa.example.com.vcf-fullchain.pem").write_bytes(b"FAKE CHAIN")
    mocks["import_certificate_chain"].return_value = {"result": "IMPORTED"}
    mocks["replace_certificate"].return_value = ("replace-job", {"state": "INPROGRESS"}, b"FAKE CHAIN")
    mocks["poll_workflow"].return_value = {"state": "COMPLETED"}
    mocks["verify_https_certificate"].return_value = {"verified": True, "sha256_thumbprint": "new-fingerprint"}
    return settings, client, mocks


def test_shared_fleet_success_requires_live_verification(workflow):
    settings, client, mocks = workflow
    result = renewer.execute_renewal(client, settings, "vcfa.example.com", certificate=record())
    assert result["result"] == "RENEWED"
    client.create_csr.assert_called_once()
    assert client.create_csr.call_args.args == (record(),)
    assert callable(client.create_csr.call_args.kwargs["on_mutation_attempt"])
    assert client.fetch_csr.call_count == 2
    assert client.fetch_csr.call_args.kwargs["strict_dns_san"] is True
    for name in ("import_certificate_chain", "replace_certificate"):
        assert mocks[name].call_args.kwargs["expected_certificate"] == record()
    mocks["verify_https_certificate"].assert_called_once_with("vcfa.example.com", b"FAKE CHAIN")
    # No post-replacement inventory refresh is required.
    assert client.query_certificates.call_count == 1


@pytest.mark.parametrize("stage,exception", [
    ("sign_csr", ValueError("ACME failed")),
    ("import_certificate_chain", ValueError("import failed")),
    ("replace_certificate", WorkflowFailedError("replace failed")),
    ("poll_workflow", WorkflowFailedError("workflow failed")),
    ("verify_https_certificate", TlsVerificationError("live mismatch")),
])
def test_failure_never_reports_success_or_advances(workflow, stage, exception):
    settings, client, mocks = workflow
    mocks[stage].side_effect = exception
    with pytest.raises(RenewalExecutionError) as caught:
        renewer.execute_renewal(client, settings, "vcfa.example.com", certificate=record())
    assert isinstance(caught.value.cause, type(exception))
    if stage == "sign_csr":
        assert caught.value.phase == "ACME signing"
        assert caught.value.completed_mutations == ("Fleet CSR generated",)
        assert not caught.value.replacement_requested
    if stage == "import_certificate_chain":
        assert caught.value.completed_mutations == ("Fleet CSR generated",)
    if stage == "verify_https_certificate":
        assert caught.value.replacement_completed
    stages = ["sign_csr", "import_certificate_chain", "replace_certificate", "poll_workflow", "verify_https_certificate"]
    for later in stages[stages.index(stage) + 1:]:
        mocks[later].assert_not_called()


def test_changed_identity_prevents_csr(workflow):
    settings, client, _ = workflow
    client.query_certificates.return_value = [record(key="changed")]
    with pytest.raises(RenewalExecutionError) as caught:
        renewer.execute_renewal(client, settings, "vcfa.example.com", certificate=record())
    assert caught.value.completed_mutations == ()
    client.create_csr.assert_not_called()


def test_import_failed_response_is_not_success(monkeypatch):
    client = VcfApiClient("https://ops.example.test", "fake")
    client.query_certificates = Mock(return_value=[record()])
    client.fetch_csr = Mock(return_value="FAKE CSR")
    client._request = Mock(return_value=Mock(json=Mock(return_value={"state": "FAILED"})))
    monkeypatch.setattr("vcf_cert_renewer.importer.validate_chain_for_csr",
                        Mock(return_value=CertificateChainInfo("vcfa.example.com", ("vcfa.example.com",), 1)))
    with pytest.raises(ValueError, match="import failed"):
        import_certificate_chain(client, b"FAKE", "vcfa.example.com", expected_certificate=record())


@pytest.mark.parametrize("operation", [import_certificate_chain, replace_certificate])
def test_later_mutations_reject_changed_identity(operation):
    client = Mock()
    client.query_certificates.return_value = [record(key="changed")]
    args = (client, b"FAKE", "vcfa.example.com") if operation is import_certificate_chain else (client, "vcfa.example.com")
    with pytest.raises(ValueError, match="identity changed"):
        operation(*args, expected_certificate=record())
    client._request.assert_not_called()


def test_all_inventory_pages_are_checked_for_ambiguity():
    client = VcfApiClient("https://ops.example.test", "fake")
    client._request = Mock(side_effect=[
        Mock(json=Mock(return_value={"vcfCertificateModels": [record()],
                                    "pageInfo": {"totalCount": 2, "page": 0}})),
        Mock(json=Mock(return_value={"vcfCertificateModels": [record("second.example.test", "second")],
                                    "pageInfo": {"totalCount": 2, "page": 1}})),
    ])
    with pytest.raises(AmbiguousCertificateError):
        find_automation_certificate(client.query_certificates(page_size=1))
    assert client._request.call_args.kwargs["params"]["page"] == 1


@pytest.mark.parametrize("phase", ["csr", "replace"])
def test_immediate_failed_workflow_is_terminal(workflow, phase):
    settings, client, mocks = workflow
    if phase == "csr":
        client.create_csr.return_value = ("csr-job", {"state": "FAILED"})
    else:
        mocks["replace_certificate"].return_value = ("replace-job", {"state": "FAILED"}, b"FAKE")
    with pytest.raises(RenewalExecutionError) as caught:
        renewer.execute_renewal(client, settings, "vcfa.example.com", certificate=record())
    assert isinstance(caught.value.cause, WorkflowFailedError)
    mocks["verify_https_certificate"].assert_not_called()
    if phase == "csr":
        assert caught.value.completed_mutations == ("Fleet CSR generation requested",)
        mocks["sign_csr"].assert_not_called()
    else:
        assert caught.value.replacement_requested
        assert not caught.value.replacement_completed


def test_metadata_route_uses_shared_fleet_engine(monkeypatch):
    client = Mock()
    fleet = Mock(return_value={"result": "RENEWED"})
    monkeypatch.setattr(cli, "exchange_token", Mock(return_value="fake"))
    monkeypatch.setattr(cli, "_client", Mock(return_value=client))
    monkeypatch.setattr(cli, "execute_renewal", fleet)
    domain = Mock(side_effect=AssertionError("Wrong API family"))
    monkeypatch.setattr(cli, "execute_domain_renewal", domain)
    settings = Settings("token", "https://ops.example.test", True, 30, "test",
                        acme_email="unit@localhost", dns_nameserver="192.0.2.53:53",
                        dns_tsig_key="unit-key", dns_tsig_secret="unit-secret")
    item = record("vcenter.example.test")
    cli._execute_supported_renewal(settings, item["applianceFqdn"], poll_interval=0,
                                  poll_timeout=1, certificate=item)
    assert fleet.call_args.kwargs["certificate"] == item
    domain.assert_not_called()


def test_real_fleet_pipeline_with_fake_api_and_live_tls(monkeypatch, tmp_path):
    """Real selection/CSR/import/PUT/verifier; fake network and ACME boundaries."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from vcf_cert_renewer import replacer

    host = "vcfa.example.com"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, host)])
    san = x509.SubjectAlternativeName([x509.DNSName(host)])
    csr = x509.CertificateSigningRequestBuilder().subject_name(name).add_extension(san, False).sign(key, hashes.SHA256())
    now = datetime.now(timezone.utc)
    leaf = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=90))
            .add_extension(san, False).sign(key, hashes.SHA256()))
    pem = leaf.public_bytes(serialization.Encoding.PEM)
    fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
    client = VcfApiClient("https://fleet.example.test", "fake", verify_tls=True)
    calls = []

    csr_reads = 0
    def fake_request(method, path, **kwargs):
        nonlocal csr_reads
        calls.append((method, path, kwargs))
        if path.endswith("/certificates/query"):
            data = {"vcfCertificateModels": [record(), *internal_records()]}
        elif path.endswith("/csrs") and method == "POST":
            assert kwargs["json"]["certificateId"] == "external-resource"
            data = {"requestId": "csr-job", "state": "COMPLETED"}
        elif path.endswith("/csrs") and method == "GET":
            assert kwargs["params"]["certificateId"] == "external-resource"
            csr_reads += 1
            entries = [] if csr_reads == 1 else [{
                "commonName": host, "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
                "certificateId": "external-resource", "applianceType": "VCF_AUTOMATION",
                "applianceFqdn": host, "vcfComponent": "ARIA"}]
            data = {"certificateSignatureInfo": entries}
        elif path == "/suite-api/api/certificate":
            data = {"certificates": [{"id": "import-id", "thumbprint": fingerprint,
                                     "certificate": pem.decode()}]}
        elif method == "PUT" and path.endswith("/certificates/external-resource"):
            assert kwargs["json"] == {"caType": "EXTERNAL_CA", "certificateChain": pem.decode()}
            data = {"requestId": "replace-job", "state": "COMPLETED"}
        else:
            raise AssertionError((method, path))
        return Mock(json=Mock(return_value=data), headers={})

    monkeypatch.setattr(client, "_request", fake_request)
    monkeypatch.setattr(renewer, "sign_csr", Mock(return_value={
        "leafPath": str(tmp_path / "leaf"), "issuerPath": str(tmp_path / "issuer"),
        "sha256Thumbprint": fingerprint}))
    monkeypatch.setattr(renewer, "build_vcf_fullchain", lambda leaf_path, issuer_path, output: output.write_bytes(pem))
    fetch = Mock(return_value=leaf)
    monkeypatch.setattr(replacer, "_fetch_https_certificate", fetch)
    settings = Settings("token", "https://fleet.example.test", True, 30, "fake", output_dir=tmp_path)
    result = renewer.execute_renewal(client, settings, host, certificate=record())
    assert result["result"] == "RENEWED"
    assert result["liveHttpsCertificate"]["sha256_thumbprint"] == fingerprint
    assert result["liveHttpsCertificate"]["verified"] is True
    assert sum(method == "PUT" for method, _, _ in calls) == 1
    assert calls[-1][1].endswith("/certificates/external-resource")
    fetch.assert_called_once_with(host, 443, 15)


def test_vcfa_plan_failure_isolated(batch, capsys):
    planner, executor = batch
    def plan(settings, fqdn, force=False):
        if fqdn == record()["applianceFqdn"]:
            raise TlsVerificationError("unreachable")
        return {"targetFqdn": fqdn, "result": "RENEWAL_REQUIRED"}
    planner.side_effect = plan
    assert cli.main(["renew", "--all", "--yes"]) == 1
    assert executor.call_count == 4
    assert json.loads(capsys.readouterr().out)["counts"]["FAILED"] == 1


def test_batch_reports_live_verification_failure(batch, capsys):
    _, executor = batch
    def execute(settings, fqdn, **kwargs):
        if kwargs.get("certificate"):
            raise TlsVerificationError("unexpected live certificate")
        return {"result": "RENEWED"}
    executor.side_effect = execute
    assert cli.main(["renew", "--all", "--yes"]) == 1
    result = json.loads(capsys.readouterr().out)
    failure = result["summary"][-1]
    assert failure["status"] == "FAILED"
    assert failure["errorType"] == "TlsVerificationError"
    assert failure["targetFqdn"] == record()["applianceFqdn"]


def test_automation_plan_is_read_only_and_labelled(monkeypatch):
    from vcf_cert_renewer import plan
    client = Mock()
    client.query_certificates.return_value = [record(), *internal_records()]
    client.fetch_csr.return_value = "FAKE EXISTING CSR"
    monkeypatch.setattr(plan, "list_imported_certificates", Mock(return_value=[]))
    monkeypatch.setattr(plan, "inspect_https_certificate", Mock(return_value={"notAfter": "2030-01-01T00:00:00Z"}))
    settings = Settings("token", "https://ops.example.test", True, 30, "fake")
    result = plan.build_plan(client, settings, record()["applianceFqdn"])
    assert result["componentDisplayName"] == "VCF Automation"
    assert result["certificateType"] == "EXTERNAL_CA"
    assert result["notice"] == "No changes have been made."
    client.create_csr.assert_not_called()
    client._request.assert_not_called()


@pytest.mark.parametrize("payload", [{}, {"certificates": []}])
def test_unconfirmed_import_refuses_success(monkeypatch, payload):
    client = VcfApiClient("https://ops.example.test", "fake")
    client.query_certificates = Mock(return_value=[record()])
    client.fetch_csr = Mock(return_value="FAKE")
    client._request = Mock(return_value=Mock(json=Mock(return_value=payload)))
    monkeypatch.setattr("vcf_cert_renewer.importer.validate_chain_for_csr",
                        Mock(return_value=CertificateChainInfo("vcfa.example.com", ("vcfa.example.com",), 1)))
    with pytest.raises(ValueError, match="did not confirm"):
        import_certificate_chain(client, b"FAKE", "vcfa.example.com", expected_certificate=record())



def test_existing_matching_csr_is_reused_without_new_mutation(workflow):
    settings, client, mocks = workflow
    client.fetch_csr.side_effect = None
    client.fetch_csr.return_value = "MATCHING EXISTING CSR"
    result = renewer.execute_renewal(client, settings, "vcfa.example.com", certificate=record())
    assert result["reusedExistingCsr"] is True
    client.create_csr.assert_not_called()
    client.fetch_csr.assert_called_once()
    assert "Fleet CSR generated" not in result["completedMutations"]
    assert "Signed certificate imported into Fleet" in result["completedMutations"]
    assert result["certificateReplacementPerformed"] is True


def test_cli_failure_reports_completed_mutations_and_no_rollback(monkeypatch, capsys):
    from vcf_cert_renewer.renewer import RenewalExecutionError
    settings = Settings("token", "https://ops.example.test", True, 30, "fake",
                        acme_mode="production")
    monkeypatch.setattr(cli.Settings, "load", Mock(return_value=settings))
    failure = RenewalExecutionError("ACME signing", ["Fleet CSR generated"], False, False,
                                    False, ValueError("accountDoesNotExist; [REDACTED]"))
    monkeypatch.setattr(cli, "_discover_automation", Mock(return_value=record()))
    monkeypatch.setattr(cli, "_execute_supported_renewal", Mock(side_effect=failure))
    monkeypatch.setattr(cli, "renewal_plan", Mock(return_value={
        "result": "RENEWAL_REQUIRED", "notice": "No changes have been made."}))
    assert cli.main(["renew", "vcfa.example.com", "--force", "--yes"]) == 1
    output = capsys.readouterr().out
    decoder = json.JSONDecoder()
    plan, end = decoder.raw_decode(output.lstrip())
    result, _ = decoder.raw_decode(output.lstrip()[end:].lstrip())
    assert plan["notice"] == "Preflight complete; renewal has not started."
    assert result["phase"] == "ACME signing"
    assert result["changesAlreadyMade"] == ["Fleet CSR generated"]
    assert result["mutatingChangesMade"] is True
    assert result["certificateReplacementPerformed"] is False
    assert "No rollback was performed" in result["notice"]
    assert "No changes have been made" not in output



def test_mutation_request_timeout_is_reported_as_unknown(workflow):
    settings, client, _ = workflow
    client.fetch_csr.side_effect = [CsrNotFoundError("none")]
    def lost_after_send(certificate, *, on_mutation_attempt):
        on_mutation_attempt()
        raise OSError("connection lost after request")
    client.create_csr.side_effect = lost_after_send
    with pytest.raises(RenewalExecutionError) as caught:
        renewer.execute_renewal(client, settings, "vcfa.example.com", certificate=record())
    assert caught.value.mutation_outcome_unknown is True
    assert caught.value.completed_mutations == ()
    assert caught.value.replacement_requested is False



def test_bad_signer_configuration_fails_before_any_fleet_mutation(monkeypatch, capsys):
    settings = Settings("token", "https://ops.example.test", True, 30, "fixture")
    monkeypatch.setattr(cli.Settings, "load", Mock(return_value=settings))
    monkeypatch.setattr(cli, "_discover_automation", Mock(return_value=record()))
    monkeypatch.setattr(cli, "renewal_plan", Mock(return_value={"result": "RENEWAL_REQUIRED"}))
    client_factory = Mock(side_effect=AssertionError("API client must not be created"))
    monkeypatch.setattr(cli, "_client", client_factory)
    assert cli.main(["renew", "vcfa.example.com", "--force", "--yes"]) == 1
    output = capsys.readouterr().out
    decoder = json.JSONDecoder()
    _, end = decoder.raw_decode(output.lstrip())
    result, _ = decoder.raw_decode(output.lstrip()[end:].lstrip())
    assert result["phase"] == "SIGNER_CONFIGURATION"
    assert result["mutatingChangesMade"] is False
    assert result["mutationAttempted"] is False
    assert result["notice"] == "No changes have been made."
    client_factory.assert_not_called()


def test_internal_automation_vmca_remains_discover_only_and_cannot_mutate(workflow):
    settings, client, mocks = workflow
    internal = internal_records()[1]
    client.query_certificates.return_value = [internal]
    with pytest.raises(RenewalExecutionError):
        renewer.execute_renewal(client, settings, "service.example.test",
                                certificate=internal)
    assert adapter_for(internal).capability.value == "DISCOVER_ONLY"
    client.create_csr.assert_not_called()
    for name in ("import_certificate_chain", "replace_certificate"):
        mocks[name].assert_not_called()
    root = internal_records()[0]
    assert adapter_for(root).capability.value == "DISCOVER_ONLY"


def test_vra_service_vmca_tls_stays_discover_only():
    runtime = record("vra-service.example.test", appliance="VCF_SERVICES_RUNTIME",
                     type="VMCA")
    assert adapter_for(runtime).capability.value == "DISCOVER_ONLY"

@pytest.mark.parametrize("target", [
    record("service.example.test", "vmca-tls", type="VMCA"),
    record("service.example.test", "vmca-root", type="VMCA", category="ROOT_CERT"),
    record("service.example.test", "runtime-tls", appliance="VCF_SERVICES_RUNTIME"),
])
@pytest.mark.parametrize("command", ["generate-csr", "import", "replace"])
def test_explicit_fleet_mutations_refuse_internal_automation_targets(
        monkeypatch, tmp_path, capsys, target, command):
    settings = Settings("token", "https://ops.example.test", True, 30, "test",
                        output_dir=tmp_path)
    monkeypatch.setattr(cli.Settings, "load", Mock(return_value=settings))
    monkeypatch.setattr(cli, "exchange_token", Mock(return_value="fixture-token"))
    client = Mock()
    client.query_certificates.return_value = [target]
    client.create_csr = Mock()
    client._request = Mock()
    monkeypatch.setattr(cli, "_client", Mock(return_value=client))

    host = target["applianceFqdn"]
    if command == "generate-csr":
        argv = [command, host]
    elif command == "import":
        argv = [command, host, str(tmp_path / "not-read.pem")]
    else:
        argv = [command, host, "--thumbprint", "fixture"]
    assert cli.main(argv) != 0
    capsys.readouterr()
    client.create_csr.assert_not_called()
    client._request.assert_not_called()


def test_explicit_generate_csr_keeps_external_automation_available(monkeypatch, tmp_path, capsys):
    target = record()
    settings = Settings("token", "https://ops.example.test", True, 30, "test",
                        output_dir=tmp_path)
    monkeypatch.setattr(cli.Settings, "load", Mock(return_value=settings))
    monkeypatch.setattr(cli, "exchange_token", Mock(return_value="fixture-token"))
    client = Mock()
    client.query_certificates.return_value = [target]
    client.create_csr.return_value = ("job", {"state": "COMPLETED"})
    client._state.side_effect = VcfApiClient._state
    client.fetch_csr.return_value = "fixture CSR"
    monkeypatch.setattr(cli, "_client", Mock(return_value=client))
    assert cli.main(["generate-csr", target["applianceFqdn"], "--output",
                     str(tmp_path)]) == 0
    capsys.readouterr()
    client.create_csr.assert_called_once_with(target)
