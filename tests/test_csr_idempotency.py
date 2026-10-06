"""Offline Fleet CSR identity and reuse validation."""
from unittest.mock import Mock
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from vcf_cert_renewer.client import AmbiguousCsrError, CsrNotFoundError, VcfApiClient


def csr_pem(host="vcfa.example.com"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, host)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), False)
        .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def entry(csr=None, *, certificate_id="resource-1", appliance="VCF_AUTOMATION",
          fqdn="vcfa.example.com", component="ARIA", common_name="vcfa.example.com"):
    return {"commonName": common_name, "csr": csr or csr_pem(fqdn),
            "certificateId": certificate_id, "applianceType": appliance,
            "applianceFqdn": fqdn, "vcfComponent": component}


def client_with(entries):
    client = VcfApiClient("https://fleet.example.test", "fixture-token")
    response = Mock()
    response.json.return_value = {"certificateSignatureInfo": entries}
    client.session.get = Mock(return_value=response)
    return client


def test_matching_existing_csr_is_reused_for_resource_and_endpoint():
    client = client_with([entry()])
    result = client.fetch_csr("resource-1", "vcfa.example.com",
                              expected_fqdn="vcfa.example.com", strict_dns_san=True,
                              appliance="VCF_AUTOMATION", component="ARIA")
    assert "BEGIN CERTIFICATE REQUEST" in result
    params = client.session.get.call_args.kwargs["params"]
    assert params["certificateId"] == "resource-1"
    assert params["commonName"] == "vcfa.example.com"


def test_mismatched_endpoint_or_resource_is_not_reused():
    entries = [
        entry(csr_pem("other.example.test")),
        entry(certificate_id="historical-resource"),
        entry(appliance="VCF_SERVICES_RUNTIME"),
        entry(fqdn="another.example.test"),
        {"commonName": "vcfa.example.com", "csr": csr_pem()},
    ]
    for candidate in entries:
        with pytest.raises(CsrNotFoundError):
            client_with([candidate]).fetch_csr(
                "resource-1", "vcfa.example.com", expected_fqdn="vcfa.example.com",
                strict_dns_san=True, appliance="VCF_AUTOMATION", component="ARIA")


def test_known_automation_appliance_aliases_match_only_with_exact_resource_and_endpoint():
    client = client_with([entry(appliance="VCF_AUTOMATION")])
    result = client.fetch_csr("resource-1", "vcfa.example.com",
                              expected_fqdn="vcfa.example.com", strict_dns_san=True,
                              appliance="ARIA_AUTOMATION", component="ARIA")
    assert "BEGIN CERTIFICATE REQUEST" in result


def test_ambiguous_matching_csrs_fail_safely():
    client = client_with([entry(), entry()])
    with pytest.raises(AmbiguousCsrError):
        client.fetch_csr("resource-1", "vcfa.example.com",
                         expected_fqdn="vcfa.example.com", strict_dns_san=True,
                         appliance="VCF_AUTOMATION", component="ARIA")


def test_empty_csr_inventory_allows_new_request():
    client = client_with([])
    with pytest.raises(CsrNotFoundError):
        client.fetch_csr("resource-1", "vcfa.example.com",
                         expected_fqdn="vcfa.example.com", strict_dns_san=True,
                         appliance="VCF_AUTOMATION", component="ARIA")


def test_completed_renewal_resource_rotation_ignores_retained_csr_and_batch_recovers(
        monkeypatch, tmp_path, capsys):
    """Exercise real importer validation across Fleet resource rotation/history."""
    from datetime import datetime, timedelta, timezone
    from cryptography.x509.oid import NameOID
    from vcf_cert_renewer import cli, renewer
    from vcf_cert_renewer.config import Settings
    from vcf_cert_renewer.plan import build_plan

    fqdn = "vcfa.example.com"

    def active_certificate(resource_id, appliance="VCF_AUTOMATION"):
        return {
            "certificateResourceKey": resource_id,
            "appliance": appliance, "applianceFqdn": fqdn,
            "issuedToCommonName": fqdn, "vcfComponent": "ARIA",
            "category": "TLS_CERT", "type": "EXTERNAL_CA",
            "subjectAlternativeNames": {"dns": [fqdn], "ip": []},
            "certificateMetadata": {"certificatePurpose": "TLS_CERT",
                "certificateChainRole": "LEAF",
                "managementLevel": "CUSTOMER_MANAGED_FULL_MANAGEMENT"},
        }

    def make_csr(host):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        value = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), False)
            .sign(key, hashes.SHA256()))
        pem = value.public_bytes(serialization.Encoding.PEM).decode()
        keys[pem] = key
        return pem

    initial = active_certificate("resource-before-replacement")
    active = {"record": initial}
    csr_history = []
    keys = {}
    imported = []
    posts = {"csr": 0, "import": 0, "replace": 0}
    client = VcfApiClient("https://fleet.example.test", "fixture-token")

    def response(payload):
        value = Mock()
        value.json.return_value = payload
        value.headers = {}
        return value

    def request(method, path, **kwargs):
        if path.endswith("/certificates/query"):
            return response({"vcfCertificateModels": [active["record"]]})
        if path.endswith("/certificate-management/csrs") and method == "GET":
            # Deliberately ignore certificateId to model retained Fleet history.
            return response({"certificateSignatureInfo": list(csr_history)})
        if path.endswith("/certificate-management/csrs") and method == "POST":
            resource_id = kwargs["json"]["certificateId"]
            posts["csr"] += 1
            csr_history.append(entry(csr=make_csr(fqdn), certificate_id=resource_id))
            return response({"id": f"csr-job-{posts['csr']}", "state": "COMPLETED"})
        if path == "/suite-api/api/certificate" and method == "POST":
            posts["import"] += 1
            chain = kwargs["files"]["certificateFile"][1]
            leaf = x509.load_pem_x509_certificate(chain)
            thumb = leaf.fingerprint(hashes.SHA256()).hex()
            item = {"id": f"imported-{posts['import']}", "thumbprint": thumb,
                    "issuedTo": f"CN={fqdn}", "certificate": chain.decode()}
            imported.append(item)
            return response({"state": "COMPLETED", "certificates": [item]})
        if path == "/suite-api/api/certificate" and method == "GET":
            return response({"certificates": list(imported)})
        if method == "PUT" and "/certificate-management/certificates/" in path:
            posts["replace"] += 1
            active["record"] = active_certificate(
                f"resource-after-replacement-{posts['replace']}",
                appliance="ARIA_AUTOMATION")
            return response({"id": f"replace-job-{posts['replace']}",
                             "state": "COMPLETED"})
        raise AssertionError(f"unexpected fixture request: {method} {path}")

    client._request = Mock(side_effect=request)
    settings = Settings(
        "token", "https://fleet.example.test", True, 30, "fixture-token",
        acme_mode="production", acme_email="unit@localhost",
        dns_nameserver="192.0.2.53:53", dns_tsig_key="unit-key",
        dns_tsig_secret="unit-secret", output_dir=tmp_path)

    def sign(_settings, csr_path):
        csr = csr_path.read_text()
        request_csr = x509.load_pem_x509_csr(csr.encode())
        subject = request_csr.subject
        now = datetime.now(timezone.utc)
        leaf = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(request_csr.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=90))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(fqdn)]), False)
                .sign(keys[csr], hashes.SHA256()))
        leaf_path = tmp_path / "leaf.pem"
        leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        return {"leafPath": str(leaf_path), "issuerPath": str(leaf_path),
                "sha256Thumbprint": leaf.fingerprint(hashes.SHA256()).hex()}

    def build_chain(leaf, _issuer, destination):
        destination.write_bytes(leaf.read_bytes())

    monkeypatch.setattr(renewer, "sign_csr", sign)
    monkeypatch.setattr(renewer, "build_vcf_fullchain", build_chain)
    monkeypatch.setattr(renewer, "verify_https_certificate",
                        Mock(return_value={"verified": True}))

    first = renewer.execute_renewal(client, settings, fqdn, certificate=initial)
    assert first["result"] == "RENEWED"
    assert active["record"]["certificateResourceKey"] == "resource-after-replacement-1"
    assert len(csr_history) == 1
    assert csr_history[0]["certificateId"] == "resource-before-replacement"
    assert posts == {"csr": 1, "import": 1, "replace": 1}

    # Read-only planning sees the rotated resource and must not select retained CSR.
    monkeypatch.setattr("vcf_cert_renewer.plan.list_imported_certificates", Mock(return_value=[]))
    monkeypatch.setattr("vcf_cert_renewer.plan.inspect_https_certificate",
                        Mock(return_value={"notAfter": "2030-01-01T00:00:00Z"}))
    planned = build_plan(client, settings, fqdn)
    assert planned["activeLeafTlsCertificate"]["certificateResourceKey"] ==         "resource-after-replacement-1"
    assert planned["existingState"]["matchingCsrExists"] is False

    # Next scheduled batch reuses neither stale CSR nor stale resource identity.
    monkeypatch.setattr(cli.Settings, "load", Mock(return_value=settings))
    monkeypatch.setattr(cli, "_discover_automation", Mock(side_effect=lambda _settings: active["record"]))
    monkeypatch.setattr(cli, "renewal_plan", Mock(side_effect=lambda _settings, host, force=False: {
        "targetFqdn": host, "result": "RENEWAL_REQUIRED" if host == fqdn
        else "NO_RENEWAL_NEEDED", "force": force}))
    actual_execute = renewer.execute_renewal
    executions = []

    def execute(_settings_arg, host, **kwargs):
        result = actual_execute(client, _settings_arg, host, **kwargs)
        executions.append(result)
        return result

    monkeypatch.setattr(cli, "_execute_supported_renewal", execute)
    assert cli.main(["renew", "--all", "--yes"]) == 0
    batch_result = json.loads(capsys.readouterr().out)
    assert batch_result["result"] == "SUCCESS"
    assert batch_result["counts"]["RENEWED"] == 1
    assert executions[0]["reusedExistingCsr"] is False
    assert posts == {"csr": 2, "import": 2, "replace": 2}
    assert csr_history[-1]["certificateId"] == "resource-after-replacement-1"
    assert active["record"]["certificateResourceKey"] == "resource-after-replacement-2"
