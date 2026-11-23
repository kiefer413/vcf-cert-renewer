import json
from unittest.mock import Mock

import pytest

from vcf_cert_renewer import renewer
from vcf_cert_renewer.config import Settings


@pytest.fixture
def workflow(tmp_path, monkeypatch):
    client = Mock()
    client.resolve_context.return_value = ("domain", {"resourceId": "resource"})
    client.generate_csr.return_value = ("csr-task", {})
    client.fetch_csr.return_value = "csr"
    client.validate_certificate.return_value = {"validationId": "validation"}
    client.replace_certificate.return_value = ("replacement", {"status": "Successful"})
    signer = Mock(return_value={"leafPath": "leaf", "issuerPath": "issuer"})
    builder = Mock(side_effect=lambda leaf, issuer, path: path.write_text("chain"))
    monkeypatch.setattr(renewer, "sign_csr", signer)
    monkeypatch.setattr(renewer, "build_vcf_fullchain", builder)
    monkeypatch.setattr(renewer, "verify_https_certificate", Mock(return_value={}))
    return client, signer, builder, Settings("https://token.invalid", "https://api.invalid", True, 30, None,
                                             output_dir=tmp_path)


@pytest.mark.parametrize("component,fqdn", [
    ("SDDC_MANAGER", "sddc.vcf.example.com"), ("VCENTER", "vcenter.vcf.example.com"),
])
def test_success(workflow, component, fqdn):
    client, _, _, settings = workflow
    result = renewer.execute_domain_renewal(client, settings, fqdn, resource_type=component)
    assert result["result"] == "RENEWED"
    assert result["taskId"] == "replacement"
    assert result["validationId"] == "validation"
    assert client.validate_certificate.call_args.args[2] == "chain"
    assert client.replace_certificate.call_args.args[2] == "chain"


@pytest.mark.parametrize("operation,stage,message", [
    ("resolve_context", "RESOURCE_DISCOVERY", "sensitive details"),
    ("generate_csr", "CSR_GENERATION", "sensitive details"),
    ("wait_task", "CSR_TASK_POLLING", "sensitive details"),
    ("fetch_csr", "CSR_RETRIEVAL", "sensitive details"),
    ("signer", "ACME_SIGNING", "sensitive details"),
    ("signer", "ACME_SIGNING", "lego signing failed with exit status 7; sensitive details"),
    ("signer", "ACME_SIGNING", "lego did not produce a certificate matching the CSR"),
    ("signer", "ACME_SIGNING", "lego did not produce the issuer certificate"),
    ("builder", "CERTIFICATE_CHAIN_CONSTRUCTION", "sensitive details"),
    ("validate_certificate", "CERTIFICATE_VALIDATION", "sensitive details"),
    ("replace_certificate", "CERTIFICATE_REPLACEMENT", "sensitive details"),
])
def test_failure(workflow, operation, stage, message):
    client, signer, builder, settings = workflow
    failure = ValueError(message)
    failure.renewal_diagnostic = {
        "httpStatus": 400, "correlationId": "correlation", "taskId": "csr-task",
        "operation": "API_OPERATION", "safeMessage": "sensitive details",
    }
    failing_call = {"signer": signer, "builder": builder}.get(operation)
    if failing_call is None:
        failing_call = getattr(client, operation)
    failing_call.side_effect = failure
    fqdn = "sddc.vcf.example.com"
    with pytest.raises(ValueError) as caught:
        renewer.execute_domain_renewal(client, settings, fqdn, resource_type="SDDC_MANAGER")
    assert caught.value is failure
    event = failure.renewal_diagnostic
    assert (event["component"], event["targetFqdn"], event["phase"]) == ("SDDC_MANAGER", fqdn, "RENEW")
    assert (event["stage"], event["errorType"], event["operation"]) == (stage, "ValueError", "API_OPERATION")
    assert (event["httpStatus"], event["correlationId"], event["taskId"]) == (400, "correlation", "csr-task")
    assert "sensitive details" not in json.dumps(event)
    if "status 7" in message:
        assert "status 7" in event["safeMessage"]
    if operation not in {"validate_certificate", "replace_certificate"}:
        client.validate_certificate.assert_not_called()
    if operation != "replace_certificate":
        client.replace_certificate.assert_not_called()
