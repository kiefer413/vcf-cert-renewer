from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from vcf_cert_renewer.config import Settings
from vcf_cert_renewer.signer import reuse_signed_csr, _classify_lego_failure
from vcf_cert_renewer.fullchain import build_vcf_fullchain
from vcf_cert_renewer.importer import parse_certificate_chain
from subprocess import CalledProcessError, run as subprocess_run

TARGET = "sddc.example"


@pytest.fixture
def artifacts(tmp_path):
    root = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    ca = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Fixture Root")])
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,TARGET)])
    now = datetime.now(timezone.utc)

    def certificate(dns, public_key, days, is_ca=False):
        b = (x509.CertificateBuilder().subject_name(ca if is_ca else subject)
             .issuer_name(ca).public_key(public_key).serial_number(x509.random_serial_number())
             .not_valid_before(now-timedelta(days=2)).not_valid_after(now+timedelta(days=days))
             .add_extension(x509.BasicConstraints(ca=is_ca,path_length=None),critical=True))
        if not is_ca:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]),critical=False)
        return b.sign(root,hashes.SHA256()).public_bytes(Encoding.PEM)

    csr = tmp_path/"request.pem"
    csr.write_bytes(x509.CertificateSigningRequestBuilder().subject_name(subject)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(TARGET)]),False)
                    .sign(key,hashes.SHA256()).public_bytes(Encoding.PEM))
    settings = Settings("token","url",True,30,None,output_dir=tmp_path)
    dirpath = tmp_path/"acme"/settings.acme_mode/"certificates"
    dirpath.mkdir(parents=True)
    leaf = dirpath/(TARGET+".crt")
    issuer = dirpath/(TARGET+".issuer.crt")
    issuer.write_bytes(certificate("",root.public_key(),90,True))
    leaf.write_bytes(certificate(TARGET,key.public_key(),90))
    return settings,csr,leaf,issuer,certificate,key,root


def test_explicit_reuse_and_fullchain(artifacts):
    s,csr,leaf,issuer,*_ = artifacts
    before = leaf.read_bytes()
    def local_verify(command, **kwargs):
        assert command[:2] == ["openssl", "verify"]
        return subprocess_run(command[:2] + ["-CAfile", str(issuer)] + command[2:], **kwargs)
    with patch("vcf_cert_renewer.signer.subprocess.run", side_effect=local_verify) as run:
        result = reuse_signed_csr(s,TARGET,csr)
    run.assert_called_once()
    assert result["result"] == "REUSED"
    chain = build_vcf_fullchain(leaf,issuer,s.output_dir/"chain.pem",max_downloads=0)
    assert len(parse_certificate_chain(chain.read_bytes())[0]) == 2
    assert b"PRIVATE KEY" not in chain.read_bytes()
    assert leaf.read_bytes() == before


@pytest.mark.parametrize("case", ["expired","near-expiry","malformed","wrong-domain","wrong-key"])
def test_reuse_rejects_invalid_leaf_without_starting_any_subprocess(artifacts,case):
    s,csr,leaf,_,cert,key,root = artifacts
    leaf.write_bytes(b"invalid" if case=="malformed" else cert(
        "wrong.example" if case=="wrong-domain" else TARGET,
        root.public_key() if case=="wrong-key" else key.public_key(),
        {"expired":-1,"near-expiry":1}.get(case,90)))
    with patch("vcf_cert_renewer.signer.subprocess.run") as run, pytest.raises(ValueError):
        reuse_signed_csr(s,TARGET,csr)
    run.assert_not_called()


def test_ari_403_stays_safe():
    error = _classify_lego_failure(CalledProcessError(1,["lego"],stderr=
        "acme: error: 403 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-order :: "
        "urn:ietf:params:acme:error:unauthorized :: Could not validate ARI replaces field"))
    assert (error.category,error.operation,error.problem_status)==("ACME_AUTHORIZATION_FAILURE","NEW_ORDER",403)
    assert "replaces" not in str(error)
