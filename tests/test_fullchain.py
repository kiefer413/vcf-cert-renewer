import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from vcf_cert_renewer.fullchain import build_vcf_fullchain
from vcf_cert_renewer.importer import parse_certificate_chain


def make_certificate(subject, issuer, public_key, issuer_key, *, ca, aia=None):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(public_key).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=1))
               .not_valid_after(now + timedelta(days=90))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True))
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("ops.example")]), False)
    if aia:
        builder = builder.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(aia))]), False)
    return builder.sign(issuer_key, hashes.SHA256())


class FullchainTests(unittest.TestCase):
    def chain(self):
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root")])
        int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Issuer")])
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ops.example")])
        root = make_certificate(root_name, root_name, root_key.public_key(), root_key, ca=True)
        intermediate = make_certificate(
            int_name, root_name, int_key.public_key(), root_key,
            ca=True, aia="https://ca.example/root.der")
        leaf = make_certificate(
            leaf_name, int_name, leaf_key.public_key(), int_key, ca=False)
        return leaf, intermediate, root

    def test_retrieves_missing_root_and_orders_chain(self):
        leaf, intermediate, root = self.chain()
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            leaf_path, issuer_path = directory / "leaf.crt", directory / "issuer.crt"
            leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
            issuer_path.write_bytes(intermediate.public_bytes(serialization.Encoding.PEM))
            output = directory / "ops.example.vcf-fullchain.pem"
            build_vcf_fullchain(
                leaf_path, issuer_path, output,
                fetch=lambda url: root.public_bytes(serialization.Encoding.DER))
            certificates, _ = parse_certificate_chain(output.read_bytes())
            self.assertEqual([item.subject for item in certificates],
                             [leaf.subject, intermediate.subject, root.subject])

    def test_does_not_fetch_when_self_signed_root_is_present(self):
        leaf, intermediate, root = self.chain()
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            leaf_path, issuer_path = directory / "leaf.crt", directory / "issuer.crt"
            leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
            issuer_path.write_bytes(
                intermediate.public_bytes(serialization.Encoding.PEM) +
                root.public_bytes(serialization.Encoding.PEM))
            output = directory / "chain.pem"
            build_vcf_fullchain(
                leaf_path, issuer_path, output,
                fetch=lambda url: self.fail("fetch must not be called"))
            certificates, _ = parse_certificate_chain(output.read_bytes())
            self.assertEqual(len(certificates), 3)

    def test_non_le_two_intermediates_with_duplicate_bundle(self):
        leaf, intermediate, root = self.chain()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        upper_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Enterprise Policy CA")])
        # Reissue existing issuer/root keys into a four-certificate hierarchy.
        upper = make_certificate(upper_name, upper_name, key.public_key(), key, ca=True)
        cross = make_certificate(root.subject, upper_name, root.public_key(), key, ca=True)
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            pem = lambda c: c.public_bytes(serialization.Encoding.PEM)
            (d / "leaf.crt").write_bytes(pem(leaf) + pem(intermediate))
            (d / "issuer.crt").write_bytes(pem(intermediate) + pem(cross) + pem(upper))
            build_vcf_fullchain(d / "leaf.crt", d / "issuer.crt", d / "full.pem",
                               fetch=lambda url: self.fail("unexpected AIA request"))
            certs, _ = parse_certificate_chain((d / "full.pem").read_bytes())
            self.assertEqual([c.subject for c in certs],
                             [leaf.subject, intermediate.subject, cross.subject, upper.subject])

    def test_rejects_unrelated_non_le_issuer(self):
        leaf, intermediate, root = self.chain()
        other_leaf, other_intermediate, other_root = self.chain()
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            pem = lambda c: c.public_bytes(serialization.Encoding.PEM)
            (d / "leaf.crt").write_bytes(pem(leaf))
            (d / "issuer.crt").write_bytes(pem(other_intermediate) + pem(other_root))
            with self.assertRaises(ValueError):
                build_vcf_fullchain(d / "leaf.crt", d / "issuer.crt", d / "full.pem")


if __name__ == "__main__":
    unittest.main()
