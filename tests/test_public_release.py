import unittest
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


class PublicReleaseTests(unittest.TestCase):
    def test_required_project_files_exist(self):
        for relative in (
            "LICENSE", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md",
            ".editorconfig", ".github/workflows/ci.yml",
            "docs/authentication.md", "docs/component-support.md",
            "docs/renewal-flow.md", "docs/security.md", "docs/troubleshooting.md",
        ):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_single_recommended_public_config_template(self):
        self.assertTrue((ROOT / "examples/vcf-cert-renewer.env.example").is_file())
        self.assertFalse((ROOT / "examples/config.yaml").exists())
        self.assertFalse((ROOT / "examples/secrets.env.example").exists())

    def test_public_marker_scan(self):
        result = subprocess.run(
            [sys.executable, "scripts/check_public_markers.py"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_scanner_allows_kubernetes_secret_reference_but_not_values(self):
        from scripts.check_public_markers import unsafe_secret_assignments
        self.assertFalse(unsafe_secret_assignments(b"secretName: vcf-cert-renewer"))
        self.assertFalse(unsafe_secret_assignments(b"automountServiceAccountToken: false"))
        self.assertTrue(unsafe_secret_assignments(b"automountServiceAccountToken: live-looking-value"))
        self.assertTrue(unsafe_secret_assignments(b"SDDC_PASSWORD: live-looking-value"))

    def test_scanner_recognizes_eab_secrets(self):
        from scripts.check_public_markers import unsafe_secret_assignments
        self.assertTrue(unsafe_secret_assignments(b"ACME_EAB_HMAC=live-looking-value"))
        self.assertTrue(unsafe_secret_assignments(b"ACME_EAB_KID=live-looking-value"))
        self.assertFalse(unsafe_secret_assignments(b"ACME_EAB_HMAC=\nACME_EAB_KID="))


if __name__ == "__main__":
    unittest.main()
