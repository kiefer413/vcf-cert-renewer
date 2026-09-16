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


if __name__ == "__main__":
    unittest.main()
