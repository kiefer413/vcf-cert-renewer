"""Small local smoke test that performs no network calls."""

from vcf_cert_renewer.config import Settings


if __name__ == "__main__":
    settings = Settings.from_env()
    print(f"VCF base URL: {settings.base_url}")
    print(f"TLS verification: {settings.verify_tls}")
    print(f"API token configured: {bool(settings.api_token)}")
