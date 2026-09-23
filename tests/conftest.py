"""Keep offline tests independent of host production configuration."""
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def isolated_host_configuration():
    with patch('vcf_cert_renewer.config.DEFAULT_CONFIG_PATH', Path('/nonexistent-vcf-test/config.yaml')), \
         patch('vcf_cert_renewer.config.DEFAULT_SECRETS_PATH', Path('/nonexistent-vcf-test/secrets.env')), \
         patch('socket.socket.connect', side_effect=AssertionError('Network access is forbidden in unit tests')):
        yield
