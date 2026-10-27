from unittest.mock import patch, MagicMock
from tests.conftest import IPCONFIG_OUTPUT


def test_detect_via_ipconfig():
    from losshound.core.gateway import _detect_via_ipconfig

    mock_result = MagicMock()
    mock_result.stdout = IPCONFIG_OUTPUT

    with patch("subprocess.run", return_value=mock_result):
        gw = _detect_via_ipconfig()
        assert gw == "192.168.1.1"


def test_detect_via_ipconfig_no_gateway():
    from losshound.core.gateway import _detect_via_ipconfig

    mock_result = MagicMock()
    mock_result.stdout = "Windows IP Configuration\n\n  No adapters found.\n"

    with patch("subprocess.run", return_value=mock_result):
        gw = _detect_via_ipconfig()
        assert gw is None


def test_detect_via_ipconfig_ignores_zero():
    from losshound.core.gateway import _detect_via_ipconfig

    mock_result = MagicMock()
    mock_result.stdout = "Default Gateway . . . : 0.0.0.0\n"

    with patch("subprocess.run", return_value=mock_result):
        gw = _detect_via_ipconfig()
        assert gw is None
