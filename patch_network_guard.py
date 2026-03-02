with open("tests/test_network_guard.py", "r") as f:
    content = f.read()

import_idx = content.find("import pytest")
content = content[:import_idx] + "from unittest.mock import MagicMock, patch\n\n" + content[import_idx:]

test_func = """    @patch("httpx.Client.request")
    def test_public_url_success(self, mock_request: MagicMock, firewall: BasalGuardCore) -> None:
        \"\"\"A public URL should succeed (mocked HTTP call to example.com).\"\"\"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Example Domain"
        mock_request.return_value = mock_response

        result = firewall.safe_web_request("https://www.example.com/")
        assert result["status"] == "success"
        assert result["status_code"] == 200
        assert "Example Domain" in result["content"]"""

old_test_func = """    def test_public_url_success(self, firewall: BasalGuardCore) -> None:
        \"\"\"A public URL should succeed (actual HTTP call to example.com).\"\"\"
        result = firewall.safe_web_request("https://www.example.com/")
        assert result["status"] == "success"
        assert result["status_code"] == 200
        assert "Example Domain" in result["content"]"""

content = content.replace(old_test_func, test_func)

with open("tests/test_network_guard.py", "w") as f:
    f.write(content)
