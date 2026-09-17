from detector import analyse_request


def test_sql_injection_is_malicious_and_explained():
    request = {"method": "POST", "path": "/api/v1/users/search", "body": {"username": "admin' OR 1=1--"}}

    result = analyse_request(request)

    assert result["verdict"] == "Malicious"
    assert result["risk_score"] >= 70
    assert any(signal["detector"] == "sql_injection" for signal in result["signals"])


def test_path_traversal_is_malicious_and_explained():
    request = {"method": "GET", "path": "/api/v1/files/../../../../etc/passwd"}

    result = analyse_request(request)

    assert result["verdict"] == "Malicious"
    assert result["risk_score"] == 70
    assert result["signals"][0]["detector"] == "path_traversal"
    assert "escape" in result["signals"][0]["reason"]


def test_generic_ssrf_is_suspicious():
    request = {"method": "POST", "body": {"url": "http://127.0.0.1:8080/admin"}}

    result = analyse_request(request)

    assert result["verdict"] == "Suspicious"
    assert result["risk_score"] == 60
    assert result["signals"][0]["detector"] == "ssrf"


def test_cloud_metadata_ssrf_is_malicious():
    request = {"method": "POST", "body": {"url": "http://169.254.169.254/latest/meta-data/"}}

    result = analyse_request(request)

    assert result["verdict"] == "Malicious"
    assert result["risk_score"] == 75
    assert result["signals"][0]["detector"] == "ssrf"
    assert "metadata service" in result["signals"][0]["reason"]


def test_normal_request_is_benign():
    request = {"method": "GET", "path": "/api/v1/users", "query": {"page": "1", "limit": "20"}}

    result = analyse_request(request)

    assert result["verdict"] == "Benign"
    assert result["risk_score"] == 0
    assert result["signals"] == []
