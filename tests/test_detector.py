from detector import analyse_request


def test_sql_injection_is_malicious_and_explained():
    request = {"method": "POST", "path": "/api/v1/users/search", "body": {"username": "admin' OR 1=1--"}}

    result = analyse_request(request)

    assert result["verdict"] == "Malicious"
    assert result["risk_score"] >= 70
    assert any(signal["detector"] == "sql_injection" for signal in result["signals"])


def test_normal_request_is_benign():
    request = {"method": "GET", "path": "/api/v1/users", "query": {"page": "1", "limit": "20"}}

    result = analyse_request(request)

    assert result["verdict"] == "Benign"
    assert result["risk_score"] == 0
    assert result["signals"] == []
