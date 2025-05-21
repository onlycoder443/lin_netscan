import pytest
from lin_netscan import input_checker

def test_input_checker_ip():
    ip = "192.168.1.1"
    ports = list(input_checker(ip, 20, 25))
    expected = [("192.168.1.1", port) for port in range(20, 26)]
    assert ports == expected

def test_input_checker_domain(monkeypatch):
    # This will resolve to Google's IP; test will pass as long as domain resolves.
    domain = "google.com"
    result = list(input_checker(domain, 80, 81))
    assert isinstance(result[0][0], str)
    assert result[0][1] == 80

def test_invalid_domain(monkeypatch):
    with pytest.raises(SystemExit):
        input_checker("nonexistent.domain.example", 80, 81)
