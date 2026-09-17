from ioc_sentinel.extractor import extract_all


def test_extract_all():
    text = "Contact 45.33.22.11 and https://malicious.example.com/path deadbeefdeadbeefdeadbeefdeadbeef"
    result = extract_all(text)
    assert "45.33.22.11" in result["ip"]
    assert "https://malicious.example.com/path" in result["url"]
    assert "malicious.example.com" in result["domain"]
    assert "deadbeefdeadbeefdeadbeefdeadbeef" in result["hash"]
