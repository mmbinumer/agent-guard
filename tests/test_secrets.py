import base64

from agent_guard.detectors.secrets import find_secrets


def test_finds_aws_access_key():
    text = "config: AKIAIOSFODNN7EXAMPLE is the key"
    matches = find_secrets(text)
    assert "AKIAIOSFODNN7EXAMPLE" in matches


def test_finds_openai_style_key():
    text = "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyzABCDEF1234567890abcd"
    matches = find_secrets(text)
    assert any(m.startswith("sk-") for m in matches)


def test_finds_private_key_block():
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumqpRZeT\n"
        "-----END RSA PRIVATE KEY-----"
    )
    matches = find_secrets(text)
    assert any("BEGIN RSA PRIVATE KEY" in m for m in matches)


def test_no_false_positive_on_plain_text():
    text = "The quick brown fox jumps over the lazy dog. Total: 42 items."
    matches = find_secrets(text)
    assert matches == []


def test_finds_base64_encoded_secret():
    secret = "AKIAIOSFODNN7EXAMPLE"
    encoded = base64.b64encode(secret.encode()).decode()
    text = f"payload: {encoded}"

    matches = find_secrets(text)

    assert secret in matches
