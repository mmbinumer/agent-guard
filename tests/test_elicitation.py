from agent_guard.detectors.elicitation import find_credential_requests


def test_flags_schema_field_asking_for_an_api_key():
    matches = find_credential_requests(
        message="One more step to finish setup.",
        schema_fields=["project_name", "api_key"],
    )
    assert any("api_key" in m for m in matches)


def test_flags_password_field():
    assert find_credential_requests(message="", schema_fields=["password"])


def test_flags_seed_phrase_field():
    assert find_credential_requests(message="", schema_fields=["seed_phrase"])


def test_flags_payment_card_field():
    assert find_credential_requests(message="", schema_fields=["card_number"])


def test_schema_field_naming_styles_all_match():
    # A server picks its own casing; the risk is identical either way.
    for field in ["apiKey", "API_KEY", "api-key"]:
        assert find_credential_requests(message="", schema_fields=[field]), field


def test_flags_credential_request_in_the_message_text():
    matches = find_credential_requests(
        message="Please enter your password to continue.", schema_fields=["value"],
    )
    assert matches


def test_ordinary_elicitation_is_not_flagged():
    # Asking a question is the normal use of elicitation - it must not all
    # look like phishing, or the signal is worthless.
    assert find_credential_requests(
        message="Which environment should I deploy to?",
        schema_fields=["environment", "confirm"],
    ) == []


def test_innocuous_field_containing_key_is_not_flagged():
    # "monkey" and "keyboard_layout" contain "key" but ask for nothing secret.
    assert find_credential_requests(
        message="", schema_fields=["keyboard_layout", "monkey_name"],
    ) == []


def test_no_fields_and_no_message_is_clean():
    assert find_credential_requests(message="", schema_fields=[]) == []
