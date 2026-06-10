import fnmatch

from agent_guard.detectors.taint import TaintStore


def test_tag_and_match_exact_value():
    store = TaintStore(max_value_bytes=512, max_entries=1000)

    store.tag(source="fs:.env", values=["sk-supersecretvalue1234567890abcdef"])

    matches = store.find_matches("posting body=sk-supersecretvalue1234567890abcdef to slack")
    assert matches
    assert matches[0]["source"] == "fs:.env"


def test_no_match_for_untagged_value():
    store = TaintStore(max_value_bytes=512, max_entries=1000)
    store.tag(source="fs:.env", values=["sk-supersecretvalue1234567890abcdef"])

    matches = store.find_matches("posting body=hello world")
    assert matches == []


def test_match_base64_encoded_taint_value():
    import base64

    store = TaintStore(max_value_bytes=512, max_entries=1000)
    secret = "sk-supersecretvalue1234567890abcdef"
    store.tag(source="fs:.env", values=[secret])

    encoded = base64.b64encode(secret.encode()).decode()
    matches = store.find_matches(f"payload={encoded}")

    assert matches
    assert matches[0]["source"] == "fs:.env"


def test_value_truncated_to_max_bytes():
    store = TaintStore(max_value_bytes=10, max_entries=1000)
    long_value = "a" * 100

    store.tag(source="fs:big.txt", values=[long_value])

    stored = store.values_for_source("fs:big.txt")
    assert all(len(v.encode()) <= 10 for v in stored)


def test_eviction_when_max_entries_exceeded():
    store = TaintStore(max_value_bytes=512, max_entries=2)

    store.tag(source="fs:a", values=["value-one-aaaaaaaaaaaaaaaa"])
    store.tag(source="fs:b", values=["value-two-bbbbbbbbbbbbbbbb"])
    store.tag(source="fs:c", values=["value-three-cccccccccccccc"])

    assert store.truncated is True
    # Oldest entry (fs:a / value-one) should have been evicted
    assert store.find_matches("contains value-one-aaaaaaaaaaaaaaaa") == []
    assert store.find_matches("contains value-three-cccccccccccccc")


def test_sink_pattern_matching():
    store = TaintStore(max_value_bytes=512, max_entries=1000)

    assert store.is_sink("slack.post_message", ["http.*", "email.*", "slack.*"])
    assert not store.is_sink("fs.read_file", ["http.*", "email.*", "slack.*"])


def test_source_pattern_matching_uses_fnmatch():
    # sanity check that our glob semantics for sensitive sources match fnmatch
    assert fnmatch.fnmatch(".env", ".env")
    assert fnmatch.fnmatch("app.secret.yaml", "*secret*")
    assert not fnmatch.fnmatch("config.yaml", "*secret*")
