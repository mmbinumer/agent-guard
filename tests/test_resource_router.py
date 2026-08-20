import pytest

from agent_guard.resource_router import ResourceRouter, ResourceRoutingError


def test_exact_uri_routes_to_its_server():
    r = ResourceRouter()
    r.register("fs", uris=["file:///proj/README.md"], templates=[])

    assert r.resolve("file:///proj/README.md") == "fs"


def test_unknown_uri_is_an_error_not_a_guess():
    # Trying servers in turn would leak the URI (which may contain a
    # sensitive path) to servers that do not own it.
    r = ResourceRouter()
    r.register("fs", uris=["file:///proj/README.md"], templates=[])

    with pytest.raises(ResourceRoutingError):
        r.resolve("file:///proj/secrets.txt")


def test_template_resolves_a_uri_that_was_never_listed():
    r = ResourceRouter()
    r.register("fs", uris=[], templates=["file:///{path}"])

    assert r.resolve("file:///anything/at/all.txt") == "fs"


def test_more_specific_template_wins():
    r = ResourceRouter()
    r.register("catchall", uris=[], templates=["{everything}"])
    r.register("github", uris=[], templates=["github://repos/{owner}/{name}"])

    assert r.resolve("github://repos/acme/widget") == "github"


def test_equally_specific_templates_are_ambiguous():
    r = ResourceRouter()
    r.register("a", uris=[], templates=["thing://{x}"])
    r.register("b", uris=[], templates=["thing://{y}"])

    with pytest.raises(ResourceRoutingError):
        r.resolve("thing://123")


def test_exact_match_beats_a_matching_template():
    r = ResourceRouter()
    r.register("templated", uris=[], templates=["file:///{path}"])
    r.register("listed", uris=["file:///proj/README.md"], templates=[])

    assert r.resolve("file:///proj/README.md") == "listed"


def test_colliding_uri_is_reported():
    r = ResourceRouter()
    r.register("fs_a", uris=["file:///README.md"], templates=[])
    r.register("fs_b", uris=["file:///README.md"], templates=[])

    assert r.collisions == {"file:///README.md": ["fs_a", "fs_b"]}


def test_colliding_uri_refuses_to_pick_one():
    # Returning the wrong server's file silently is worse than an error:
    # the agent would act on the wrong content with no signal.
    r = ResourceRouter()
    r.register("fs_a", uris=["file:///README.md"], templates=[])
    r.register("fs_b", uris=["file:///README.md"], templates=[])

    with pytest.raises(ResourceRoutingError):
        r.resolve("file:///README.md")


def test_collision_does_not_break_other_resources():
    r = ResourceRouter()
    r.register("fs_a", uris=["file:///README.md", "file:///only-a.txt"], templates=[])
    r.register("fs_b", uris=["file:///README.md"], templates=[])

    assert r.resolve("file:///only-a.txt") == "fs_a"


def test_regex_metacharacters_in_uris_are_literal():
    # A URI like "file:///a+b(c).txt" must not be treated as a pattern.
    r = ResourceRouter()
    r.register("fs", uris=[], templates=["file:///a+b(c).{ext}"])

    assert r.resolve("file:///a+b(c).txt") == "fs"
    with pytest.raises(ResourceRoutingError):
        r.resolve("file:///aXbXcX.txt")


def test_error_names_the_uri():
    r = ResourceRouter()
    r.register("fs", uris=[], templates=[])

    with pytest.raises(ResourceRoutingError, match="weird://thing"):
        r.resolve("weird://thing")
