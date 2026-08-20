"""Routing of resource URIs to the downstream server that owns them.

Tool names carry their server (`<server>__<tool>`), but a resource URI has
scheme semantics and cannot be namespaced without breaking what the client
displays. So ownership is worked out from what each server advertises.

Resolution order:

1. exact URI, from `resources/list`
2. URI template, from `resources/templates/list`, most specific first
3. error

There is deliberately no "try each server until one answers" fallback. A URI
can itself be sensitive (`file:///home/me/.ssh/id_rsa`), and probing every
connected server to find the owner would hand that path to servers with no
claim to it - a cross-server leak caused by the tool meant to prevent them.
"""
from __future__ import annotations

import re
from collections import OrderedDict

_VARIABLE = re.compile(r"\{[^}]*\}")


class ResourceRoutingError(Exception):
    """A URI could not be attributed to exactly one server."""


def _template_to_regex(template: str) -> re.Pattern:
    """Match a URI template as a shape, not per RFC 6570.

    We only need "which server owns this", never the variable values, so each
    `{var}` becomes `.+` and every literal run is escaped."""
    literals = [re.escape(part) for part in _VARIABLE.split(template)]
    return re.compile("^" + ".+".join(literals) + "$")


def _specificity(template: str) -> int:
    """Literal (non-variable) characters. `github://repos/{id}` outranks
    `{anything}`, so the catch-all only wins when nothing else matches."""
    return sum(len(part) for part in _VARIABLE.split(template))


class ResourceRouter:
    def __init__(self) -> None:
        # uri -> [server, ...]; a list because collisions are reported, not
        # silently resolved in favour of whoever registered first.
        self._exact: OrderedDict[str, list[str]] = OrderedDict()
        self._templates: list[tuple[str, re.Pattern, int]] = []

    def register(self, server_name: str, uris: list[str], templates: list[str]) -> None:
        for uri in uris:
            self._exact.setdefault(uri, [])
            if server_name not in self._exact[uri]:
                self._exact[uri].append(server_name)

        for template in templates:
            self._templates.append(
                (server_name, _template_to_regex(template), _specificity(template))
            )

    @property
    def collisions(self) -> dict[str, list[str]]:
        """URIs claimed by more than one server, surfaced at connect time so
        the conflict is visible before a read fails."""
        return {uri: owners for uri, owners in self._exact.items() if len(owners) > 1}

    def resolve(self, uri: str) -> str:
        owners = self._exact.get(uri)
        if owners:
            if len(owners) > 1:
                raise ResourceRoutingError(
                    f"Resource {uri} is claimed by multiple servers "
                    f"({', '.join(owners)}); Agent Guard will not guess which."
                )
            return owners[0]

        matches = [
            (server, score)
            for server, pattern, score in self._templates
            if pattern.match(uri)
        ]
        if matches:
            best = max(score for _server, score in matches)
            tied = {server for server, score in matches if score == best}
            if len(tied) > 1:
                raise ResourceRoutingError(
                    f"Resource {uri} matches templates from multiple servers "
                    f"({', '.join(sorted(tied))}) equally well."
                )
            return next(server for server, score in matches if score == best)

        raise ResourceRoutingError(f"No connected server owns resource {uri}")
