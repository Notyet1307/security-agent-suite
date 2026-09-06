#!/usr/bin/env python3
"""Verify the pinned runtime release contract using only the standard library."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

MAX_MANIFEST_BYTES = 64 * 1024
REPOSITORY_DIGEST = re.compile(
    r"docker\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"@sha256:[0-9a-f]{64}"
)
CANONICAL_REPOSITORIES = {
    "agent-compose": "docker.io/chaitin/agent-compose",
    "Guest": "docker.io/chaitin/agent-compose-guest",
    "OctoBus": "docker.io/chaitin/octobus",
}
VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
PLATFORM = re.compile(r"linux/(?:amd64|arm64)")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


class ManifestError(ValueError):
    pass


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ManifestError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _constant(value: str) -> None:
    raise ManifestError(f"invalid JSON constant: {value}")


def _load(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if not data or len(data) > MAX_MANIFEST_BYTES:
        raise ManifestError("release manifest is empty or too large")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError("release manifest is not valid UTF-8 JSON") from exc
    if type(value) is not dict:
        raise ManifestError("release manifest must be a JSON object")
    return value


def _shape(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ManifestError(f"{label} must be an object")
    if set(value) != keys:
        raise ManifestError(f"{label} fields must be exactly {sorted(keys)}")
    return value


def _string(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if type(value) is not str or not value:
        raise ManifestError(f"{label} must be a non-empty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ManifestError(f"{label} has an invalid format")
    return value


def _single_value(path: Path, pattern: re.Pattern[str], label: str) -> str:
    matches = pattern.findall(path.read_text(encoding="utf-8"))
    if len(matches) != 1:
        raise ManifestError(f"{label} must be declared exactly once")
    return matches[0]


def validate(root: Path) -> None:
    root = root.resolve()
    manifest = _shape(
        _load(root / "release-manifest.json"),
        {"manifest_version", "manifest_role", "runtime_platform", "components", "compose"},
        "release manifest",
    )
    if type(manifest["manifest_version"]) is not int or manifest["manifest_version"] != 1:
        raise ManifestError("manifest_version must be integer 1")
    if _string(manifest["manifest_role"], "manifest role") != "verified-deployment-metadata":
        raise ManifestError("manifest role must identify deployment metadata")
    if _string(manifest["runtime_platform"], "runtime platform", PLATFORM) != "linux/arm64":
        raise ManifestError("runtime platform must be linux/arm64")

    components = _shape(
        manifest["components"], {"agent_compose", "guest", "octobus"}, "components"
    )
    agent_compose = _shape(
        components["agent_compose"],
        {"version", "repository_digest"},
        "components.agent_compose",
    )
    guest = _shape(components["guest"], {"repository_digest"}, "components.guest")
    octobus = _shape(components["octobus"], {"repository_digest"}, "components.octobus")

    version = _string(agent_compose["version"], "agent-compose version", VERSION)
    for label, component in (
        ("agent-compose", agent_compose),
        ("Guest", guest),
        ("OctoBus", octobus),
    ):
        digest = _string(
            component["repository_digest"], f"{label} repository digest", REPOSITORY_DIGEST
        )
        if digest.split("@", 1)[0] != CANONICAL_REPOSITORIES[label]:
            raise ManifestError(f"{label} repository is not canonical")

    compose = _shape(manifest["compose"], {"path", "sha256", "parser_version"}, "compose")
    if _string(compose["path"], "compose path") != "agent-compose.yml":
        raise ManifestError("compose path must be agent-compose.yml")
    parser_version = _string(compose["parser_version"], "compose parser version", VERSION)
    expected_hash = _string(compose["sha256"], "compose sha256", SHA256)
    actual_hash = "sha256:" + hashlib.sha256((root / compose["path"]).read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        raise ManifestError("agent-compose.yml does not match the release manifest")
    if parser_version != version:
        raise ManifestError("compose parser version must match agent-compose version")

    guest_digest = guest["repository_digest"]
    env_guest = _single_value(
        root / ".env.example",
        re.compile(r"(?m)^AGENT_COMPOSE_GUEST_IMAGE=([^\s#]+)$"),
        ".env.example Guest default",
    )
    docker_guest = _single_value(
        root / "images/base/Dockerfile",
        re.compile(r"(?m)^ARG AGENT_COMPOSE_GUEST_IMAGE=([^\s#]+)$"),
        "base Dockerfile Guest default",
    )
    if env_guest != guest_digest or docker_guest != guest_digest:
        raise ManifestError("Guest defaults do not match the release manifest")

    doctor_version = _single_value(
        root / "internal/doctor/doctor.go",
        re.compile(r'(?m)^\s*agentComposeVersion\s*=\s*"([^"]+)"\s*$'),
        "Doctor agent-compose version",
    )
    if doctor_version != version:
        raise ManifestError("Doctor agent-compose version does not match the release manifest")

    release_guest = _single_value(
        root / "internal/doctor/doctor.go",
        re.compile(r'(?m)^\s*releaseGuestImage\s*=\s*"([^\"]+)"\s*$'),
        "Doctor release Guest image",
    )
    if release_guest != guest_digest:
        raise ManifestError("Doctor release Guest image does not match the release manifest")


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) == 2 else Path(__file__).resolve().parent.parent
    if len(argv) > 2:
        print(f"usage: {Path(argv[0]).name} [repository-root]", file=sys.stderr)
        return 2
    try:
        validate(root)
    except (ManifestError, OSError) as exc:
        print(f"release manifest verification failed: {exc}", file=sys.stderr)
        return 1
    print("release manifest verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
