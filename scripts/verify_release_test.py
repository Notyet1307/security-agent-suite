#!/usr/bin/env python3

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

import verify_release


class VerifyReleaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "images/base").mkdir(parents=True)
        (self.root / "internal/doctor").mkdir(parents=True)
        self.compose = b"name: test\nagents: {}\n"
        (self.root / "agent-compose.yml").write_bytes(self.compose)
        self.guest = "docker.io/chaitin/agent-compose-guest@sha256:" + "b" * 64
        self.manifest = {
            "manifest_version": 1,
            "manifest_role": "verified-deployment-metadata",
            "runtime_platform": "linux/arm64",
            "components": {
                "agent_compose": {
                    "version": "v2609.1.0",
                    "repository_digest": "docker.io/chaitin/agent-compose@sha256:" + "a" * 64,
                },
                "guest": {"repository_digest": self.guest},
                "octobus": {
                    "repository_digest": "docker.io/chaitin/octobus@sha256:" + "c" * 64
                },
            },
            "compose": {
                "path": "agent-compose.yml",
                "sha256": "sha256:" + hashlib.sha256(self.compose).hexdigest(),
                "parser_version": "v2609.1.0",
            },
        }
        self.write_fixture()

    def write_fixture(self) -> None:
        (self.root / "release-manifest.json").write_text(
            json.dumps(self.manifest), encoding="utf-8"
        )
        (self.root / ".env.example").write_text(
            f"AGENT_COMPOSE_GUEST_IMAGE={self.guest}\n", encoding="utf-8"
        )
        (self.root / "images/base/Dockerfile").write_text(
            f"ARG AGENT_COMPOSE_GUEST_IMAGE={self.guest}\n", encoding="utf-8"
        )
        (self.root / "internal/doctor/doctor.go").write_text(
            'const (\n\tagentComposeVersion = "v2609.1.0"\n\treleaseGuestImage = "' + self.guest + '"\n)\n', encoding="utf-8"
        )

    def assert_invalid(self) -> None:
        with self.assertRaises(verify_release.ManifestError):
            verify_release.validate(self.root)

    def test_valid_contract(self) -> None:
        verify_release.validate(self.root)

    def test_rejects_shape_and_type_drift(self) -> None:
        for mutate in (
            lambda value: value.update(manifest_version=True),
            lambda value: value.update(unexpected=True),
            lambda value: value["components"].pop("octobus"),
        ):
            with self.subTest(mutate=mutate):
                original = copy.deepcopy(self.manifest)
                mutate(self.manifest)
                self.write_fixture()
                self.assert_invalid()
                self.manifest = original

    def test_rejects_malformed_runtime_identity(self) -> None:
        original = self.manifest["runtime_platform"]
        self.manifest["runtime_platform"] = "linux/amd64"
        self.write_fixture()
        self.assert_invalid()
        self.manifest["runtime_platform"] = original

    def test_rejects_malformed_or_duplicate_json(self) -> None:
        for data in ("{", '{"manifest_version":1,"manifest_version":1}'):
            with self.subTest(data=data):
                (self.root / "release-manifest.json").write_text(data, encoding="utf-8")
                self.assert_invalid()

    def test_rejects_mutable_or_noncanonical_image_reference(self) -> None:
        for image in (
            "docker.io/chaitin/agent-compose-guest:v2609.1.0",
            "chaitin/agent-compose-guest@sha256:" + "b" * 64,
            "docker.io/Chaitin/agent-compose-guest@sha256:" + "b" * 64,
        ):
            with self.subTest(image=image):
                self.manifest["components"]["guest"]["repository_digest"] = image
                self.write_fixture()
                self.assert_invalid()
    def test_rejects_noncanonical_component_repositories(self) -> None:
        for name, repository in (
            ("agent_compose", "docker.io/other/agent-compose"),
            ("guest", "docker.io/other/agent-compose-guest"),
            ("octobus", "docker.io/other/octobus"),
        ):
            with self.subTest(component=name):
                component = self.manifest["components"][name]
                original = component["repository_digest"]
                suffix = original.split("@", 1)[1]
                component["repository_digest"] = f"{repository}@{suffix}"
                self.write_fixture()
                self.assert_invalid()
                component["repository_digest"] = original

    def test_rejects_compose_drift(self) -> None:
        (self.root / "agent-compose.yml").write_text("name: changed\n", encoding="utf-8")
        self.assert_invalid()

    def test_rejects_manifest_role_or_parser_drift(self) -> None:
        self.manifest["manifest_role"] = "runtime-deployment"
        self.write_fixture()
        self.assert_invalid()
        self.manifest["manifest_role"] = "verified-deployment-metadata"

        self.manifest["compose"]["parser_version"] = "v2608.5.0"
        self.write_fixture()
        self.assert_invalid()

    def test_rejects_guest_default_drift(self) -> None:
        other = "docker.io/chaitin/other@sha256:" + "d" * 64
        for path, line in (
            (self.root / ".env.example", f"AGENT_COMPOSE_GUEST_IMAGE={other}\n"),
            (
                self.root / "images/base/Dockerfile",
                f"ARG AGENT_COMPOSE_GUEST_IMAGE={other}\n",
            ),
        ):
            with self.subTest(path=path):
                self.write_fixture()
                path.write_text(line, encoding="utf-8")
                self.assert_invalid()

    def test_rejects_doctor_version_drift(self) -> None:
        (self.root / "internal/doctor/doctor.go").write_text(
            'const (\n\tagentComposeVersion = "v2608.5.0"\n)\n', encoding="utf-8"
        )
        self.assert_invalid()

    def test_rejects_doctor_release_guest_drift(self) -> None:
        (self.root / "internal/doctor/doctor.go").write_text(
            'const (\n\tagentComposeVersion = "v2609.1.0"\n\treleaseGuestImage = "docker.io/chaitin/other@sha256:' + "d" * 64 + '"\n)\n',
            encoding="utf-8",
        )
        self.assert_invalid()

    def test_release_workflow_gates_runtime_manifest_to_linux_arm64(self) -> None:
        workflow = (Path(__file__).resolve().parent.parent / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn('if [[ "${{ matrix.goos }}/${{ matrix.goarch }}" == linux/arm64 ]]; then', workflow)
        self.assertIn("release-manifest.json .env.example", workflow)
        self.assertIn("RUNTIME_SCOPE.txt", workflow)
        self.assertIn("Client/mock-only", workflow)


if __name__ == "__main__":
    unittest.main()
