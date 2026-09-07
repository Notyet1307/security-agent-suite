#!/usr/bin/env python3
"""Focused local tests for the SAS-103 raw-evidence harness."""
from __future__ import annotations
import copy
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts import sas103_acceptance as h
PROMPT, TOKEN, OUTPUT = "PROMPT_SENTINEL", "TOKEN_SENTINEL", "OUTPUT_SENTINEL"
def fake_run_id(number): return f"run_{1700000000000 + number:013d}_{number:016x}"
def fake_runtime_id(kind, run_id): return h.sha(f"{kind}:{run_id}".encode())
def fake_provenance(agent, run_id, status):
    return {"agent_name": agent, "daemon_run_id": fake_runtime_id("daemon", run_id), "sandbox_id": fake_runtime_id("sandbox", run_id), "status": status, "driver": "docker", "image_ref": h.guest_image(), **({"provider": "pi"} if status in h.RUNTIME_SUCCESS else {})}
def fake_artifact(run_id, data):
    artifact_id = f"art_{run_id.removeprefix('run_')}"
    return {"id": artifact_id, "name": "agent-compose-final-output.json", "uri": f"artifact://runs/{run_id}/{artifact_id}-agent-compose-final-output.json", "media_type": "application/json", "sha256": h.sha(data), "size_bytes": len(data), "created_at": "2026-09-07T00:00:00Z"}
def external_control_exchange(agent, kind, number):
    if kind in {"daemon_unavailable", "octobus_unavailable"}:
        target = kind.removesuffix("_unavailable")
        return {"request": {"method": "GET", "path": f"/preflight/{target}", "body_json": None}, "response": {"status": 503, "body_json": json.dumps({"agent_id": agent, "status": "failed", "error_code": kind}, separators=(",", ":"))}}
    run_id = fake_run_id(1000 + number)
    if kind == "invalid_schema":
        return {"request": {"method": "GET", "path": f"/v1/runs/{run_id}", "body_json": None}, "response": {"status": 200, "body_json": json.dumps({"id": run_id, "agent_id": agent, "status": "failed", "error_code": "agent_output_contract_invalid"}, separators=(",", ":"))}}
    return {"request": {"method": "POST", "path": f"/v1/runs/{run_id}/capabilities", "body_json": json.dumps({"forbidden_capability": h.FORBIDDEN_CAPABILITY}, separators=(",", ":"))}, "response": {"status": 403, "body_json": json.dumps({"id": run_id, "agent_id": agent, "status": "failed", "error_code": "capability_denied", "sandbox_id": fake_runtime_id("sandbox", run_id)}, separators=(",", ":"))}}
def valid_output(fixture):
    agent = fixture["agent_id"]; status = fixture["expected_output_status"]; protocol = fixture["expected_protocol"]
    if agent == "traffic-analysis": return {"protocol": protocol, "status": status, "summary": "synthetic", "evidence": [], "timeline": [], "findings": [], "limitations": []}
    if agent == "event-triage": return {"protocol": protocol, "status": status, "summary": "synthetic", "classification": "insufficient_evidence", "severity": "undetermined", "confidence": 0, "hypotheses": [], "evidence": [], "findings": [], "recommended_actions": [], "limitations": []}
    if agent == "attack-path-validation": return {"protocol": protocol, "status": status, "summary": "synthetic", "scope_check": {"authorized": False, "authorization_ref": "synthetic", "approval_id": "synthetic", "targets": [], "checks": []}, "validations": [], "evidence": [], "findings": [], "attack_paths": [], "stop_reason": "synthetic", "limitations": []}
    if agent == "compliance-query": return {"protocol": protocol, "status": status, "answer": "insufficient", "applicability": {"applies": "unknown", "assumptions": [], "reason": "synthetic"}, "citations": [], "control_gaps": [], "evidence_requirements": [], "recommendations": [], "uncertainty": []}
    return {"protocol": protocol, "status": status, "report_type": "daily", "period": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z", "timezone": "UTC"}, "executive_summary": "synthetic", "metrics": [], "key_events": [], "recommendations": [], "artifacts": [], "validation": {"numbers": "passed", "citations": "passed", "template": "passed", "sensitive_data": "passed"}, "limitations": []}

class FakeAPI:
    def __init__(self, fixtures, replay=False, duplicate_lifecycle=False, stalled_timeout=False, synchronous_cancel=False, timeout_queued=False, different_artifact=False, unknown_provider=False):
        self.fixtures, self.replay, self.replayed, self.runs, self.next, self.duplicate_lifecycle, self.stalled_timeout, self.synchronous_cancel, self.timeout_queued, self.different_artifact, self.unknown_provider = fixtures, replay, False, {}, 0, duplicate_lifecycle, stalled_timeout, synchronous_cancel, timeout_queued, different_artifact, unknown_provider; self.outstanding_normal = 0; self.max_outstanding_normal = 0; FakeAPI.last = self
        self.catalog = {item["id"]: item for item in h.json_file(ROOT / "configs" / "agents.json", "agent catalog")["agents"]}
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *unused): pass
            def send(self, status, body):
                raw = json.dumps(body, separators=(",", ":")).encode(); self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
            def send_artifact(self, raw):
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
            def body(self): return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
            def do_GET(self):
                parts = self.path.split("/")
                if len(parts) == 6 and parts[1:3] == ["v1", "runs"] and parts[4] == "artifacts":
                    run = owner.runs.get(unquote(parts[3])); artifact = fake_artifact(run["id"], run["artifact_bytes"]) if run and run.get("artifact_bytes") is not None else None
                    if artifact and unquote(parts[5]) == artifact["id"]: return self.send_artifact(run["artifact_bytes"])
                    return self.send(404, {})
                if self.path == "/v1/agents":
                    return self.send(200, {"agents": [{"id": agent, "capset_ids": owner.catalog[agent]["capset_ids"], "allowed_modes": owner.catalog[agent]["allowed_modes"], "output_formats": owner.catalog[agent]["output_formats"]} for agent in owner.fixtures]})
                run = owner.runs.get(unquote(self.path.rsplit("/", 1)[-1]))
                if not run: return self.send(404, {})
                if run["scenario"] == "cancel" and not run["cancelled"]: return self.send(200, {"id": run["id"], "agent_id": run["agent"], "status": "running"})
                if run["scenario"] == "timeout":
                    if not run.get("observed_running"): run["observed_running"] = True; return self.send(200, {"id": run["id"], "agent_id": run["agent"], "status": "queued" if owner.timeout_queued else "running"})
                    return self.send(200, {"id": run["id"], "agent_id": run["agent"], "status": "running"} if owner.stalled_timeout else {"id": run["id"], "agent_id": run["agent"], "status": "failed", "result": {"error_code": "executor_timeout", "provenance": fake_provenance(run["agent"], run["id"], "canceled")}})
                if run["scenario"] == "cancel": return self.send(200, {"id": run["id"], "agent_id": run["agent"], "status": "cancelled", "result": {"error_code": "executor_cancelled", "provenance": fake_provenance(run["agent"], run["id"], "canceled")}})
                fixture = owner.fixtures[run["agent"]]
                if run["scenario"] == "normal" and not run.get("terminal"): run["terminal"] = True; owner.outstanding_normal -= 1
                output = valid_output(fixture); artifact_output = copy.deepcopy(output)
                if owner.different_artifact and run["agent"] == "traffic-analysis": artifact_output["summary"] = "semantically different"
                run["artifact_bytes"] = json.dumps(artifact_output, indent=2).encode(); artifact = fake_artifact(run["id"], run["artifact_bytes"])
                provenance = fake_provenance(run["agent"], run["id"], "succeeded")
                if owner.unknown_provider: provenance["provider"] = "foo"
                return self.send(200, {"id": run["id"], "agent_id": run["agent"], "status": "partial", "result": {"executor": "agentcompose-cli", "raw_output": output, "prompt": PROMPT, "token": TOKEN, "output": OUTPUT, "provenance": provenance, "artifacts": [artifact]}})
            def do_POST(self):
                if self.path.startswith("/v1/agents/"):
                    agent, body = unquote(self.path.split("/")[3]), self.body()
                    if owner.replay and "-normal-" in body["request_id"] and not owner.replayed:
                        owner.replayed = True; return self.send(200, {"id": TOKEN, "agent_id": agent})
                    owner.next += 1; scenario = "timeout" if "max_duration" in body["policy"] else "cancel" if "-cancel-" in body["request_id"] else "normal"; identifier = fake_run_id(1) if owner.duplicate_lifecycle and scenario == "cancel" else fake_run_id(owner.next)
                    owner.runs[identifier] = {"id": identifier, "agent": agent, "scenario": scenario, "cancelled": False}
                    if scenario == "normal": owner.outstanding_normal += 1; owner.max_outstanding_normal = max(owner.max_outstanding_normal, owner.outstanding_normal)
                    return self.send(202, {"id": identifier, "agent_id": agent})
                identifier = unquote(self.path.split("/")[3]); run = owner.runs.get(identifier)
                if not run: return self.send(404, {})
                run["cancelled"] = True; self.send(200 if owner.synchronous_cancel else 202, {"id": identifier, "agent_id": run["agent"], "status": "cancelled" if owner.synchronous_cancel else "running", **({"error_code": "executor_cancelled", "provenance": fake_provenance(run["agent"], identifier, "cancelled")} if owner.synchronous_cancel else {})})
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler); self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
    @property
    def url(self): return f"http://127.0.0.1:{self.http.server_address[1]}"
    def __enter__(self): self.thread.start(); return self
    def __exit__(self, *unused): self.http.shutdown(); self.http.server_close(); self.thread.join()

def malicious_validator(directory):
    path = directory / "malicious-sasctl"
    path.write_text("#!/bin/sh\nexit 0\n")
    os.chmod(path, 0o700); return path

class SAS103AcceptanceHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_path = ROOT / "evals" / "sas103-fixtures.json"; cls.manifest, cls.fixtures = h.fixtures(cls.manifest_path)
    def collect(self, directory, replay=False, controls_path=None, runs=20, duplicate_lifecycle=False, stalled_timeout=False, poll_timeout=1, synchronous_cancel=False, timeout_queued=False, different_artifact=False, unknown_provider=False):
        binary = h.TRUSTED_SASCTL; api_key = os.environ.pop("SAS_API_KEY", None)
        try:
            with FakeAPI(self.fixtures, replay, duplicate_lifecycle, stalled_timeout, synchronous_cancel, timeout_queued, different_artifact, unknown_provider) as api:
                return h.collect(self.manifest_path, directory / "out", api.url, "tenant", runs, poll_timeout, .001, "1s", False, binary, controls_path), binary
        finally:
            if api_key is not None: os.environ["SAS_API_KEY"] = api_key
    def report(self, output): return json.loads((output / "sas103-report.json").read_text())
    def rewrite(self, output, report): (output / "sas103-report.json").write_bytes(h.canonical(report))
    def verify(self, report_path, binary, controls_path=None): return h.verify_report(report_path, self.manifest_path, controls_path, binary)
    def test_fixture_integrity(self):
        self.assertEqual(set(self.fixtures), set(h.AGENTS))
        self.assertEqual(h.PROVIDERS, {"codex", "claude", "gemini", "opencode", "pi", "dsh"})
        for fixture in self.fixtures.values(): self.assertEqual(fixture["request"]["inputs"][0]["metadata"], {"synthetic": "true", "data_availability": "none"})
        bad = copy.deepcopy(self.manifest); bad["fixtures"][0]["fixture_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"; path.write_bytes(h.canonical(bad))
            with self.assertRaises(h.HarnessError): h.fixtures(path)
        for url, remote in (("http://127.0.0.1:8080/?query=1", False), ("http://127.0.0.1:8080/#fragment", False), ("https://127.0.0.1:8080/path", False), ("http://example.test", True)):
            with self.assertRaises(h.HarnessError): h.base_url(url, remote)
    def test_projection_validates_hashes_and_ids(self):
        digest = "a" * 64
        sandbox_id = "b" * 64
        self.assertEqual(h._safe_result({"sandbox_id": sandbox_id}, digest), {"sandbox_id": sandbox_id, "raw_output_sha256": digest})
        for result in ({"sandbox_id": True}, {"sandbox_id": "sandbox-run-1"}, {"provenance": {"daemon_run_id": "daemon-run-1"}}, {"raw_output_sha256": "invalid"}):
            with self.subTest(result=result), self.assertRaises(h.HarnessError): h._safe_result(result)
        for status in ("queued", "validating"):
            with self.subTest(status=status): self.assertEqual(h._safe_result({"status": status}), {"status": status})
    def test_projection_rejects_provider_tokens(self):
        cases = (({"id": TOKEN}, {}), ({"agent_id": TOKEN}, {}), ({"error_code": TOKEN}, {}), ({"executor": TOKEN}, {}), ({"provenance": {"daemon_run_id": TOKEN}}, {}), ({"provenance": {"status": TOKEN}}, {}), ({}, {"output_protocol": TOKEN}), ({}, {"output_status": TOKEN}))
        for result, options in cases:
            with self.subTest(result=result, options=options), self.assertRaises(h.HarnessError): h._safe_result(result, **options)
        catalog = {"request": {"method": "GET", "path": "/v1/agents", "body_json": None}, "response": {"status": 200, "body_json": json.dumps({"agents": [{"id": h.AGENTS[0], "capset_ids": [], "allowed_modes": [], "output_formats": ["json", TOKEN]}]})}}
        with self.assertRaises(h.HarnessError): h.project_exchange(catalog)
        definitions = h.json_file(ROOT / "configs" / "agents.json", "agent catalog")["agents"]; items = [{key: item[key] for key in ("id", "capset_ids", "allowed_modes", "output_formats")} for item in definitions]
        for replacement in (h.AGENTS[0], "unknown-agent"):
            malformed = copy.deepcopy(items); malformed[-1]["id"] = replacement
            exchange = {"request": {"method": "GET", "path": "/v1/agents", "body_json": None}, "response": {"status": 200, "body_json": json.dumps({"agents": malformed})}}
            with self.subTest(catalog_id=replacement), self.assertRaises(h.HarnessError): h.project_exchange(exchange)
        run_id = fake_run_id(1); capability = {"request": {"method": "POST", "path": f"/v1/runs/{run_id}/capabilities", "body_json": json.dumps({"forbidden_capability": {"method": TOKEN, "capset": "dev"}})}, "response": {"status": 403, "body_json": json.dumps({"id": run_id, "agent_id": h.AGENTS[0], "status": "failed", "error_code": "capability_denied", "sandbox_id": fake_runtime_id("sandbox", run_id)})}}
        with self.assertRaises(h.HarnessError): h.project_exchange(capability, agent_id=h.AGENTS[0], run_id=run_id)
    def test_evidence_reader_rejects_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); real = root / "real"; real.mkdir(); path = real / "evidence.json"; path.write_text("{}")
            link = root / "link"; link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(h.HarnessError, "symlink ancestor"): h.reject_symlink_ancestors(link / path.name, "evidence", root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "out"; root.mkdir(); real = Path(temporary) / "real"; real.mkdir(); os.chmod(root, 0o700); os.chmod(real, 0o700); (root / "raw-api-responses").symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(h.HarnessError, "raw evidence directory is unsafe"): h.raw_bytes(root, "raw-api-responses/000001-evidence.json", h.sha(b"{}"), "evidence")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / "out"; held = root / "held"; output_fd, raw_fd = h.new_output(output, keep_open=True); relative = "raw-api-responses/000001-evidence.json"; data = b"{}"
            try:
                h.write_new(Path(relative).name, data, raw_fd); output.rename(held); output.mkdir(0o700); replacement_raw = output / "raw-api-responses"; replacement_raw.mkdir(0o700); replacement = replacement_raw / Path(relative).name; replacement.write_bytes(b"redirected"); os.chmod(replacement, 0o600)
                self.assertEqual(h.raw_bytes(output, relative, h.sha(data), "evidence", output_fd, raw_fd), data); h.write_new("sas103-report.json", data, output_fd)
            finally:
                os.close(raw_fd); os.close(output_fd)
            self.assertEqual((held / relative).read_bytes(), data); self.assertEqual((held / "sas103-report.json").read_bytes(), data); self.assertFalse((output / "sas103-report.json").exists())
    def test_real_validator_rejects_malformed_output_and_override_is_pinned(self):
        with self.assertRaisesRegex(h.HarnessError, "output validation failed"):
            h.validate_output(h.TRUSTED_SASCTL, h.AGENTS[0], b"{}")
        with tempfile.TemporaryDirectory() as temporary:
            malicious = malicious_validator(Path(temporary))
            with self.assertRaisesRegex(h.HarnessError, "repository bin/sasctl"):
                h.validator(malicious)
    def test_normal_submission_is_waved_and_validates_pretty_artifact_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.collect(root); report = self.report(root / "out"); self.assertEqual(len([item for item in report["api"] if "-normal-" in item["relative_path"] and item["relative_path"].endswith("-create.json")]), 100); self.assertLessEqual(FakeAPI.last.max_outstanding_normal, 5)
            validator = report["validators"][0]; poll = next(item for item in report["api"] if item["run_id"] == validator["run_id"] and "-poll-" in item["relative_path"]); projected = json.loads(((root / "out") / poll["relative_path"]).read_text())["response"]["body"]; artifact_bytes = FakeAPI.last.runs[validator["run_id"]]["artifact_bytes"]; self.assertTrue(artifact_bytes.startswith(b"{\n  \"")); self.assertNotEqual(projected["raw_output_sha256"], validator["raw_output_sha256"]); self.assertEqual(validator["raw_output_sha256"], validator["artifact"]["sha256"])
            self.assertTrue(all(artifact_bytes not in path.read_bytes() for path in (root / "out").rglob("*.json")))
    def test_valid_but_different_artifact_fails_collection(self):
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(h.HarnessError, "collection failed"):
            self.collect(Path(temporary), different_artifact=True)
    def test_synchronous_cancel_action_is_valid(self):
        with tempfile.TemporaryDirectory() as temporary: self.collect(Path(temporary), synchronous_cancel=True)
    def test_unknown_provider_fails_collection(self):
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(h.HarnessError, "provenance provider"):
            self.collect(Path(temporary), unknown_provider=True)
    def test_malicious_create_is_not_persisted(self):
        agent, wrong_agent, run_id = h.AGENTS[0], h.AGENTS[1], fake_run_id(1); fixture = self.fixtures[agent]; request = h.request_for(fixture, "tenant", "normal")
        exchange = {"request": {"method": "POST", "path": f"/v1/agents/{agent}/runs", "body_json": h.canonical(request).decode()}, "response": {"status": 202, "body_json": json.dumps({"id": run_id, "agent_id": wrong_agent})}}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out"; h.new_output(output); report, state = {"api": []}, {"sequence": 0}
            with self.assertRaisesRegex(h.HarnessError, "projected agent binding"): h.record_api(report, output, state, "malicious-create", exchange, "POST", f"/v1/agents/{agent}/runs", agent)
            self.assertEqual(list((output / "raw-api-responses").iterdir()), [])
    def test_normal_gate_rejects_tampered_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report_path, binary = self.collect(root); output, report = report_path.parent, self.report(report_path.parent); agent = h.AGENTS[0]; fixture = self.fixtures[agent]
            item = next(item for item in report["api"] if f"-normal-{agent}-001-poll-" in item["relative_path"]); path = output / item["relative_path"]; original = json.loads(path.read_text())
            cases = (("status", "failed"), ("executor", "mock"), ("error_code", "executor_timeout"), ("schema_valid", False), ("output_protocol", next(value for value in h.PROTOCOLS if value != fixture["expected_protocol"])), ("output_status", next(value for value in h.OUTPUT_STATUSES if value != fixture["expected_output_status"])))
            for field, value in cases:
                exchange = copy.deepcopy(original); exchange["response"]["body"][field] = value; data = h.canonical(exchange); path.write_bytes(data); item["sha256"] = h.sha(data); self.rewrite(output, report)
                with self.subTest(field=field), self.assertRaisesRegex(h.HarnessError, "normal terminal contract|provenance|executor is invalid"): self.verify(report_path, binary)
            self.assertEqual(original["response"]["body"]["provenance"]["provider"], "pi")
            for provider in ("foo", None):
                exchange = copy.deepcopy(original); provenance = exchange["response"]["body"]["provenance"]
                if provider is None: provenance.pop("provider")
                else: provenance["provider"] = provider
                data = h.canonical(exchange); path.write_bytes(data); item["sha256"] = h.sha(data); self.rewrite(output, report)
                with self.subTest(provider=provider), self.assertRaisesRegex(h.HarnessError, "provenance"): self.verify(report_path, binary)
            artifact = original["response"]["body"]["artifacts"][0]; self.assertEqual(set(artifact), {"id", "name", "uri", "media_type", "sha256", "size_bytes"})
            for artifact_case in ("digest", "size", "missing", "duplicate"):
                exchange = copy.deepcopy(original); artifacts = exchange["response"]["body"]["artifacts"]
                if artifact_case == "digest": artifacts[0]["sha256"] = "0" * 64
                elif artifact_case == "size": artifacts[0]["size_bytes"] += 1
                elif artifact_case == "missing": exchange["response"]["body"].pop("artifacts")
                else: artifacts.append(copy.deepcopy(artifacts[0]))
                data = h.canonical(exchange); path.write_bytes(data); item["sha256"] = h.sha(data); self.rewrite(output, report)
                with self.subTest(artifact=artifact_case), self.assertRaisesRegex(h.HarnessError, "artifact|schema control"): self.verify(report_path, binary)
    def test_runs_and_counts_are_strict(self):
        normal = len(h.AGENTS) * 20
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(h.HarnessError, "collection arguments"): self.collect(Path(temporary), runs=1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report_path, binary = self.collect(root); report = self.report(report_path.parent)
            self.assertEqual(report["counts"], {"normal_attempts": normal, "normal_created": normal, "control_plane_accepted": normal, "lifecycle_attempts": len(h.AGENTS) * 2})
            report["runs_per_agent"] = 1; self.rewrite(report_path.parent, report)
            with self.assertRaisesRegex(h.HarnessError, "report index"): self.verify(report_path, binary)
            report["runs_per_agent"] = 20; report["api"] = [{}]; self.rewrite(report_path.parent, report)
            with self.assertRaisesRegex(h.HarnessError, "report index"): self.verify(report_path, binary)
    def test_ambiguous_create_interrupt_requires_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary, FakeAPI(self.fixtures) as api:
            root = Path(temporary); real_call = h.call
            def interrupt_after_create(*args, **kwargs):
                exchange = real_call(*args, **kwargs)
                if args[4] == "POST" and args[5].startswith("/v1/agents/"): raise KeyboardInterrupt
                return exchange
            with mock.patch.object(h, "call", side_effect=interrupt_after_create), self.assertRaises(KeyboardInterrupt):
                h.collect(self.manifest_path, root / "out", api.url, "tenant", 20, 1, .001, "1s", False, h.TRUSTED_SASCTL)
            self.assertEqual(self.report(root / "out")["failure"], "cleanup_required"); self.assertEqual(len(api.runs), 1)
    def test_validator_is_not_staged_before_output_exists(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(h, "_stage_validator") as stage:
            with self.assertRaisesRegex(h.HarnessError, "output directory"):
                h.collect(self.manifest_path, Path(temporary) / "missing" / "out", "http://127.0.0.1:8080", "tenant", 20, 1, .001, "1s", False, h.TRUSTED_SASCTL)
            stage.assert_not_called()
    def test_lifecycle_collection_fails_closed(self):
        for option in ("duplicate_lifecycle", "stalled_timeout", "timeout_queued"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(h.HarnessError, "collection failed"): self.collect(Path(temporary), **{option: True}, poll_timeout=.001)
    def test_lifecycle_evidence_is_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report_path, binary = self.collect(root); output, report = report_path.parent, self.report(report_path.parent); agent = h.AGENTS[0]
            cancel_poll = next(item for item in report["api"] if f"-cancel-{agent}-001-poll-" in item["relative_path"] and json.loads((output / item["relative_path"]).read_text())["response"]["body"]["status"] == "cancelled"); cancel_path = output / cancel_poll["relative_path"]; cancel_data = cancel_path.read_bytes(); cancel_exchange = json.loads(cancel_data)
            for field in ("error_code", "provenance"):
                tampered = copy.deepcopy(cancel_exchange)
                if field == "error_code": tampered["response"]["body"][field] = "agent_compose_cancelled"
                else: tampered["response"]["body"].pop(field)
                data = h.canonical(tampered); cancel_path.write_bytes(data); cancel_poll["sha256"] = h.sha(data); self.rewrite(output, report)
                with self.subTest(cancel_field=field), self.assertRaisesRegex(h.HarnessError, "cancel lifecycle"): self.verify(report_path, binary)
            cancel_path.write_bytes(cancel_data); cancel_poll["sha256"] = h.sha(cancel_data); self.rewrite(output, report)
            timeout_poll = next(item for item in report["api"] if f"-timeout-{agent}-001-poll-" in item["relative_path"]); run_id = timeout_poll["run_id"]
            action_body = {"actor": "sas103", "reason": "synthetic lifecycle control"}; action_relative = f"raw-api-responses/999998-timeout-{agent}-001-action.json"; action = {"request": {"method": "POST", "path": f"/v1/runs/{run_id}/cancel", "body_sha256": h.sha(h.canonical(action_body)), "body_present": True}, "response": {"status": 202, "body": {"id": run_id, "agent_id": agent, "status": "running"}}}; action_data = h.canonical(action); (output / action_relative).write_bytes(action_data); os.chmod(output / action_relative, 0o600)
            action_entry = {"relative_path": action_relative, "sha256": h.sha(action_data), "method": "POST", "path": f"/v1/runs/{run_id}/cancel", "agent_id": agent, "run_id": run_id}; report["api"].append(action_entry); report["api"].sort(key=lambda item: item["relative_path"]); self.rewrite(output, report)
            with self.assertRaisesRegex(h.HarnessError, "timeout lifecycle"): self.verify(report_path, binary)
            report["api"].remove(action_entry); (output / action_relative).unlink()
            extra_relative = "raw-api-responses/999999-unrelated.json"; extra = {"request": {"method": "GET", "path": "/extra", "body_sha256": None, "body_present": False}, "response": {"status": 200, "body": {}}}; extra_data = h.canonical(extra); (output / extra_relative).write_bytes(extra_data); os.chmod(output / extra_relative, 0o600)
            extra_entry = {"relative_path": extra_relative, "sha256": h.sha(extra_data), "method": "GET", "path": "/extra", "agent_id": None, "run_id": None}; report["api"].append(extra_entry); report["api"].sort(key=lambda item: item["relative_path"]); self.rewrite(output, report)
            with self.assertRaisesRegex(h.HarnessError, "unexpected API evidence"): self.verify(report_path, binary)
            report["api"].remove(extra_entry); (output / extra_relative).unlink(); self.rewrite(output, report)
            missing_path = output / timeout_poll["relative_path"]; missing_data = missing_path.read_bytes(); missing_path.unlink()
            with self.assertRaisesRegex(h.HarnessError, "raw evidence is missing"): self.verify(report_path, binary)
            missing_path.write_bytes(missing_data); os.chmod(missing_path, 0o600)
            normal_id = next(item for item in report["api"] if f"-normal-{agent}-001-poll-" in item["relative_path"])["run_id"]; timeout_id = timeout_poll["run_id"]
            for item in report["api"]:
                if f"-timeout-{agent}-001-" not in item["relative_path"]: continue
                path = output / item["relative_path"]; exchange = json.loads(path.read_text()); exchange["request"]["path"] = exchange["request"]["path"].replace(timeout_id, normal_id); result = exchange["response"]["body"]
                if result.get("id") == timeout_id: result["id"] = normal_id
                data = h.canonical(exchange); path.write_bytes(data); item["sha256"] = h.sha(data); item["path"] = item["path"].replace(timeout_id, normal_id)
                if item["run_id"] == timeout_id: item["run_id"] = normal_id
            self.rewrite(output, report)
            with self.assertRaisesRegex(h.HarnessError, "run identity is reused"): self.verify(report_path, binary)
    def test_raw_evidence_is_redacted_from_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report_path, _ = self.collect(root); output = report_path.parent
            report = report_path.read_bytes()
            for value in (PROMPT, TOKEN, OUTPUT): self.assertNotIn(value.encode(), report)
            for path in (output / "raw-api-responses").glob("*.json"): self.assertTrue(all(value.encode() not in path.read_bytes() for value in (PROMPT, TOKEN, OUTPUT)))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700); self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)
    def test_200_replay_fails_without_persisting_response_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(h.HarnessError): self.collect(root, replay=True)
            output, report = root / "out", self.report(root / "out")
            creates = [item for item in report["api"] if "-normal-" in item["relative_path"] and item["relative_path"].endswith("-create.json")]
            self.assertEqual(creates, [])
            self.assertNotIn(TOKEN.encode(), (output / "sas103-report.json").read_bytes())
            self.assertTrue(all(TOKEN.encode() not in path.read_bytes() for path in (output / "raw-api-responses").glob("*.json")))
    def test_projected_tampered_values_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report_path, binary = self.collect(root); output, report = report_path.parent, self.report(report_path.parent); item = next(item for item in report["api"] if "-normal-" in item["relative_path"] and "-poll-" in item["relative_path"]); path = output / item["relative_path"]; exchange = json.loads(path.read_text()); exchange["response"]["body"]["error_code"] = "executor_timeout"; exchange["response"]["body"]["provenance"]["daemon_run_id"] = "f" * 64; data = h.canonical(exchange); path.write_bytes(data); item["sha256"] = h.sha(data); self.rewrite(output, report)
            with self.assertRaisesRegex(h.HarnessError, "normal terminal contract|provenance|controls_unverified|required external control"): self.verify(report_path, binary)
    def test_projected_catalog_exact_match_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report_path, binary = self.collect(root); output, report = report_path.parent, self.report(report_path.parent); item = next(item for item in report["api"] if item["path"] == "/v1/agents"); path = output / item["relative_path"]; exchange = json.loads(path.read_text()); exchange["response"]["body"]["agents"][0]["allowed_modes"] = ["analyze"]; data = h.canonical(exchange); path.write_bytes(data); item["sha256"] = h.sha(data); self.rewrite(output, report)
            with self.assertRaisesRegex(h.HarnessError, "catalog contract"): self.verify(report_path, binary)

    def test_wrong_binding_and_tampered_raw_are_rejected(self):
        for field, value, update_hash in (("id", "wrong-run", True), ("agent_id", "wrong-agent", True), (None, None, False)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); report_path, binary = self.collect(root); output, report = report_path.parent, self.report(report_path.parent)
                item = next(item for item in report["api"] if "-normal-" in item["relative_path"] and "-poll-" in item["relative_path"])
                path = output / item["relative_path"]
                if field is None: path.write_bytes(b"tampered")
                else:
                    exchange = json.loads(path.read_text()); body = exchange["response"]["body"]; body[field] = value; data = h.canonical(exchange); path.write_bytes(data); item["sha256"] = h.sha(data)
                if update_hash: self.rewrite(output, report)
                with self.assertRaises(h.HarnessError): self.verify(report_path, binary)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report_path, binary = self.collect(root); report = self.report(report_path.parent); entry = report["validators"][0]; schema_hash = h.sha((ROOT / self.fixtures[entry["agent_id"]]["schema_path"]).read_bytes()); self.assertEqual(entry["output_schema_sha256"], schema_hash)
            entry["output_schema_sha256"] = "0" * 64; self.rewrite(report_path.parent, report)
            with self.assertRaisesRegex(h.HarnessError, "validator index"): self.verify(report_path, binary)
            entry["output_schema_sha256"] = schema_hash; entry["raw_output_sha256"] = "0" * 64; self.rewrite(report_path.parent, report)
            with self.assertRaisesRegex(h.HarnessError, "final output artifact"): self.verify(report_path, binary)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report_path, binary = self.collect(root); output, report = report_path.parent, self.report(report_path.parent); entry = report["validators"][0]; path = output / entry["relative_path"]
            observed = json.loads(path.read_text()); observed["contract"]["valid"] = False; data = h.canonical(observed); path.write_bytes(data); entry["sha256"] = h.sha(data); entry["contract_sha256"] = h.sha(h.canonical(observed["contract"])); self.rewrite(output, report)
            with self.assertRaisesRegex(h.HarnessError, "validator observation"): self.verify(report_path, binary)
    def test_malicious_validator_cannot_verify_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report_path, _ = self.collect(root); malicious = malicious_validator(root)
            with self.assertRaisesRegex(h.HarnessError, "repository bin/sasctl"):
                h.verify_report(report_path, self.manifest_path, sasctl_bin=malicious)
    def test_imported_controls_are_explicitly_unverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "controls"; raw = source / "raw-api-responses"; raw.mkdir(parents=True); os.chmod(source, 0o700); os.chmod(raw, 0o700)
            controls = [{"agent_id": agent, "kind": kind, "state": "not_executed"} for agent in h.AGENTS for kind in h.CONTROL_KINDS]
            controls_path = source / "controls.json"; controls_path.write_bytes(h.canonical({"schema": "sas103-controls.v1", "controls": controls}))
            with self.assertRaisesRegex(h.HarnessError, "controls_unverified"): self.collect(root, controls_path=controls_path)
            report = self.report(root / "out"); self.assertEqual(report["failure"], "controls_unverified"); self.assertEqual(report["counts"], {})
    def test_fabricated_controls_cannot_verify_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "controls"; raw = source / "raw-api-responses"; raw.mkdir(parents=True); os.chmod(source, 0o700); os.chmod(raw, 0o700); controls = []
            for number, (agent, kind) in enumerate(((agent, kind) for agent in h.AGENTS for kind in h.CONTROL_KINDS), 1):
                relative = f"raw-api-responses/{number:06d}-control-{agent}-{kind}.json"; data = h.canonical(external_control_exchange(agent, kind, number)); (source / relative).write_bytes(data); os.chmod(source / relative, 0o600); controls.append({"agent_id": agent, "kind": kind, "state": "executed", "relative_path": relative, "sha256": h.sha(data)})
            controls_path = source / "controls.json"; controls_path.write_bytes(h.canonical({"schema": "sas103-controls.v1", "controls": controls}))
            with self.assertRaisesRegex(h.HarnessError, "controls_unverified"): self.collect(root, controls_path=controls_path)
if __name__ == "__main__": unittest.main()
