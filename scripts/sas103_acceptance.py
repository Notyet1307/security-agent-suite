#!/usr/bin/env python3
"""SAS-103 collection and verification bound to private raw exchanges."""
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import json
import os
import re
import resource
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRUSTED_SASCTL = ROOT / "bin" / "sasctl"
AGENTS = ("traffic-analysis", "event-triage", "attack-path-validation", "compliance-query", "security-report")
MODES = dict(zip(AGENTS, ("analyze", "triage", "assess", "query", "weekly")))
INSUFFICIENT = dict(zip(AGENTS, ("insufficient_evidence", "insufficient_evidence", "insufficient_evidence", "insufficient_basis", "insufficient_data")))
CONTROL_KINDS = ("invalid_schema", "daemon_unavailable", "octobus_unavailable", "undeclared_capset")
TERMINAL = {"succeeded", "partial", "failed", "cancelled"}
NONTERMINAL = {"queued", "validating", "waiting_approval", "running"}
ERROR_CODES = {"agent_compose_cancelled", "executor_cancelled", "executor_timeout", "daemon_unavailable", "octobus_unavailable", "capability_denied", "agent_output_empty", "agent_output_malformed", "agent_output_contract_invalid", "agent_output_evidence_invalid", "agent_output_untrusted_claims"}
PROTOCOLS = {f"security-agent-suite.{agent}.v1" for agent in AGENTS}
PROVIDERS = {"codex", "claude", "gemini", "opencode", "pi", "dsh"}
OUTPUT_STATUSES = frozenset(INSUFFICIENT.values())
RUNTIME_SUCCESS = {"completed", "succeeded", "success"}
RUNTIME_CANCELLED = {"canceled", "cancelled"}
RUNTIME_STATUSES = RUNTIME_SUCCESS | RUNTIME_CANCELLED | {"partial", "failed", "failure", "error"}
FORBIDDEN_CAPABILITY = {"method": "calculator.v1.CalculatorService/Add", "capset": "dev"}
RUN_ID = re.compile(r"^run_[0-9]{13}_[0-9a-f]{16}$")
ARTIFACT_ID = re.compile(r"^art_[0-9]{13}_[0-9a-f]{16}$")
SHA = re.compile(r"^[0-9a-f]{64}$")
RAW_PATH = re.compile(r"^raw-api-responses/[0-9]{6}-[a-z0-9_-]+\.json$")
DURATION = re.compile(r"^[1-9][0-9]*(ms|s)$")
MAX = 8 * 1024 * 1024
GUEST = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
LIMIT = 8192

class HarnessError(RuntimeError): pass
def need(value, message):
    if not value: raise HarnessError(message)
def duplicate(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key"); result[key] = value
    return result
def bad_constant(value): raise HarnessError("non-finite JSON value")
def strict(data, label="JSON"):
    need(len(data) <= MAX, f"{label} is too large")
    try: return json.loads(data.decode(), object_pairs_hook=duplicate, parse_constant=bad_constant)
    except HarnessError: raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error: raise HarnessError(f"{label} is not strict JSON") from error
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
def sha(data): return hashlib.sha256(data).hexdigest()
def reject_symlink_ancestors(path, label, stop=None):
    current = Path(path); stop = Path(stop) if stop is not None else None
    while True:
        try: info = os.lstat(current)
        except OSError as error: raise HarnessError(f"{label} is unavailable") from error
        need(not stat.S_ISLNK(info.st_mode), f"{label} has symlink ancestor")
        if stop is not None and current == stop: return
        parent = current.parent
        if parent == current: return
        current = parent
def _same_file(left, right):
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino
def read_regular(path, label="file", limit=MAX, expected_stat=None, dir_fd=None):
    try:
        before = expected_stat or os.lstat(path, dir_fd=dir_fd) if dir_fd is not None else expected_stat or os.lstat(path); need(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode), f"{label} is not regular")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, dir_fd=dir_fd) if dir_fd is not None else os.open(path, flags)
    except (OSError, TypeError, NotImplementedError) as error: raise HarnessError(f"cannot read {label}") from error
    try:
        after = os.fstat(fd); need(stat.S_ISREG(after.st_mode) and _same_file(before, after) and stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode), f"{label} changed while opening")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk: return b"".join(chunks)
            chunks.append(chunk); size += len(chunk); need(size <= limit, f"{label} is too large")
    finally: os.close(fd)
def json_file(path, label): return strict(read_regular(path, label), label)
def sha_file(path):
    try:
        before = os.lstat(path); need(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode), "validator is not regular")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error: raise HarnessError("validator is unavailable") from error
    try:
        need(_same_file(before, os.fstat(fd)), "validator changed while opening")
        digest = hashlib.sha256()
        while chunk := os.read(fd, 65536): digest.update(chunk)
        return digest.hexdigest()
    finally: os.close(fd)
def write_new(path, data, dir_fd=None):
    directory_fd = fd = None
    try:
        if dir_fd is None:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0); directory_fd = os.open(Path(path).parent, flags); dir_fd = directory_fd
        info = os.fstat(dir_fd); need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700, "evidence directory is unsafe")
        fd = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dir_fd)
    except (OSError, TypeError, NotImplementedError, HarnessError) as error:
        if directory_fd is not None: os.close(directory_fd)
        raise HarnessError("refusing to replace evidence") from error
    try:
        os.fchmod(fd, 0o600); view = memoryview(data)
        while view: view = view[os.write(fd, view):]
    finally:
        if fd is not None: os.close(fd)
        if directory_fd is not None: os.close(directory_fd)
def raw_file(root, relative, expected_sha, label, root_fd=None, raw_fd=None): return strict(raw_bytes(root, relative, expected_sha, label, root_fd, raw_fd), label)
def new_output(path, keep_open=False):
    parent_fd = output_fd = raw_fd = None; ready = False
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0); parent_fd = os.open(Path(path).parent, flags)
        os.mkdir(Path(path).name, 0o700, dir_fd=parent_fd); output_fd = os.open(Path(path).name, flags, dir_fd=parent_fd); os.fchmod(output_fd, 0o700)
        os.mkdir("raw-api-responses", 0o700, dir_fd=output_fd); raw_fd = os.open("raw-api-responses", flags, dir_fd=output_fd); os.fchmod(raw_fd, 0o700)
        need(stat.S_IMODE(os.fstat(output_fd).st_mode) == 0o700 and stat.S_IMODE(os.fstat(raw_fd).st_mode) == 0o700, "output directory mode is unsafe"); ready = True
        return (output_fd, raw_fd) if keep_open else None
    except (OSError, TypeError, NotImplementedError) as error: raise HarnessError("output directory must be new and parent must exist") from error
    finally:
        if parent_fd is not None: os.close(parent_fd)
        if not (keep_open and ready):
            if raw_fd is not None: os.close(raw_fd)
            if output_fd is not None: os.close(output_fd)
def guest_image():
    try: value = json_file(ROOT / "release-manifest.json", "release manifest")["components"]["guest"]["repository_digest"]
    except (KeyError, TypeError) as error: raise HarnessError("release manifest lacks guest digest") from error
    need(isinstance(value, str) and GUEST.fullmatch(value), "release manifest guest digest is invalid"); return value
def fixtures(path):
    manifest = json_file(path, "fixture manifest")
    try: items = manifest["fixtures"]; result = {item["agent_id"]: item for item in items}
    except (KeyError, TypeError) as error: raise HarnessError("fixture manifest is invalid") from error
    need(manifest.get("schema") == "sas103-fixtures.v1" and len(items) == 5 and set(result) == set(AGENTS), "fixture agents are invalid")
    for agent, fixture in result.items():
        try:
            request, source = fixture["request"], fixture["fixture"]; input_ref = request["inputs"][0]
            protocol = json_file(ROOT / fixture["schema_path"], "output schema")["properties"]["protocol"]["const"]
        except (KeyError, IndexError, TypeError) as error: raise HarnessError("fixture is incomplete") from error
        need(fixture.get("case_id") == f"sas103-{agent}" and request.get("mode") == MODES[agent], "fixture mode is unsafe")
        need(sha(canonical(source)) == fixture.get("fixture_sha256") and source.get("synthetic") is True and source.get("records") == [], "fixture digest is invalid")
        need(input_ref.get("type") == "json" and input_ref.get("uri") == f"case://sas103/{agent}/fixture" and input_ref.get("sha256") == fixture["fixture_sha256"] and input_ref.get("media_type") == "application/json" and input_ref.get("metadata") == {"synthetic": "true", "data_availability": "none"}, "fixture input is invalid")
        need(request.get("policy") == {"network_access": "deny"} and request.get("output") == {"formats": ["json"]}, "fixture policy is unsafe")
        need(fixture.get("expected_protocol") == protocol and fixture.get("expected_output_status") == INSUFFICIENT[agent], "fixture output contract is invalid")
        need(fixture.get("forbidden_capability") == FORBIDDEN_CAPABILITY, "fixture forbidden capability is invalid")
    return manifest, result
def base_url(value, allow_remote):
    try: parsed = urllib.parse.urlsplit(value); _ = parsed.port
    except ValueError as error: raise HarnessError("base URL is invalid") from error
    need(parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username and not parsed.password and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment, "base URL is invalid")
    try: loopback = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError: loopback = False
    need(loopback or (allow_remote and parsed.scheme == "https"), "remote collection requires --allow-remote HTTPS")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/"), loopback
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *unused): return None
def _validator_info(path):
    path = Path(path)
    try: info = os.lstat(path)
    except OSError as error: raise HarnessError("validator is unavailable") from error
    need(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) and os.access(path, os.X_OK), "validator is absent or non-executable")
    return path, sha_file(path)
def validator(path=None):
    path = Path(path or TRUSTED_SASCTL)
    need(path.absolute() == TRUSTED_SASCTL, "validator must be the repository bin/sasctl build")
    return _validator_info(path)
def _test_validator(path):
    return _validator_info(path)
def output_limit(): resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
def _stage_validator(binary, expected_sha=None):
    source = None; fd = None
    try:
        fd = os.open(binary, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)); info = os.fstat(fd); need(stat.S_ISREG(info.st_mode) and info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH), "validator is absent or non-executable")
        digest = hashlib.sha256()
        with tempfile.NamedTemporaryFile(mode="w+b", delete=False) as staged:
            source = staged.name; os.fchmod(staged.fileno(), 0o700)
            while chunk := os.read(fd, 65536): digest.update(chunk); staged.write(chunk)
        if expected_sha is not None: need(digest.hexdigest() == expected_sha, "validator changed before execution")
        return source
    except BaseException:
        if source:
            try: os.unlink(source)
            except OSError: pass
        raise
    finally:
        if fd is not None: os.close(fd)
def validate_output(binary, agent, raw, expected_binary_sha=None, staged_binary=None):
    need(len(raw) <= MAX, "raw output is too large"); source = None; staged = staged_binary
    try:
        if staged is None: staged = _stage_validator(binary, expected_binary_sha)
        with tempfile.NamedTemporaryFile(mode="w+b", delete=False) as handle:
            source = handle.name; os.chmod(source, 0o600); handle.write(raw); handle.flush()
        with tempfile.TemporaryFile(mode="w+b") as stdout, tempfile.TemporaryFile(mode="w+b") as stderr:
            completed = subprocess.run([staged, "validate-output", "--agent", agent, "--file", source], shell=False, env={}, close_fds=True, stdout=stdout, stderr=stderr, timeout=30, preexec_fn=output_limit)
            stdout.seek(0); stderr.seek(0); output, errors = stdout.read(LIMIT + 1), stderr.read(LIMIT + 1)
        need(len(output) <= LIMIT and len(errors) <= LIMIT and not errors and completed.returncode == 0, "output validation failed")
        acknowledgement = strict(output.strip(), "validator acknowledgement")
        need(acknowledgement == {"agent_id": agent, "valid": True}, "output validation acknowledgement is invalid")
        return acknowledgement
    except (OSError, subprocess.TimeoutExpired) as error: raise HarnessError("output validation failed") from error
    finally:
        if staged_binary is None and staged:
            try: os.unlink(staged)
            except OSError: pass
        if source:
            try: os.unlink(source)
            except OSError: pass
def call(opener, url, tenant, key, method, path, body=None):
    encoded = None if body is None else canonical(body); headers = {"Accept": "application/json", "X-Tenant-ID": tenant}
    if encoded is not None: headers["Content-Type"] = "application/json"
    if key: headers["X-API-Key"] = key
    request = urllib.request.Request(url + path, data=encoded, headers=headers, method=method)
    try:
        response = opener.open(request, timeout=30)
        try: raw, status = response.read(MAX + 1), response.status
        finally: response.close()
    except urllib.error.HTTPError as error: raw, status = error.read(MAX + 1), error.code
    except (OSError, urllib.error.URLError) as error: raise HarnessError("API request failed") from error
    need(len(raw) <= MAX, "API response is too large")
    try: response_json = raw.decode()
    except UnicodeDecodeError as error: raise HarnessError("API response is not UTF-8") from error
    return {"request": {"method": method, "path": path, "body_json": None if encoded is None else encoded.decode()}, "response": {"status": status, "body_json": response_json}}
def fetch_artifact(opener, url, tenant, key, run_id, artifact):
    path = f"/v1/runs/{urllib.parse.quote(run_id, safe='')}/artifacts/{urllib.parse.quote(artifact['id'], safe='')}"; headers = {"Accept": "application/json", "X-Tenant-ID": tenant}
    if key: headers["X-API-Key"] = key
    request = urllib.request.Request(url + path, headers=headers, method="GET")
    try:
        response = opener.open(request, timeout=30)
        try: raw, status, media_type = response.read(MAX + 1), response.status, response.headers.get_content_type()
        finally: response.close()
    except urllib.error.HTTPError as error:
        try: error.read(MAX + 1)
        finally: error.close()
        raise HarnessError("artifact download failed") from error
    except (OSError, urllib.error.URLError) as error: raise HarnessError("artifact download failed") from error
    need(status == 200 and media_type == "application/json" and len(raw) <= MAX and len(raw) == artifact["size_bytes"] and sha(raw) == artifact["sha256"], "artifact download is invalid")
    return raw
def unpack_full(exchange):
    need(isinstance(exchange, dict) and set(exchange) == {"request", "response"}, "raw exchange is invalid")
    request, response = exchange["request"], exchange["response"]
    need(isinstance(request, dict) and isinstance(response, dict) and isinstance(request.get("method"), str) and isinstance(request.get("path"), str), "raw request is invalid")
    need(request.get("body_json") is None or isinstance(request.get("body_json"), str), "raw request body is invalid")
    need(isinstance(response.get("status"), int) and isinstance(response.get("body_json"), str), "raw response is invalid")
    body = None if request["body_json"] is None else strict(request["body_json"].encode(), "raw request body")
    return request, body, response, strict(response["body_json"].encode(), "raw response body")

TOKEN = re.compile(r"^[A-Za-z0-9._:/@+-]{1,256}$")
CONTROL_PATHS = {"/preflight/daemon", "/preflight/octobus", "/preflight/cli"}
def safe_text(value, label):
    need(isinstance(value, str) and TOKEN.fullmatch(value), f"{label} is invalid"); return value
def _safe_input_ref(value):
    need(isinstance(value, dict) and value.get("metadata") == {"synthetic": "true", "data_availability": "none"}, "create input is invalid")
    need(isinstance(value.get("sha256"), str) and SHA.fullmatch(value["sha256"]) and isinstance(value.get("uri"), str) and re.fullmatch(r"case://sas103/[a-z0-9-]+/fixture", value["uri"]) and value.get("type") == "json" and value.get("media_type") == "application/json", "create input is invalid")
    return {key: value[key] for key in ("sha256", "uri", "type", "media_type", "metadata")}
PROVENANCE_FIELDS = {"daemon_run_id", "sandbox_id", "agent_name", "driver", "image_ref", "status", "provider"}
def _safe_provenance(value):
    need(isinstance(value, dict), "provenance is invalid")
    result = {key: value[key] for key in PROVENANCE_FIELDS if key in value}
    for key, item in result.items():
        if key == "agent_name": need(isinstance(item, str) and item in AGENTS, "provenance agent is invalid")
        elif key == "provider": need(item in PROVIDERS, "provenance provider is invalid")
        elif key == "driver": need(item == "docker", "provenance driver is invalid")
        elif key == "image_ref": need(item == guest_image(), "provenance image is invalid")
        elif key == "status": need(isinstance(item, str) and item in RUNTIME_STATUSES, "provenance status is invalid")
        elif key in {"daemon_run_id", "sandbox_id"}: need(isinstance(item, str) and SHA.fullmatch(item), "provenance ID is invalid")
        else: raise HarnessError("provenance is invalid")
    return result
def _final_artifact(values, run_id, raw_hash=None, raw_size=None):
    need(isinstance(values, list), "final output artifact is missing")
    matches = [item for item in values if isinstance(item, dict) and item.get("name") == "agent-compose-final-output.json"]
    need(len(matches) == 1, "final output artifact is not unique"); item = matches[0]
    fields = {"id", "name", "uri", "media_type", "sha256", "size_bytes"}; need(fields <= set(item), "final output artifact is incomplete")
    artifact_id = item["id"]; expected_uri = f"artifact://runs/{run_id}/{artifact_id}-agent-compose-final-output.json"
    need(isinstance(artifact_id, str) and ARTIFACT_ID.fullmatch(artifact_id) and item["uri"] == expected_uri and item["media_type"] == "application/json" and isinstance(item["sha256"], str) and SHA.fullmatch(item["sha256"]) and isinstance(item["size_bytes"], int) and not isinstance(item["size_bytes"], bool) and item["size_bytes"] >= 0 and (raw_hash is None or item["sha256"] == raw_hash) and (raw_size is None or item["size_bytes"] == raw_size), "final output artifact is invalid")
    return {key: item[key] for key in fields}

def _safe_result(result, raw_hash=None, schema_valid=None, output_protocol=None, output_status=None, run_id=None, raw_size=None):
    need(isinstance(result, dict), "response result is invalid")
    nested = result.get("result") if isinstance(result.get("result"), dict) else {}
    allowed = {"id", "agent_id", "status", "error_code", "executor", "provenance", "sandbox_id", "raw_output_sha256"}
    projected = {key: result[key] for key in allowed if key in result}
    projected.update({key: nested[key] for key in allowed if key in nested and key not in projected})
    if "provenance" in projected: projected["provenance"] = _safe_provenance(projected["provenance"])
    if raw_hash is not None:
        projected["raw_output_sha256"] = raw_hash
        if run_id is not None:
            artifacts = result.get("artifacts", nested.get("artifacts")); projected["artifacts"] = [_final_artifact(artifacts, run_id)]
    if schema_valid is not None: projected["schema_valid"] = schema_valid
    if output_protocol is not None: projected["output_protocol"] = output_protocol
    if output_status is not None: projected["output_status"] = output_status
    for key, item in projected.items():
        if key == "id": need(isinstance(item, str) and RUN_ID.fullmatch(item), "run ID is invalid")
        elif key == "agent_id": need(isinstance(item, str) and item in AGENTS, "agent ID is invalid")
        elif key == "error_code": need(item is None or isinstance(item, str) and item in ERROR_CODES, "error code is invalid")
        elif key == "executor": need(item == "agentcompose-cli", "executor is invalid")
        elif key == "output_protocol": need(isinstance(item, str) and item in PROTOCOLS, "output protocol is invalid")
        elif key == "output_status": need(isinstance(item, str) and item in OUTPUT_STATUSES, "output status is invalid")
        elif key == "sandbox_id": need(isinstance(item, str) and SHA.fullmatch(item), "sandbox ID is invalid")
        elif key == "raw_output_sha256": need(isinstance(item, str) and SHA.fullmatch(item), "output hash is invalid")
        elif key == "schema_valid": need(isinstance(item, bool), "schema validity is invalid")
        elif key == "status": need(isinstance(item, str) and item in TERMINAL | NONTERMINAL, "response status is invalid")
        elif key == "provenance": need(isinstance(item, dict), "provenance is invalid")
        elif key == "artifacts": need(isinstance(item, list) and len(item) == 1, "final output artifact is not unique")
        else: raise HarnessError("response result is invalid")
    return projected

def project_exchange(exchange, validated=None, agent_id=None, run_id=None):
    request, body, response, result = unpack_full(exchange)
    method, path = request["method"], request["path"]
    need(not re.search(r"[?#\x00-\x1f\x7f]", path), "API path is invalid")
    create_path = re.fullmatch(r"/v1/agents/([a-z0-9-]+)/runs", path); run_path = re.fullmatch(r"/v1/runs/(run_[0-9]{13}_[0-9a-f]{16})(/cancel|/capabilities)?", path)
    need(path == "/v1/agents" or (create_path and create_path.group(1) in AGENTS) or run_path or path in CONTROL_PATHS, "unknown API endpoint or shape")
    body_hash = None if body is None else sha(canonical(body))
    projected_request = {"method": method, "path": path, "body_sha256": body_hash, "body_present": body is not None}
    projected_body = None
    if method == "GET" and path == "/v1/agents":
        need(body is None and isinstance(result, dict) and isinstance(result.get("agents"), list), "unknown API shape")
        definitions = {item["id"]: item for item in json_file(ROOT / "configs" / "agents.json", "agent catalog").get("agents", []) if isinstance(item, dict) and isinstance(item.get("id"), str)}
        need(set(definitions) == set(AGENTS), "agent catalog is invalid")
        need(len(result["agents"]) == len(AGENTS), "catalog response is invalid"); seen_agents = set(); agents = []
        for item in result["agents"]:
            need(isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"] in AGENTS and item["id"] not in seen_agents and isinstance(item.get("capset_ids"), list) and isinstance(item.get("allowed_modes"), list) and isinstance(item.get("output_formats"), list), "catalog response is invalid")
            seen_agents.add(item["id"]); need(all(item[key] == definitions[item["id"]].get(key) for key in ("capset_ids", "allowed_modes", "output_formats")), "catalog response is invalid")
            agents.append({"id": item["id"], "capset_ids": item["capset_ids"], "allowed_modes": item["allowed_modes"], "output_formats": item["output_formats"]})
        projected_response = {"status": response["status"], "body": {"agents": agents}}
    elif method == "POST" and create_path:
        need(response["status"] == 202 and agent_id is not None and create_path.group(1) == agent_id, "create response binding is invalid")
        need(isinstance(body, dict), "create request is invalid")
        input_ref = body.get("inputs", [None]); input_ref = input_ref[0] if isinstance(input_ref, list) and len(input_ref) == 1 else None
        need(isinstance(input_ref, dict), "create input is invalid")
        input_projection = _safe_input_ref(input_ref); policy = body.get("policy"); output = body.get("output")
        need(isinstance(policy, dict) and policy.get("network_access") == "deny" and isinstance(output, dict) and output.get("formats") == ["json"], "create request is unsafe")
        projected_policy = {"network_access": "deny"}
        if "max_duration" in policy:
            need(isinstance(policy["max_duration"], str) and DURATION.fullmatch(policy["max_duration"]), "create duration is invalid")
            projected_policy["max_duration"] = policy["max_duration"]
        projected_request.update({"case_id": safe_text(body.get("case_id"), "case_id"), "mode": safe_text(body.get("mode"), "mode"), "request_id_sha256": sha(body["request_id"].encode()) if isinstance(body.get("request_id"), str) and len(body["request_id"]) <= 256 else None, "tenant_id_sha256": sha(body["scope"]["tenant_id"].encode()) if isinstance(body.get("scope"), dict) and isinstance(body["scope"].get("tenant_id"), str) and len(body["scope"]["tenant_id"]) <= 256 else None, "input": input_projection, "policy": projected_policy, "output": {"formats": [safe_text(item, "output format") for item in output["formats"]]}})
        projected_response = {"status": response["status"], "body": _safe_result(result)}
        need("id" in projected_response["body"], "create response binding is invalid")
    elif method == "GET" and run_path and run_path.group(2) is None:
        need(response["status"] == 200, "poll response status is invalid")
        need(body is None and isinstance(result, dict), "poll response is invalid")
        raw = result.get("raw_output"); nested = result.get("result") if isinstance(result.get("result"), dict) else {}; raw = nested.get("raw_output", raw)
        if raw is not None:
            raw_bytes_value = raw.encode() if isinstance(raw, str) else canonical(raw); raw_hash = sha(raw_bytes_value); payload = strict(raw_bytes_value, "raw output")
            need(isinstance(payload, dict) and isinstance(payload.get("protocol"), str) and isinstance(payload.get("status"), str), "normal output contract is invalid"); output_protocol, output_status = payload["protocol"], payload["status"]
        else: raw_hash = output_protocol = output_status = None
        projected_response = {"status": response["status"], "body": _safe_result(result, raw_hash, validated, output_protocol, output_status, run_path.group(1), len(raw_bytes_value) if raw is not None else None)}
    elif method == "POST" and run_path and run_path.group(2) == "/cancel":
        need(isinstance(body, dict) and isinstance(result, dict), "action response is invalid")
        projected_response = {"status": response["status"], "body": _safe_result(result)}
        status = projected_response["body"].get("status"); need((response["status"] == 202 and status == "running") or (response["status"] == 200 and status in TERMINAL), "cancel response status is invalid")
    elif method in {"GET", "POST"} and (path in CONTROL_PATHS or (run_path and run_path.group(2) == "/capabilities")):
        need(isinstance(result, dict), "control response is invalid")
        projected_response = {"status": response["status"], "body": _safe_result(result)}
        if isinstance(body, dict) and "forbidden_capability" in body:
            capability = body["forbidden_capability"]; need(capability == FORBIDDEN_CAPABILITY, "control request is invalid")
            projected_request["forbidden_capability"] = capability
    else:
        raise HarnessError(f"unknown API endpoint or shape: {method} {path}")
    projected_body = projected_response["body"]
    if agent_id is not None: need(projected_body.get("agent_id") == agent_id, "projected agent binding is invalid")
    if run_id is not None: need(run_path and run_path.group(1) == run_id and projected_body.get("id") == run_id, "projected run binding is invalid")
    return {"request": projected_request, "response": projected_response}

def unpack(exchange):
    if isinstance(exchange, dict) and isinstance(exchange.get("request"), dict) and "body_json" in exchange["request"]: return unpack_full(exchange)
    need(isinstance(exchange, dict) and set(exchange) == {"request", "response"}, "projected exchange is invalid")
    request, response = exchange["request"], exchange["response"]; need(isinstance(request, dict) and isinstance(response, dict), "projected exchange is invalid")
    common = {"method", "path", "body_sha256", "body_present"}; extras = {"case_id", "mode", "request_id_sha256", "tenant_id_sha256", "input", "policy", "output"} if re.fullmatch(r"/v1/agents/[^/]+/runs", request.get("path", "")) else ({"forbidden_capability"} if "forbidden_capability" in request else set())
    need(set(request) == common | extras and isinstance(request["method"], str) and isinstance(request["path"], str) and (request["body_sha256"] is None or SHA.fullmatch(request["body_sha256"])) and isinstance(request["body_present"], bool), "projected request is invalid")
    allowed = {"agents"} if request["path"] == "/v1/agents" else {"id", "agent_id", "status", "error_code", "executor", "provenance", "sandbox_id", "raw_output_sha256", "schema_valid", "output_protocol", "output_status", "artifacts"}; need(set(response["body"]) <= allowed, "projected response has unknown fields")
    if request["path"] != "/v1/agents":
        for key, item in response["body"].items():
            if key == "id": need(isinstance(item, str) and RUN_ID.fullmatch(item), "run ID is invalid")
            elif key == "agent_id": need(isinstance(item, str) and item in AGENTS, "agent ID is invalid")
            elif key == "status": need(isinstance(item, str) and item in TERMINAL | NONTERMINAL, "response status is invalid")
            elif key == "error_code": need(item is None or isinstance(item, str) and item in ERROR_CODES, "error code is invalid")
            elif key == "executor": need(item == "agentcompose-cli", "executor is invalid")
            elif key == "provenance": need(_safe_provenance(item) == item, "provenance is invalid")
            elif key in {"sandbox_id", "raw_output_sha256"}: need(isinstance(item, str) and SHA.fullmatch(item), "projected hash is invalid")
            elif key == "schema_valid": need(isinstance(item, bool), "schema validity is invalid")
            elif key == "output_protocol": need(isinstance(item, str) and item in PROTOCOLS, "output protocol is invalid")
            elif key == "artifacts": need(isinstance(item, list) and len(item) == 1 and _final_artifact(item, request["path"].rsplit("/", 1)[-1]) == item[0], "final output artifact is invalid")
            elif key == "output_status": need(isinstance(item, str) and item in OUTPUT_STATUSES, "output status is invalid")
    else: need(set(response["body"]) == {"agents"}, "catalog response is invalid")
    body = {key: value for key, value in request.items() if key not in common}
    return request, body if request["body_present"] else None, response, response["body"]
def next_path(state, label):
    state["sequence"] += 1; return f"raw-api-responses/{state['sequence']:06d}-{label}.json"
def record_api(report, output, state, label, exchange, method, path, agent_id=None, run_id=None, validated=None):
    relative = next_path(state, label); projected = project_exchange(exchange, validated, agent_id, run_id); data = canonical(projected); write_new(Path(relative).name if state.get("raw_fd") is not None else output / relative, data, state.get("raw_fd"))
    report["api"].append({"relative_path": relative, "sha256": sha(data), "method": method, "path": path, "agent_id": agent_id, "run_id": run_id})
def record_validator(report, output, state, label, agent, run_id, binary_sha, contract, artifact, schema_sha):
    need(contract == {"agent_id": agent, "valid": True}, "validator acknowledgement is invalid")
    artifact = _final_artifact([artifact], run_id); raw_hash = artifact["sha256"]; contract_hash = sha(canonical(contract)); observed = {"binary_sha256": binary_sha, "raw_output_sha256": raw_hash, "schema_valid": True, "contract": contract, "artifact": artifact, "output_schema_sha256": schema_sha}
    relative = next_path(state, label); data = canonical(observed); write_new(Path(relative).name if state.get("raw_fd") is not None else output / relative, data, state.get("raw_fd"))
    report["validators"].append({"relative_path": relative, "sha256": sha(data), "agent_id": agent, "run_id": run_id, "binary_sha256": binary_sha, "raw_output_sha256": raw_hash, "schema_valid": True, "contract_sha256": contract_hash, "artifact": artifact, "output_schema_sha256": schema_sha})
def request_for(fixture, tenant, scenario, duration=None):
    request = json.loads(canonical(fixture["request"])); request["request_id"] = f"sas103-{fixture['agent_id']}-{scenario}-{uuid.uuid4().hex}"; request["scope"]["tenant_id"] = tenant
    if duration: request["policy"]["max_duration"] = duration
    return request
def bind_create(fixture, entry, exchange, scenario, seen):
    request, body, response, result = unpack(exchange)
    need(entry["method"] == request["method"] == "POST" and entry["path"] == request["path"] == f"/v1/agents/{fixture['agent_id']}/runs" and entry["agent_id"] == fixture["agent_id"] and entry["run_id"] is None and isinstance(body, dict), "create binding is invalid")
    if "body_json" not in exchange["request"]:
        need(body.get("case_id") == fixture["case_id"] and body.get("mode") == fixture["request"]["mode"], "create request differs from fixture")
        request_hash = request.get("request_id_sha256"); need(isinstance(request_hash, str) and SHA.fullmatch(request_hash) and request_hash not in seen, "request_id is not fresh"); seen.add(request_hash)
        input_ref = body.get("input", {})
        need(request.get("tenant_id_sha256") and input_ref == {"sha256": fixture["fixture_sha256"], "uri": f"case://sas103/{fixture['agent_id']}/fixture", "type": "json", "media_type": "application/json", "metadata": {"synthetic": "true", "data_availability": "none"}}, "create input differs from fixture")
        need(body.get("policy", {}).get("network_access") == "deny" and body.get("output") == {"formats": ["json"]}, "create policy is unsafe")
        if scenario == "timeout": need(DURATION.fullmatch(body.get("policy", {}).get("max_duration", "")), "timeout duration is invalid")
        else: need("max_duration" not in body.get("policy", {}), "unexpected timeout duration")
    else:
        inputs = body.get("inputs"); input_ref = inputs[0] if isinstance(inputs, list) and len(inputs) == 1 else {}
        need(body.get("case_id") == fixture["case_id"] and body.get("mode") == fixture["request"]["mode"], "create request differs from fixture")
        need(isinstance(body.get("request_id"), str) and body["request_id"] not in seen and body["request_id"] != "__SAS103_REQUEST_ID__", "request_id is not fresh"); seen.add(body["request_id"])
        need(isinstance(body.get("scope", {}).get("tenant_id"), str) and body["scope"]["tenant_id"], "tenant ID is missing")
        need(input_ref.get("type") == "json" and input_ref.get("uri") == f"case://sas103/{fixture['agent_id']}/fixture" and input_ref.get("sha256") == fixture["fixture_sha256"] and input_ref.get("media_type") == "application/json" and input_ref.get("metadata") == {"synthetic": "true", "data_availability": "none"}, "create input differs from fixture")
        need(body.get("policy", {}).get("network_access") == "deny" and body.get("output") == {"formats": ["json"]}, "create policy is unsafe")
        if scenario == "timeout": need(isinstance(body["policy"].get("max_duration"), str) and DURATION.fullmatch(body["policy"]["max_duration"]), "timeout duration is invalid")
        else: need("max_duration" not in body.get("policy", {}), "unexpected timeout duration")
    need(response["status"] == 202 and isinstance(result, dict) and result.get("agent_id") == fixture["agent_id"] and isinstance(result.get("id"), str) and result["id"], "create was not a new bound run")
    return result["id"]
def bind_poll(fixture, entry, exchange, run_id):
    request, body, response, result = unpack(exchange); expected = f"/v1/runs/{urllib.parse.quote(run_id, safe='')}"
    need(entry["method"] == request["method"] == "GET" and entry["path"] == request["path"] == expected and entry["agent_id"] == fixture["agent_id"] and entry["run_id"] == run_id and body is None, "poll binding is invalid")
    need(response["status"] == 200 and isinstance(result, dict) and result.get("id") == run_id and result.get("agent_id") == fixture["agent_id"] and isinstance(result.get("status"), str), "poll is bound to the wrong run or agent")
    return result
def raw_output(fixture, terminal, image):
    need(terminal.get("status") == "partial", "normal run did not become partial")
    result = terminal.get("result"); need(isinstance(result, dict) and result.get("executor") == "agentcompose-cli", "normal executor is invalid")
    need(result.get("error_code") is None, "normal terminal contract is invalid")
    raw = result.get("raw_output"); data = raw.encode() if isinstance(raw, str) else canonical(raw); payload = strict(data, "raw output")
    need(isinstance(payload, dict) and payload.get("protocol") == fixture["expected_protocol"] and payload.get("status") == fixture["expected_output_status"], "normal output is not the expected insufficient payload")
    provenance = result.get("provenance"); need(isinstance(provenance, dict) and provenance.get("agent_name") == fixture["agent_id"] and provenance.get("provider") in PROVIDERS and all(isinstance(provenance.get(name), str) and provenance[name] for name in ("daemon_run_id", "sandbox_id")), "provenance is invalid")
    need(provenance.get("driver") == "docker" and provenance.get("image_ref") == image, "provenance runtime differs")
    return data
def catalog_gate(entry, exchange, fixture_map):
    request, body, response, result = unpack(exchange)
    need(entry["method"] == request["method"] == "GET" and entry["path"] == request["path"] == "/v1/agents" and entry["agent_id"] is entry["run_id"] is None and body is None and response["status"] == 200 and isinstance(result, dict) and isinstance(result.get("agents"), list), "catalog binding is invalid")
    definitions = {item["id"]: item for item in json_file(ROOT / "configs" / "agents.json", "agent catalog")["agents"]}
    need(len(result["agents"]) == len(AGENTS), "catalog agents differ"); agents = {}
    for item in result["agents"]:
        need(isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"] in AGENTS and item["id"] not in agents, "catalog agents differ")
        agents[item["id"]] = item
    need(set(agents) == set(AGENTS), "catalog agents differ")
    for agent, fixture in fixture_map.items():
        item = agents[agent]; definition = definitions[agent]; need(all(item.get(key) == definition[key] for key in ("capset_ids", "allowed_modes", "output_formats")) and item.get("capset_ids") == fixture["declared_capsets"] and fixture["request"]["mode"] in item["allowed_modes"] and "json" in item["output_formats"], "catalog contract differs")
def raw_bytes(root, relative, expected_sha, label, root_fd=None, raw_fd=None):
    need(isinstance(relative, str) and RAW_PATH.fullmatch(relative) and isinstance(expected_sha, str) and SHA.fullmatch(expected_sha), "raw evidence path is invalid")
    directory = root / "raw-api-responses"; path = root / relative; need(path.parent == directory, "raw evidence path escapes report directory")
    own_root = own_raw = False
    try:
        dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        if root_fd is None:
            root_info = os.lstat(root); need(stat.S_ISDIR(root_info.st_mode) and not stat.S_ISLNK(root_info.st_mode), "raw evidence directory is unsafe")
            root_fd = os.open(root, dir_flags); own_root = True; need(_same_file(root_info, os.fstat(root_fd)), "raw evidence root changed while opening")
        root_info = os.fstat(root_fd); need(stat.S_ISDIR(root_info.st_mode) and stat.S_IMODE(root_info.st_mode) == 0o700, "raw evidence directory is unsafe")
        current = os.lstat("raw-api-responses", dir_fd=root_fd); need(stat.S_ISDIR(current.st_mode) and not stat.S_ISLNK(current.st_mode) and stat.S_IMODE(current.st_mode) == 0o700, "raw evidence directory is unsafe")
        if raw_fd is None:
            raw_fd = os.open("raw-api-responses", dir_flags, dir_fd=root_fd); own_raw = True
        raw_info = os.fstat(raw_fd); need(stat.S_ISDIR(raw_info.st_mode) and _same_file(current, raw_info) and stat.S_IMODE(raw_info.st_mode) == 0o700, "raw evidence directory changed while opening")
        try: file_info = os.lstat(path.name, dir_fd=raw_fd)
        except OSError as error: raise HarnessError("raw evidence is missing") from error
        need(stat.S_ISREG(file_info.st_mode) and not stat.S_ISLNK(file_info.st_mode) and stat.S_IMODE(file_info.st_mode) == 0o600, "raw evidence file is unsafe")
        data = read_regular(path.name, label, expected_stat=file_info, dir_fd=raw_fd); need(sha(data) == expected_sha, "raw evidence digest differs"); return data
    except (OSError, TypeError, NotImplementedError) as error: raise HarnessError("cannot read raw evidence") from error
    finally:
        if own_raw: os.close(raw_fd)
        if own_root: os.close(root_fd)

def control_records(controls):
    wanted = {(agent, kind) for agent in AGENTS for kind in CONTROL_KINDS}; need(isinstance(controls, list) and len(controls) == len(wanted), "external controls are incomplete")
    seen = set()
    for control in controls:
        need(isinstance(control, dict) and isinstance(control.get("agent_id"), str) and isinstance(control.get("kind"), str), "external control is invalid")
        key = control["agent_id"], control["kind"]; need(key in wanted and key not in seen, "external controls are invalid"); seen.add(key)
        if control.get("state") == "not_executed": need(set(control) == {"agent_id", "kind", "state"}, "not-executed control is invalid")
        else: need(control.get("state") == "executed" and set(control) == {"agent_id", "kind", "state", "relative_path", "sha256"} and isinstance(control["relative_path"], str) and RAW_PATH.fullmatch(control["relative_path"]) and isinstance(control["sha256"], str) and SHA.fullmatch(control["sha256"]), "executed control is invalid")
    return controls
def load_controls(path):
    value = json_file(path, "controls document"); need(isinstance(value, dict) and set(value) == {"schema", "controls"} and value["schema"] == "sas103-controls.v1", "controls document is invalid")
    return control_records(value["controls"])
def import_controls(output, state, path):
    raise HarnessError("controls_unverified: no trusted signed or independently reviewable attestation mechanism is configured")
def lifecycle_records(acknowledged=False):
    return sorted(({"agent_id": agent, "scenario": scenario, "downstream_acknowledged": acknowledged} for agent in AGENTS for scenario in ("cancel", "timeout")), key=lambda item: (item["agent_id"], item["scenario"]))
def label(entry): return Path(entry["relative_path"]).stem.split("-", 1)[1]
def api_index(root, entries, root_fd=None, raw_fd=None):
    fields = {"relative_path", "sha256", "method", "path", "agent_id", "run_id"}; result = {}
    need(isinstance(entries, list), "API index is invalid")
    for entry in entries:
        need(isinstance(entry, dict) and set(entry) == fields and isinstance(entry["method"], str) and isinstance(entry["path"], str) and (entry["agent_id"] is None or isinstance(entry["agent_id"], str)) and (entry["run_id"] is None or isinstance(entry["run_id"], str)), "API index is invalid")
        key = entry["relative_path"]; need(key not in result, "raw evidence is indexed twice"); exchange = raw_file(root, key, entry["sha256"], "API evidence", root_fd, raw_fd); need("body_json" not in exchange.get("request", {}) and "body_json" not in exchange.get("response", {}), "raw API body persisted"); unpack(exchange); result[key] = (entry, exchange)
    return result
def validator_index(root, entries, api, binary_sha, schema_hashes, root_fd=None, raw_fd=None):
    fields = {"relative_path", "sha256", "agent_id", "run_id", "binary_sha256", "raw_output_sha256", "schema_valid", "contract_sha256", "artifact", "output_schema_sha256"}; result, paths = {}, set()
    need(isinstance(entries, list), "validator index is invalid")
    for entry in entries:
        need(isinstance(entry, dict) and set(entry) == fields and isinstance(entry["agent_id"], str) and entry["agent_id"] in schema_hashes and isinstance(entry["run_id"], str) and isinstance(entry["schema_valid"], bool) and all(isinstance(entry[name], str) and SHA.fullmatch(entry[name]) for name in ("sha256", "binary_sha256", "raw_output_sha256", "contract_sha256", "output_schema_sha256")) and entry["binary_sha256"] == binary_sha and entry["output_schema_sha256"] == schema_hashes[entry["agent_id"]] and entry["schema_valid"], "validator index is invalid")
        artifact = _final_artifact([entry["artifact"]], entry["run_id"], entry["raw_output_sha256"]); need(artifact == entry["artifact"], "validator artifact is invalid")
        key = entry["relative_path"]; need(key not in paths and key not in api, "validator evidence is indexed twice"); paths.add(key); observed = raw_file(root, key, entry["sha256"], "validator evidence", root_fd, raw_fd)
        need(isinstance(observed, dict) and set(observed) == {"binary_sha256", "raw_output_sha256", "schema_valid", "contract", "artifact", "output_schema_sha256"} and observed["binary_sha256"] == binary_sha and observed["raw_output_sha256"] == entry["raw_output_sha256"] and observed["schema_valid"] is True and observed["contract"] == {"agent_id": entry["agent_id"], "valid": True} and observed["artifact"] == artifact and observed["output_schema_sha256"] == schema_hashes[entry["agent_id"]] and entry["contract_sha256"] == sha(canonical(observed["contract"])), "validator observation is invalid")
        binding = entry["agent_id"], entry["run_id"]; need(binding not in result, "validator evidence is indexed twice"); result[binding] = entry
    return result
def records(api, prefix): return sorted((pair for pair in api.values() if label(pair[0]).startswith(prefix)), key=lambda pair: pair[0]["relative_path"])
def normal_gate(fixture, attempt, api, validators, image, seen):
    prefix = f"normal-{fixture['agent_id']}-{attempt:03d}-"; group = records(api, prefix); creates = [pair for pair in group if label(pair[0]).endswith("-create")]; polls = [pair for pair in group if "-poll-" in label(pair[0])]
    need(len(creates) == 1 and len(creates) + len(polls) == len(group) and polls, "normal evidence is incomplete")
    run_id = bind_create(fixture, creates[0][0], creates[0][1], "normal", seen); states = [bind_poll(fixture, entry, exchange, run_id) for entry, exchange in polls]
    need(all(state.get("status") in NONTERMINAL for state in states[:-1]), "normal evidence has extra terminal state"); terminal = states[-1]
    need(terminal.get("status") == "partial" and terminal.get("executor") == "agentcompose-cli" and terminal.get("error_code") is None and terminal.get("schema_valid") is True and terminal.get("output_protocol") == fixture["expected_protocol"] and terminal.get("output_status") == fixture["expected_output_status"], "normal terminal contract is invalid")
    need(SHA.fullmatch(terminal.get("raw_output_sha256", "")), "projected output hash invalid")
    provenance = terminal.get("provenance"); need(isinstance(provenance, dict) and provenance.get("agent_name") == fixture["agent_id"] and provenance.get("driver") == "docker" and provenance.get("image_ref") == image and provenance.get("status") in RUNTIME_SUCCESS and provenance.get("provider") in PROVIDERS and provenance.get("daemon_run_id") and provenance.get("sandbox_id"), "provenance is invalid")
    observed = validators.get((fixture["agent_id"], run_id)); need(observed is not None and terminal.get("artifacts") == [observed["artifact"]] and observed["schema_valid"] is True, "schema control is not proven")
    return run_id
def lifecycle_gate(fixture, scenario, api, seen, timeout_duration):
    prefix = f"{scenario}-{fixture['agent_id']}-001-"; group = records(api, prefix); creates = [pair for pair in group if label(pair[0]).endswith("-create")]; polls = [pair for pair in group if "-poll-" in label(pair[0])]; actions = [pair for pair in group if label(pair[0]).endswith("-action")]
    need(len(creates) == 1 and polls and len(creates) + len(polls) + len(actions) == len(group), "lifecycle evidence is incomplete")
    run_id = bind_create(fixture, creates[0][0], creates[0][1], scenario, seen); create_request, _, _, _ = unpack(creates[0][1]); states = [(entry, bind_poll(fixture, entry, exchange, run_id)) for entry, exchange in polls]
    need(all(state.get("status") in NONTERMINAL for _, state in states[:-1]), "lifecycle evidence has extra terminal state")
    if scenario == "cancel":
        need(len(actions) == 1, "cancel action is missing"); entry, exchange = actions[0]; request, body, response, result = unpack(exchange); expected = f"/v1/runs/{urllib.parse.quote(run_id, safe='')}/cancel"
        action_provenance = result.get("provenance"); need(entry["method"] == request["method"] == "POST" and entry["path"] == request["path"] == expected and entry["agent_id"] == fixture["agent_id"] and entry["run_id"] == run_id and isinstance(body, dict) and response["status"] in {200, 202} and isinstance(result, dict) and result.get("id") == run_id and result.get("agent_id") == fixture["agent_id"] and ((response["status"] == 202 and result.get("status") == "running") or (response["status"] == 200 and result.get("status") == "cancelled" and result.get("error_code") == "executor_cancelled" and isinstance(action_provenance, dict) and action_provenance.get("status") in RUNTIME_CANCELLED and action_provenance.get("agent_name") == fixture["agent_id"])), "cancel action is invalid")
        action_path = entry["relative_path"]; running = next((index for index, (_, state) in enumerate(states) if state.get("status") == "running"), None); terminal = states[-1][1]; provenance = terminal.get("provenance")
        need(running is not None and running + 1 < len(states) and states[running][0]["relative_path"] < action_path < states[running + 1][0]["relative_path"] and terminal.get("status") == "cancelled" and terminal.get("error_code") == "executor_cancelled" and isinstance(provenance, dict) and provenance.get("agent_name") == fixture["agent_id"] and provenance.get("driver") == "docker" and provenance.get("image_ref") == guest_image() and provenance.get("status") in RUNTIME_CANCELLED and all(provenance.get(name) for name in ("daemon_run_id", "sandbox_id")), "cancel lifecycle is invalid")
    else:
        need(create_request.get("policy", {}).get("max_duration") == timeout_duration, "timeout duration does not match configured duration")
        need(states[:-1] and any(state.get("status") == "running" for _, state in states[:-1]), "timeout lifecycle lacks an observed running state")
        terminal = states[-1][1]; provenance = terminal.get("provenance")
        need(not actions and terminal.get("status") == "failed" and terminal.get("error_code") == "executor_timeout" and isinstance(provenance, dict) and provenance.get("agent_name") == fixture["agent_id"] and provenance.get("driver") == "docker" and provenance.get("image_ref") == guest_image() and provenance.get("status") in RUNTIME_CANCELLED and all(provenance.get(name) for name in ("daemon_run_id", "sandbox_id")), "timeout lifecycle is invalid")
    return run_id
def verify_controls(controls, root, fixture_map):
    raise HarnessError("controls_unverified: no trusted signed or independently reviewable attestation mechanism is configured")
def selected_controls(report, root, path):
    if path is not None:
        raise HarnessError("controls_unverified: no trusted signed or independently reviewable attestation mechanism is configured")
    return report["controls"]
def verify_report(report_path, manifest_path, controls_path=None, sasctl_bin=None, *, _validator=None):
    try:
        root_info, report_info = os.lstat(report_path.parent), os.lstat(report_path)
    except OSError as error: raise HarnessError("report is missing") from error
    need(stat.S_ISDIR(root_info.st_mode) and not stat.S_ISLNK(root_info.st_mode) and stat.S_IMODE(root_info.st_mode) == 0o700 and stat.S_ISREG(report_info.st_mode) and not stat.S_ISLNK(report_info.st_mode) and stat.S_IMODE(report_info.st_mode) == 0o600, "report storage is unsafe")
    reject_symlink_ancestors(report_path, "report", report_path.parent)
    root_fd = raw_fd = None
    try:
        try:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0); root_fd = os.open(report_path.parent, flags); opened_root = os.fstat(root_fd); need(stat.S_ISDIR(opened_root.st_mode) and _same_file(root_info, opened_root) and stat.S_IMODE(opened_root.st_mode) == 0o700, "report storage changed while opening")
            report = strict(read_regular(report_path.name, "report", expected_stat=report_info, dir_fd=root_fd), "report")
            raw_info = os.lstat("raw-api-responses", dir_fd=root_fd); need(stat.S_ISDIR(raw_info.st_mode) and not stat.S_ISLNK(raw_info.st_mode) and stat.S_IMODE(raw_info.st_mode) == 0o700, "raw evidence directory is unsafe")
            raw_fd = os.open("raw-api-responses", flags, dir_fd=root_fd); opened_raw = os.fstat(raw_fd); need(stat.S_ISDIR(opened_raw.st_mode) and _same_file(raw_info, opened_raw) and stat.S_IMODE(opened_raw.st_mode) == 0o700, "raw evidence directory changed while opening")
            manifest, fixture_map = fixtures(manifest_path)
            schema_hashes = {agent: sha(read_regular(ROOT / fixture["schema_path"], "output schema")) for agent, fixture in fixture_map.items()}
        except (OSError, TypeError, NotImplementedError) as error: raise HarnessError("report is missing") from error
        fields = {"schema", "manifest_sha256", "guest_image_ref", "runs_per_agent", "timeout_max_duration", "failure", "api", "validators", "counts", "lifecycle", "controls"}
        need(isinstance(report, dict) and set(report) == fields and report["schema"] == "sas103-raw-index.v1", "report shape is invalid")
        need(isinstance(report["timeout_max_duration"], str) and DURATION.fullmatch(report["timeout_max_duration"]), "report timeout duration is invalid")
        image = guest_image(); need(report["manifest_sha256"] == sha(canonical(manifest)) and report["guest_image_ref"] == image, "report is incomplete")
        if report["failure"] == "controls_unverified": raise HarnessError("controls_unverified: no trusted signed or independently reviewable attestation mechanism is configured")
        need(report["failure"] is None, "report is incomplete")
        for entries in (report["api"], report["validators"]):
            need(isinstance(entries, list) and all(isinstance(item, dict) and isinstance(item.get("relative_path"), str) for item in entries), "report index is invalid")
        need(isinstance(report["runs_per_agent"], int) and report["runs_per_agent"] == 20 and report["api"] == sorted(report["api"], key=lambda item: item["relative_path"]) and report["validators"] == sorted(report["validators"], key=lambda item: item["relative_path"]), "report index is invalid")
        binary, binary_sha = _validator() if _validator else validator(sasctl_bin or TRUSTED_SASCTL)
        api = api_index(report_path.parent, report["api"], root_fd, raw_fd); validators = validator_index(report_path.parent, report["validators"], api, binary_sha, schema_hashes, root_fd, raw_fd); catalog = api.get(next((path for path, pair in api.items() if label(pair[0]) == "catalog"), ""))
        need(catalog is not None and len([pair for pair in api.values() if label(pair[0]) == "catalog"]) == 1, "catalog evidence is missing"); catalog_gate(catalog[0], catalog[1], fixture_map)
        seen, accepted, normal_created, run_ids, normal_runs = set(), 0, 0, set(), set()
        used = {catalog[0]["relative_path"]}
        for agent in AGENTS:
            for attempt in range(1, report["runs_per_agent"] + 1):
                group = records(api, f"normal-{agent}-{attempt:03d}-"); used.update(entry["relative_path"] for entry, _ in group)
                creates = [exchange for entry, exchange in group if label(entry).endswith("-create")]
                normal_created += len(creates) == 1 and creates[0]["response"]["status"] == 202
                run_id = normal_gate(fixture_map[agent], attempt, api, validators, image, seen); need(run_id not in run_ids, "run identity is reused"); run_ids.add(run_id); normal_runs.add((agent, run_id)); accepted += 1
        for agent in AGENTS:
            for scenario in ("cancel", "timeout"):
                group = records(api, f"{scenario}-{agent}-001-"); used.update(entry["relative_path"] for entry, _ in group)
                run_id = lifecycle_gate(fixture_map[agent], scenario, api, seen, report["timeout_max_duration"]); need(run_id not in run_ids, "run identity is reused"); run_ids.add(run_id)
        need(set(api) == used, "unexpected API evidence")
        need(set(validators) == normal_runs, "validator evidence does not match normal runs")
        controls = selected_controls(report, report_path.parent, controls_path)
        expected = lifecycle_records(True); need(report["lifecycle"] == expected, "lifecycle acknowledgement is invalid")
        counts = {"normal_attempts": len(AGENTS) * report["runs_per_agent"], "normal_created": normal_created, "control_plane_accepted": accepted, "lifecycle_attempts": len(expected)}
        need(report["counts"] == counts and normal_created == counts["normal_attempts"] and accepted == counts["normal_attempts"], "derived report counts are invalid")
        verify_controls(controls, report_path.parent, fixture_map); return counts
    finally:
        if raw_fd is not None: os.close(raw_fd)
        if root_fd is not None: os.close(root_fd)
def collect(manifest_path, output, url, tenant, runs, poll_timeout, poll_interval, duration, allow_remote, sasctl_bin=None, controls_path=None, *, _validator=None):
    manifest, fixture_map = fixtures(manifest_path); need(isinstance(runs, int) and runs == 20 and DURATION.fullmatch(duration), "collection arguments are invalid"); schema_hashes = {agent: sha(read_regular(ROOT / fixture["schema_path"], "output schema")) for agent, fixture in fixture_map.items()}; binary, binary_sha = _validator() if _validator else validator(sasctl_bin or TRUSTED_SASCTL)
    url, loopback = base_url(url, allow_remote); key = os.environ.get("SAS_API_KEY"); need(loopback or not key or url.startswith("https://"), "refusing API key over remote HTTP")
    controls = [{"agent_id": agent, "kind": kind, "state": "not_executed"} for agent in AGENTS for kind in CONTROL_KINDS]
    report = {"schema": "sas103-raw-index.v1", "manifest_sha256": sha(canonical(manifest)), "guest_image_ref": guest_image(), "runs_per_agent": runs, "timeout_max_duration": duration, "failure": None, "api": [], "validators": [], "counts": {}, "lifecycle": lifecycle_records(), "controls": controls}
    report["lifecycle"].sort(key=lambda item: (item["agent_id"], item["scenario"])); report["controls"].sort(key=lambda item: (item["agent_id"], item["kind"])); opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    output_fd, raw_fd = new_output(output, keep_open=True); staged_binary = None; side_effects = controls_blocked = False; state, normals, failed, run_ids = {"sequence": 0, "raw_fd": raw_fd}, [], False, set()
    try:
        staged_binary = _stage_validator(binary, binary_sha)
        if controls_path:
            try: report["controls"] = import_controls(output, state, controls_path)
            except BaseException: controls_blocked = True; raise
            report["controls"].sort(key=lambda item: (item["agent_id"], item["kind"]))
        exchange = call(opener, url, tenant, key, "GET", "/v1/agents"); record_api(report, output, state, "catalog", exchange, "GET", "/v1/agents"); catalog_gate(report["api"][-1], exchange, fixture_map)
        for attempt in range(1, runs + 1):
            wave = []
            for agent in AGENTS:
                fixture = fixture_map[agent]; side_effects = True; exchange = call(opener, url, tenant, key, "POST", f"/v1/agents/{agent}/runs", request_for(fixture, tenant, "normal")); record_api(report, output, state, f"normal-{agent}-{attempt:03d}-create", exchange, "POST", f"/v1/agents/{agent}/runs", agent); wave.append((fixture, attempt, report["api"][-1], exchange, [])); normals.append(wave[-1])
            for fixture, attempt, entry, create, polls in wave:
                try: run_id = bind_create(fixture, entry, create, "normal", set()); need(run_id not in run_ids, "run identity is reused"); run_ids.add(run_id)
                except HarnessError: failed = True; continue
                deadline, poll_number = time.monotonic() + poll_timeout, 0
                while True:
                    poll_number += 1; path = f"/v1/runs/{urllib.parse.quote(run_id, safe='')}"; poll = call(opener, url, tenant, key, "GET", path); temp_entry = {"method": "GET", "path": path, "agent_id": fixture["agent_id"], "run_id": run_id}
                    try:
                        result = bind_poll(fixture, temp_entry, poll, run_id); status = result.get("status"); validated = None; contract = artifact = None
                        if status in TERMINAL:
                            api_raw = raw_output(fixture, result, report["guest_image_ref"]); artifact = _final_artifact(result["result"].get("artifacts"), run_id); artifact_raw = fetch_artifact(opener, url, tenant, key, run_id, artifact)
                            try:
                                need(canonical(strict(api_raw, "API raw output")) == canonical(strict(artifact_raw, "artifact output")), "artifact output differs from API output")
                                contract = validate_output(binary, fixture["agent_id"], artifact_raw, binary_sha, staged_binary)
                            finally: del artifact_raw
                            validated = contract["valid"]
                        record_api(report, output, state, f"normal-{fixture['agent_id']}-{attempt:03d}-poll-{poll_number:03d}", poll, "GET", path, fixture["agent_id"], run_id, validated); polls.append((report["api"][-1], poll, contract, artifact))
                    except HarnessError:
                        failed = True; record_api(report, output, state, f"normal-{fixture['agent_id']}-{attempt:03d}-poll-{poll_number:03d}", poll, "GET", path, fixture["agent_id"], run_id); polls.append((report["api"][-1], poll, None, None)); break
                    if status in TERMINAL or time.monotonic() >= deadline: break
                    time.sleep(poll_interval)
        for agent in AGENTS:
            fixture = fixture_map[agent]
            for scenario in ("cancel", "timeout"):
                side_effects = True; create = call(opener, url, tenant, key, "POST", f"/v1/agents/{agent}/runs", request_for(fixture, tenant, scenario, duration if scenario == "timeout" else None)); record_api(report, output, state, f"{scenario}-{agent}-001-create", create, "POST", f"/v1/agents/{agent}/runs", agent)
                try: run_id = bind_create(fixture, report["api"][-1], create, scenario, set()); need(run_id not in run_ids, "run identity is reused"); run_ids.add(run_id)
                except HarnessError: failed = True; continue
                deadline, number, cancelled = time.monotonic() + poll_timeout, 0, False
                while True:
                    number += 1; path = f"/v1/runs/{urllib.parse.quote(run_id, safe='')}"; poll = call(opener, url, tenant, key, "GET", path); record_api(report, output, state, f"{scenario}-{agent}-001-poll-{number:03d}", poll, "GET", path, agent, run_id)
                    try: status = bind_poll(fixture, report["api"][-1], poll, run_id).get("status")
                    except HarnessError: failed = True; break
                    if scenario == "cancel" and status == "running" and not cancelled:
                        action_path = f"/v1/runs/{urllib.parse.quote(run_id, safe='')}/cancel"; action = call(opener, url, tenant, key, "POST", action_path, {"actor": "sas103", "reason": "synthetic lifecycle control"}); record_api(report, output, state, f"{scenario}-{agent}-001-action", action, "POST", action_path, agent, run_id); cancelled = True
                    if status in TERMINAL or time.monotonic() >= deadline: break
                    time.sleep(poll_interval)
        try:
            lifecycle_api, lifecycle_seen = api_index(output, report["api"], output_fd, raw_fd), set()
            for agent in AGENTS:
                for scenario in ("cancel", "timeout"):
                    lifecycle_gate(fixture_map[agent], scenario, lifecycle_api, lifecycle_seen, duration)
                    next(item for item in report["lifecycle"] if item["agent_id"] == agent and item["scenario"] == scenario)["downstream_acknowledged"] = True
        except HarnessError: failed = True
        normal_created, accepted = sum(create["response"]["status"] == 202 for _, _, _, create, _ in normals), 0
        for fixture, attempt, entry, create, polls in normals:
            try:
                run_id = bind_create(fixture, entry, create, "normal", set()); terminal = None; contract = artifact = None
                for poll_entry, poll, observed_contract, observed_artifact in polls:
                    terminal = bind_poll(fixture, poll_entry, poll, run_id)
                    if terminal.get("status") in TERMINAL: contract, artifact = observed_contract, observed_artifact
                raw_output(fixture, terminal, report["guest_image_ref"]); need(contract is not None and artifact is not None, "validator acknowledgement is missing"); record_validator(report, output, state, f"validator-{fixture['agent_id']}-{attempt:03d}", fixture["agent_id"], run_id, binary_sha, contract, artifact, schema_hashes[fixture["agent_id"]]); accepted += 1
            except HarnessError: failed = True
        report["counts"] = {"normal_attempts": len(normals), "normal_created": normal_created, "control_plane_accepted": accepted, "lifecycle_attempts": len(AGENTS) * 2}
        if failed or accepted != len(normals): report["failure"] = "collection_failed"; raise HarnessError("collection failed")
    except BaseException:
        report["failure"] = "cleanup_required" if side_effects else ("controls_unverified" if controls_blocked else "collection_failed")
        raise
    finally:
        try:
            report["api"].sort(key=lambda item: item["relative_path"]); report["validators"].sort(key=lambda item: item["relative_path"]); write_new("sas103-report.json", canonical(report), output_fd)
        finally:
            os.close(raw_fd); os.close(output_fd)
            if staged_binary is not None: os.unlink(staged_binary)
    return output / "sas103-report.json"
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest="command", required=True); manifest = ROOT / "evals" / "sas103-fixtures.json"
    collect_parser = commands.add_parser("collect"); collect_parser.add_argument("--manifest", type=Path, default=manifest); collect_parser.add_argument("--output-dir", type=Path, required=True); collect_parser.add_argument("--base-url"); collect_parser.add_argument("--tenant-id"); collect_parser.add_argument("--runs-per-agent", type=int, default=20); collect_parser.add_argument("--poll-timeout", type=float, default=600.0); collect_parser.add_argument("--poll-interval", type=float, default=0.25); collect_parser.add_argument("--timeout-max-duration", default="1s"); collect_parser.add_argument("--allow-remote", action="store_true"); collect_parser.add_argument("--sasctl-bin", type=Path, help="repository build path only: bin/sasctl"); collect_parser.add_argument("--controls", type=Path, help="blocked until an external signed attestation mechanism is configured")
    verify_parser = commands.add_parser("verify"); verify_parser.add_argument("--manifest", type=Path, default=manifest); verify_parser.add_argument("--report", type=Path, required=True); verify_parser.add_argument("--controls", type=Path, help="blocked until an external signed attestation mechanism is configured"); verify_parser.add_argument("--sasctl-bin", type=Path, help="repository build path only: bin/sasctl")
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            binary = args.sasctl_bin or TRUSTED_SASCTL; report = collect(args.manifest, args.output_dir, args.base_url or os.environ.get("SAS_BASE_URL", "http://127.0.0.1:8080"), args.tenant_id or os.environ.get("SAS_TENANT_ID", "sas103-synthetic"), args.runs_per_agent, args.poll_timeout, args.poll_interval, args.timeout_max_duration, args.allow_remote, binary, args.controls); print(f"SAS-103 raw index written: {report}")
        else: print(f"SAS-103 report structure verified: {verify_report(args.report, args.manifest, args.controls, args.sasctl_bin)['control_plane_accepted']} control-plane runs")
        return 0
    except HarnessError as error: print(f"sas103 acceptance: {error}", file=sys.stderr); return 1
if __name__ == "__main__": raise SystemExit(main())
