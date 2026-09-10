#!/usr/bin/env python3
"""Offline #71 fixture integrity checks; not the #72 submission validator."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('nonstandard JSON number: ' + value)


def check_schema(value, schema):
    # Only the keywords used by this one fixture schema; fail on schema expansion.
    supported = {'$schema', '$id', 'title', 'type', 'const', 'required',
                 'additionalProperties', 'properties', 'items', 'maxItems',
                 'minLength', 'maxLength', 'pattern'}
    assert not schema.keys() - supported, 'unsupported fixture schema keyword'
    if 'const' in schema and (type(value) is not type(schema['const']) or value != schema['const']):
        raise ValueError('constant mismatch')
    kind = schema.get('type')
    types = {'object': dict, 'array': list, 'string': str}
    if kind and type(value) is not types[kind]:
        raise ValueError('type mismatch')
    if kind == 'object':
        properties = schema['properties']
        if not set(schema['required']) <= value.keys() or value.keys() - properties.keys():
            raise ValueError('missing or unknown field')
        assert schema['additionalProperties'] is False
        for key, child in value.items():
            check_schema(child, properties[key])
    if kind == 'array':
        if len(value) > schema['maxItems']:
            raise ValueError('too many items')
        for child in value:
            check_schema(child, schema['items'])
    if kind == 'string':
        value.encode('utf-8')  # Reject unpaired escaped surrogates.
        if not schema['minLength'] <= len(value) <= schema['maxLength']:
            raise ValueError('string length')
        if 'pattern' in schema and not re.fullmatch(schema['pattern'], value):
            raise ValueError('string pattern')


def verify():
    directory = ROOT / 'evals/input-preparation-v1'
    manifest = json.loads((directory / 'manifest.json').read_text())
    schema_bytes = (directory / manifest['schema_path']).read_bytes()
    assert hashlib.sha256(schema_bytes).hexdigest() == manifest['schema_sha256'], 'schema drift'
    schema = json.loads(schema_bytes)
    assert manifest['version'] == 'sas.input-fixtures/v1'
    assert manifest['spec_version'] == 2
    assert manifest['source']['real_data'] is False
    seen = set()
    for fixture in manifest['fixtures']:
        assert fixture['id'] not in seen, 'duplicate fixture id'
        seen.add(fixture['id'])
        raw = (directory / fixture['path']).read_bytes()
        frozen = fixture['input_manifest']
        assert hashlib.sha256(raw).hexdigest() == frozen['sha256'], fixture['id'] + ': digest drift'
        assert len(raw) == frozen['size_bytes'] and 0 < len(raw) <= 1 << 20
        assert frozen['schema'] == 'sas.synthetic-alert/v1'
        assert frozen['media_type'] == 'application/json'
        outcome, count = 'accepted', None
        try:
            value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                               parse_constant=reject_constant)
        except ValueError:
            outcome = 'invalid_json'
        else:
            try:
                check_schema(value, schema)
            except ValueError:
                outcome = 'invalid_schema'
            else:
                count = len(value['observations'])
        expected = fixture['expected']
        assert outcome == expected['validation'], fixture['id'] + ': outcome drift'
        assert count == expected['observation_count'], fixture['id'] + ': count drift'
        assert expected['security_verdict'] is None, 'fixtures cannot establish a security verdict'
        assert expected['submit_http_status'] == (202 if outcome == 'accepted' else 400)
        assert expected['error_code'] == (None if outcome == 'accepted' else 'invalid_request')
    assert seen == {'normal', 'empty-observations', 'prompt-injection', 'damaged',
                    'duplicate-key', 'trailing-data', 'invalid-utf8',
                    'nonstandard-number', 'unknown-version', 'non-synthetic'}
    print(f'verified {len(seen)} input fixtures (offline bytes/schema only; no API or executor run)')


if __name__ == '__main__':
    verify()
