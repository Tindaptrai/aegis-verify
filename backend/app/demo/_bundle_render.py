"""Reconstruct expected transport bytes, never infer collection assurance."""

from dataclasses import asdict
from hashlib import sha256
import json

from ..connectors.wazuh.manager_snapshot import parse_manager_snapshots
from ..intake import decode_config, parse_manifest
from ..intake.errors import IntakeError
from ..models import PreciseTimestamp
from ..validation import EvaluationContext, EvaluationProfile


def digest(raw):
    return sha256(raw).hexdigest()


def config_bytes(value):
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                     allow_nan=False).encode('utf-8')
    decode_config(raw, stage='inputs')  # Also bounds generated ledger/config.
    return raw


def render(snapshots, scope, profile, context):
    result = parse_manager_snapshots(snapshots, scope=scope)
    EvaluationProfile.model_validate(decode_config(profile, stage='profile'))
    ctx = EvaluationContext.model_validate(decode_config(context, stage='context'))
    if (ctx.declarations or ctx.environment_id != scope.environment_id
            or ctx.start != PreciseTimestamp.parse(scope.start)
            or ctx.end != PreciseTimestamp.parse(scope.end)):
        raise IntakeError('invalid_context')
    payload = {'profile.json': profile, 'context.json': context}
    snapshot_descriptors = []
    for item in snapshots:
        path = 'snapshots/' + item.sha256 + '.jsonl'
        payload[path] = item.raw
        snapshot_descriptors.append({'source_label': item.source_label, 'sha256': item.sha256, 'path': path})
    entries = []
    paths = {}
    for doc in result.documents:
        path = 'documents/' + digest(doc.source_ref.encode('utf-8')) + '.json'
        paths[doc.source_ref] = path
        payload[path] = doc.raw
        entries.append({'path': path, 'source_ref': doc.source_ref, 'sha256': digest(doc.raw),
                        'parser': doc.parser, 'context': {
                            'ingested_at': scope.ingested_at, 'collection_mode': 'direct'}})
    manifest = {'bundle_schema_version': '0.1.0', 'environment_id': scope.environment_id, 'files': entries}
    parse_manifest(manifest)
    payload['inputs.json'] = config_bytes(manifest)
    rows = []
    for row in result.ledger:
        rows.append(asdict(row) | {'document_path': paths.get(row.document_source_ref)})
    payload['ledger.json'] = config_bytes({'version': '0.1.0', 'lines': rows})
    completion = config_bytes({
        'kind': 'snapshot_transport_unknown', 'version': '0.1.0', 'scope': asdict(scope),
        'snapshots': snapshot_descriptors,
        'files': {name: digest(raw) for name, raw in payload.items()},
    })
    return payload, completion, result
