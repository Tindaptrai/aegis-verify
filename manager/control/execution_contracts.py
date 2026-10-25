"""Closed, immutable execution v2 contracts. Never used to interpret legacy bytes."""
from dataclasses import asdict, dataclass, fields, is_dataclass
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import math
import re
import types
import typing
import uuid

PROTOCOL = 'aegis-windows-execution/2'
KEY_ID = 'manager-execution-v2'
PROVIDER_ID = 'reviewed-scn001-windows/1'
REQUEST_LIMIT = 65536
ENVELOPE_LIMIT = 98304
JOB_RESPONSE_LIMIT = 4 * 1024 * 1024
LOCAL_CODES = frozenset(('profile_mismatch', 'artifact_mismatch', 'clock_uncertain', 'local_not_ready', 'unsupported_platform'))
BLOCKING_CODES = LOCAL_CODES | frozenset(('upgrade_required', 'binding_missing', 'binding_disabled', 'identity_unavailable',
    'environment_invalid', 'mapping_missing', 'ownership_conflict', 'local_stale', 'worker_unavailable',
    'source_unavailable', 'busy', 'reconciliation_required'))
ERRORS = dict(invalid_request=400, identity_denied=403, job_not_found=404, lease_conflict=409,
    start_conflict=409, receipt_conflict=409, temporarily_unavailable=503,
    preview_conflict=409, job_conflict=409, binding_conflict=409, execution_unavailable=503)


@dataclass(frozen=True)
class ErrorCode:
    code: str


@dataclass(frozen=True)
class ErrorResponse:
    error: ErrorCode


class ExecutionError(ValueError):
    def __init__(self, code):
        if code not in ERRORS: raise ValueError('invalid_request')
        self.code, self.status = code, ERRORS[code]
        self.response = ErrorResponse(ErrorCode(code))
        super().__init__(code)


class FrozenReportMap(dict):
    """Opaque existing canonical report JSON; never interpreted as execution authority."""
    def __init__(self, value):
        def freeze(item):
            if type(item) is dict: return FrozenReportMap(item)
            if type(item) is list: return tuple(freeze(v) for v in item)
            return item
        dict.__init__(self, ((key, freeze(item)) for key, item in dict(value).items()))
    def _immutable(self, *args, **kwargs): raise TypeError('Report JSON is immutable')
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _immutable
    def __deepcopy__(self, memo): return self


@dataclass(frozen=True)
class IdentityFields:
    protocol: str
    device_id: str
    generation: int


@dataclass(frozen=True)
class BindingFields:
    binding_id: str
    binding_revision: int


@dataclass(frozen=True)
class PollRequest(IdentityFields, BindingFields):
    pass


@dataclass(frozen=True)
class ReadinessRequest(PollRequest):
    installation_profile_sha256: str
    artifact_set_sha256: str
    ready: bool
    blocking_codes: tuple[str, ...]


@dataclass(frozen=True)
class ReadinessAck:
    protocol: str
    server_time: str
    accepted: bool


@dataclass(frozen=True)
class Envelope:
    protocol: str
    key_id: str
    payload: str
    signature: str


@dataclass(frozen=True)
class Parameters:
    run_label: str
    rule_revision: str
    rule_sha256: str


@dataclass(frozen=True)
class ArtifactPins:
    scenario_sha256: str
    profile_sha256: str
    runner_sha256: str
    kit_sha256: str
    payload_sha256: str


@dataclass(frozen=True)
class RulePins:
    baseline: str
    behavioral: str


@dataclass(frozen=True)
class SignedJob(IdentityFields, BindingFields, ArtifactPins):
    job_id: str
    run_id: str
    certificate_sha256: str
    approval_id: str
    environment_id: str
    release_id: int
    approval_snapshot_sha256: str
    scenario_id: str
    runner_id: str
    runner_version: str
    not_before: str
    expires_at: str
    collection_start: str
    collection_end: str
    timeout_seconds: int
    parameters: Parameters


@dataclass(frozen=True)
class StartRequest(PollRequest):
    start_request_id: str
    job_sha256: str


@dataclass(frozen=True)
class StartAck:
    protocol: str
    job_id: str
    start_request_id: str
    job_sha256: str
    authorized: bool


@dataclass(frozen=True)
class Receipt(PollRequest):
    receipt_id: str
    job_id: str
    job_sha256: str
    state: str
    started_at: str | None
    finished_at: str
    exit_code: int | None
    cleanup_succeeded: bool


@dataclass(frozen=True)
class ReceiptAck:
    protocol: str
    job_id: str
    receipt_id: str
    job_sha256: str
    accepted: bool


@dataclass(frozen=True)
class BindingInput:
    expected_revision: int | None
    enabled: bool
    provider_id: str
    runner_release_id: int
    installation_profile_sha256: str
    wazuh_connection_id: str
    wazuh_connection_revision: int
    wazuh_agent_id: str


@dataclass(frozen=True)
class PreviewInput:
    device_id: str
    provider_id: str
    binding_revision: int
    run_label: str
    rule_revision: str


@dataclass(frozen=True)
class ApproveInput:
    preview_id: str
    preview_sha256: str
    idempotency_key: str


@dataclass(frozen=True)
class SnapshotIdentity:
    device_id: str
    generation: int
    certificate_sha256: str
    environment_id: str


@dataclass(frozen=True)
class SnapshotBinding(BindingFields):
    provider_id: str
    installation_profile_sha256: str
    artifact_set_sha256: str
    ownership_revision: int


@dataclass(frozen=True)
class EvaluationBinding:
    name: str
    value: str | int | tuple[str, ...] | tuple[int, ...]


@dataclass(frozen=True)
class ReleaseDefinition:
    release_id: int
    scenario_id: str
    runner_id: str
    runner_version: str
    artifact_pins: ArtifactPins
    rule_pins: RulePins
    allow_rehearsal: bool
    timeout_seconds: int
    evaluation_bindings: tuple[EvaluationBinding, ...]
    scenario_path: str
    profile_path: str


@dataclass(frozen=True)
class SnapshotRelease(ReleaseDefinition):
    release_sha256: str
    parameters: Parameters


@dataclass(frozen=True)
class ExecutionWindows:
    not_before: str
    expires_at: str
    collection_start: str
    collection_end: str


@dataclass(frozen=True)
class SnapshotConnection:
    connection_id: str
    revision: int
    config_path: str
    config_sha256: str
    output_root_fingerprint: str
    wazuh_agent_id: str


@dataclass(frozen=True)
class JobApprovalSnapshotData:
    schema_version: int
    identity: SnapshotIdentity
    binding: SnapshotBinding
    release: SnapshotRelease
    windows: ExecutionWindows
    connection: SnapshotConnection


@dataclass(frozen=True)
class InstallationProfile:
    schema_version: int
    provider_id: str
    environment_id: str
    expected_computer_name: str
    scenario_path: str
    profile_path: str
    runner_path: str
    kit_directory: str
    run_directory: str
    study_path: str
    study_sha256: str
    artifact_pins: ArtifactPins
    rule_pins: RulePins
    allow_rehearsal: bool
    timeout_seconds: int


@dataclass(frozen=True)
class InstalledGrant:
    schema_version: int
    device_id: str
    generation: int
    certificate_sha256: str
    binding_id: str
    binding_revision: int
    installation_profile_sha256: str
    artifact_set_sha256: str


@dataclass(frozen=True)
class ExecutionDeviceDTO:
    device_id: str
    provider_id: str | None
    binding_id: str | None
    binding_revision: int | None
    capability: str
    ready: bool
    blocking_codes: tuple[str, ...]
    checked_at: str | None
    readiness_expires_at: str | None
    release_id: int | None
    release_sha256: str | None
    wazuh_connection_id: str | None
    wazuh_agent_id: str | None


@dataclass(frozen=True)
class PublicSummary:
    device_id: str
    environment_id: str
    wazuh_connection_id: str
    wazuh_agent_id: str
    provider_id: str
    binding_id: str
    binding_revision: int
    release_id: int
    release_sha256: str
    scenario_id: str
    runner_id: str
    runner_version: str
    parameters: Parameters
    timeout_seconds: int
    not_before: str
    expires_at: str
    collection_start: str
    collection_end: str
    artifact_pins: ArtifactPins
    rule_pins: RulePins
    cleanup_policy: str
    execution_receipt_is_detection_evidence: bool
    run_binding: str
    collection_assurance: str


@dataclass(frozen=True)
class PreviewDTO:
    preview_id: str
    preview_sha256: str
    expires_at: str
    summary: PublicSummary


@dataclass(frozen=True)
class JobDTO:
    job_id: str
    summary: PublicSummary
    execution_state: str
    collection_state: str
    evaluation_state: str
    created_at: str
    started_authorized_at: str | None
    finished_at: str | None
    error_code: str | None
    report: FrozenReportMap | None


@dataclass(frozen=True)
class ProviderDTO:
    provider_id: str
    scenario_id: str
    runner_id: str
    runner_version: str
    release_id: int
    release_sha256: str
    allow_rehearsal: bool
    timeout_seconds: int


@dataclass(frozen=True)
class ProviderList:
    providers: tuple[ProviderDTO, ...]


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('invalid_request')
        value[key] = item
    return value


def _invalid_constant(_):
    raise ValueError('invalid_request')


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number): raise ValueError('invalid_request')
    return number


def load_json(raw: bytes, limit=REQUEST_LIMIT):
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError('invalid_request')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_invalid_constant, parse_float=_finite_float)
        def depth(item, level=1):
            if isinstance(item, (dict, list)):
                if level > 12: raise ValueError('invalid_request')
                for child in (item.values() if isinstance(item, dict) else item): depth(child, level + 1)
        depth(value)
        return value
    except (UnicodeError, RecursionError, TypeError, json.JSONDecodeError):
        raise ValueError('invalid_request') from None


def canonical_bytes(value):
    return json.dumps(asdict(value) if is_dataclass(value) else value,
                      sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('utf-8')


def timestamp(value):
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value):
        raise ValueError('invalid_request')
    try: return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError: raise ValueError('invalid_request') from None


def canonical_base64(value):
    try:
        decoded = base64.b64decode(value, validate=True)
        if not decoded or base64.b64encode(decoded).decode('ascii') != value: raise ValueError
        return decoded
    except (ValueError, TypeError): raise ValueError('invalid_request') from None


def _field(name, value):
    if value is None: return
    if isinstance(value, str) and not value and name not in ('value', 'error_code'): raise ValueError('invalid_request')
    if name.endswith('_sha256') or name in ('baseline', 'behavioral', 'output_root_fingerprint'):
        if not re.fullmatch('[0-9a-f]{64}', value): raise ValueError('invalid_request')
    if name in ('device_id', 'binding_id', 'job_id', 'run_id', 'approval_id', 'receipt_id', 'start_request_id',
                'preview_id', 'idempotency_key', 'connection_id', 'wazuh_connection_id'):
        if str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0: raise ValueError('invalid_request')
    if name in ('generation', 'binding_revision', 'revision', 'expected_revision', 'ownership_revision', 'wazuh_connection_revision'):
        if not 1 <= value <= 2147483647: raise ValueError('invalid_request')
    if name in ('release_id', 'runner_release_id') and not 1 <= value <= 9223372036854775807: raise ValueError('invalid_request')
    if name in ('not_before', 'expires_at', 'collection_start', 'collection_end', 'server_time', 'started_at', 'finished_at',
                'checked_at', 'readiness_expires_at', 'created_at', 'started_authorized_at'): timestamp(value)
    constants = dict(protocol=PROTOCOL, key_id=KEY_ID, provider_id=PROVIDER_ID, scenario_id='SCN-001',
                     runner_id='scn001-safe-demo', runner_version='0.3.0', schema_version=1, cleanup_policy='bounded_process_tree',
                     run_binding='unknown', collection_assurance='unknown')
    if name in constants and value != constants[name]: raise ValueError('invalid_request')
    if name == 'environment_id' and not re.fullmatch('[A-Za-z0-9_-]{1,64}', value): raise ValueError('invalid_request')
    if name == 'timeout_seconds' and not 180 <= value <= 300: raise ValueError('invalid_request')
    if name == 'exit_code' and not -2147483648 <= value <= 2147483647: raise ValueError('invalid_request')
    if name in ('accepted', 'authorized') and value is not True: raise ValueError('invalid_request')
    if name == 'execution_receipt_is_detection_evidence' and value is not False: raise ValueError('invalid_request')
    if name == 'capability' and value not in ('installed_supported', 'upgrade_required', 'unsupported'): raise ValueError('invalid_request')
    if name == 'evaluation_state' and value not in ('not_evaluated', 'evaluated'): raise ValueError('invalid_request')
    if name == 'collection_state' and value not in ('pending', 'collecting', 'evaluated', 'empty', 'failed', 'reconciled'): raise ValueError('invalid_request')
    if name == 'execution_state' and value not in ('draft', 'queued', 'leased', 'started', 'succeeded', 'failed', 'execution_unknown', 'cancelled', 'expired'): raise ValueError('invalid_request')
    if name == 'code' and value not in ERRORS: raise ValueError('invalid_request')
    if name == 'run_label' and value not in ('A', 'B', 'C', 'Rehearsal'): raise ValueError('invalid_request')
    if name == 'rule_revision' and value not in ('baseline', 'behavioral'): raise ValueError('invalid_request')
    if name == 'wazuh_agent_id' and not re.fullmatch('[0-9]{1,64}', value): raise ValueError('invalid_request')
    if name in ('payload', 'signature'): canonical_base64(value)


def _convert(cls, data):
    if cls is FrozenReportMap:
        if type(data) is not dict: raise ValueError('invalid_request')
        return FrozenReportMap(data)
    origin = typing.get_origin(cls)
    if origin in (typing.Union, types.UnionType):
        if data is None and type(None) in typing.get_args(cls): return None
        for branch in typing.get_args(cls):
            if branch is type(None): continue
            try: return _convert(branch, data)
            except ValueError: pass
        raise ValueError('invalid_request')
    if origin is tuple:
        if type(data) not in (list, tuple): raise ValueError('invalid_request')
        return tuple(_convert(typing.get_args(cls)[0], value) for value in data)
    if is_dataclass(cls):
        if type(data) is not dict or set(data) != {f.name for f in fields(cls)}: raise ValueError('invalid_request')
        converted = {f.name: _convert(f.type, data[f.name]) for f in fields(cls)}
        for name, value in converted.items(): _field(name, value)
        result = cls(**converted)
        _validate(result)
        return result
    if type(data) is not cls: raise ValueError('invalid_request')
    if cls is str and len(data) > REQUEST_LIMIT: raise ValueError('invalid_request')
    return data


def _validate(value):
    if isinstance(value, EvaluationBinding):
        # Use the existing engine contract rather than narrowing its scalar/list semantics.
        from aegis_verify.validation.contracts import Binding
        Binding.model_validate(asdict(value))
    if isinstance(value, (Parameters, PreviewInput)):
        if value.run_label in ('A', 'B') and value.rule_revision != 'baseline' or value.run_label == 'C' and value.rule_revision != 'behavioral':
            raise ValueError('invalid_request')
    if isinstance(value, ReleaseDefinition):
        names = [item.name for item in value.evaluation_bindings]
        if len(names) != len(set(names)) or len(names) > 64: raise ValueError('invalid_request')
    if isinstance(value, SnapshotRelease):
        if value.parameters.run_label == 'Rehearsal' and not value.allow_rehearsal: raise ValueError('invalid_request')
        if value.parameters.rule_sha256 != getattr(value.rule_pins, value.parameters.rule_revision): raise ValueError('invalid_request')
        definition = _convert(ReleaseDefinition, {k: v for k, v in asdict(value).items() if k not in ('parameters', 'release_sha256')})
        if value.release_sha256 != hashlib.sha256(canonical_bytes(definition)).hexdigest(): raise ValueError('invalid_request')
    if isinstance(value, (ReadinessRequest, ExecutionDeviceDTO)):
        allowed = LOCAL_CODES if isinstance(value, ReadinessRequest) else BLOCKING_CODES
        codes = value.blocking_codes
        if len(codes) > 8 or len(codes) != len(set(codes)) or set(codes) - allowed or value.ready and codes: raise ValueError('invalid_request')
    if isinstance(value, SignedJob) and value.run_id != value.job_id: raise ValueError('invalid_request')
    if isinstance(value, JobApprovalSnapshotData):
        if timestamp(value.windows.collection_end) < timestamp(value.windows.expires_at) + timedelta(seconds=value.release.timeout_seconds):
            raise ValueError('invalid_request')
    if isinstance(value, (SignedJob, ExecutionWindows, PublicSummary)):
        start, end, cstart, cend = map(timestamp, (value.not_before, value.expires_at, value.collection_start, value.collection_end))
        if not cstart <= start < end <= cend or (end - start).total_seconds() > 120 or (cend - cstart).total_seconds() > 900: raise ValueError('invalid_request')
        if isinstance(value, (SignedJob, PublicSummary)) and cend < end + timedelta(seconds=value.timeout_seconds): raise ValueError('invalid_request')
    if isinstance(value, Receipt):
        if value.state not in ('succeeded', 'failed', 'execution_unknown'): raise ValueError('invalid_request')
        if value.started_at is not None and timestamp(value.started_at) > timestamp(value.finished_at): raise ValueError('invalid_request')
        if value.state == 'succeeded' and (value.started_at is None or value.exit_code != 0 or not value.cleanup_succeeded): raise ValueError('invalid_request')
        if value.state == 'failed' and value.started_at is None: raise ValueError('invalid_request')


CONTRACTS = {cls.__name__: cls for cls in tuple(globals().values()) if isinstance(cls, type) and is_dataclass(cls)}


def decode_contract(kind: str, raw: bytes):
    limit = JOB_RESPONSE_LIMIT if kind == 'JobDTO' else ENVELOPE_LIMIT if kind == 'Envelope' else REQUEST_LIMIT
    try: return _convert(CONTRACTS[kind], load_json(raw, limit))
    except (KeyError, TypeError, AttributeError, ValueError): raise ValueError('invalid_request') from None


def parse_execution_request(kind: str, raw: bytes):
    kinds = dict(readiness='ReadinessRequest', poll='PollRequest', start='StartRequest', receipt='Receipt',
                 binding='BindingInput', preview='PreviewInput', approve='ApproveInput')
    if kind not in kinds: raise ValueError('invalid_request')
    return decode_contract(kinds[kind], raw)


def snapshot_bytes(snapshot: JobApprovalSnapshotData) -> bytes:
    if type(snapshot) is not JobApprovalSnapshotData: raise ValueError('invalid_request')
    raw = canonical_bytes(snapshot)
    decode_contract('JobApprovalSnapshotData', raw)
    return raw


def release_definition_bytes(definition: ReleaseDefinition) -> bytes:
    if type(definition) is not ReleaseDefinition: raise ValueError('invalid_request')
    raw = canonical_bytes(definition)
    decode_contract('ReleaseDefinition', raw)
    return raw


def freeze_release(definition: ReleaseDefinition, parameters: Parameters) -> SnapshotRelease:
    digest = hashlib.sha256(release_definition_bytes(definition)).hexdigest()
    if type(parameters) is not Parameters: raise ValueError('invalid_request')
    return decode_contract('SnapshotRelease', canonical_bytes(asdict(definition) |
        dict(release_sha256=digest, parameters=asdict(parameters))))


def public_summary(snapshot: JobApprovalSnapshotData) -> PublicSummary:
    snapshot_bytes(snapshot)
    i, b, r, w, c = snapshot.identity, snapshot.binding, snapshot.release, snapshot.windows, snapshot.connection
    return PublicSummary(i.device_id, i.environment_id, c.connection_id, c.wazuh_agent_id, b.provider_id,
        b.binding_id, b.binding_revision, r.release_id, r.release_sha256, r.scenario_id, r.runner_id, r.runner_version,
        r.parameters, r.timeout_seconds, w.not_before, w.expires_at, w.collection_start, w.collection_end,
        r.artifact_pins, r.rule_pins, 'bounded_process_tree', False, 'unknown', 'unknown')
