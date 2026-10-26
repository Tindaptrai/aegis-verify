"""Synthetic protocol vectors: mutations must fail at the actual trust boundary."""
import base64
from dataclasses import FrozenInstanceError, asdict
import hashlib
import json
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.test import SimpleTestCase, override_settings

PROTOCOL = 'aegis-windows-execution/2'
UUID = 'a1111111-1111-4111-8111-111111111111'
DIGEST = 'a' * 64
PINS = {k + '_sha256': DIGEST for k in ('scenario', 'profile', 'runner', 'kit', 'payload')}
RULES = dict(baseline='b' * 64, behavioral='c' * 64)
PARAMETERS = dict(run_label='A', rule_revision='baseline', rule_sha256=RULES['baseline'])
WINDOWS = dict(not_before='2026-10-25T12:00:00Z', expires_at='2026-10-25T12:02:00Z',
               collection_start='2026-10-25T11:59:30Z', collection_end='2026-10-25T12:05:00Z')


def raw(value):
    return json.dumps(value, separators=(',', ':')).encode()


def job_data():
    return dict(protocol=PROTOCOL, job_id=UUID, run_id=UUID, device_id=UUID,
        certificate_sha256=DIGEST, approval_id=UUID, environment_id='synthetic-env', generation=1,
        binding_id=UUID, binding_revision=1, release_id=1, approval_snapshot_sha256=DIGEST,
        scenario_id='SCN-001', runner_id='scn001-safe-demo', runner_version='0.3.0',
        **PINS, **WINDOWS, timeout_seconds=180, parameters=PARAMETERS.copy())


def snapshot_data():
    release = dict(release_id=1, scenario_id='SCN-001', runner_id='scn001-safe-demo',
        runner_version='0.3.0', artifact_pins=PINS, rule_pins=RULES,
        allow_rehearsal=False, timeout_seconds=180, evaluation_bindings=[dict(name='host', value='synthetic-host')],
        scenario_path='private/scenario.yaml', profile_path='private/profile.json')
    digest = hashlib.sha256(json.dumps(release, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    return dict(schema_version=1,
        identity=dict(device_id=UUID, generation=1, certificate_sha256=DIGEST, environment_id='synthetic-env'),
        binding=dict(binding_id=UUID, binding_revision=1, provider_id='reviewed-scn001-windows/1',
                     installation_profile_sha256=DIGEST, artifact_set_sha256=DIGEST, ownership_revision=1),
        release=release | dict(release_sha256=digest, parameters=PARAMETERS),
        windows=WINDOWS, connection=dict(connection_id=UUID, revision=1, config_path='private/config.json',
            config_sha256=DIGEST, output_root_fingerprint=DIGEST, wazuh_agent_id='901'))


class ExecutionContractTests(SimpleTestCase):
    def test_current_job_framing_preserves_existing_job_depth_and_byte_bounds(self):
        from control.execution_contracts import decode_contract, public_summary, canonical_bytes
        snapshot = decode_contract('JobApprovalSnapshotData', raw(snapshot_data()))
        nested = []
        for _ in range(9): nested = [nested]
        data = dict(job_id=UUID, admission_blocked=False, summary=asdict(public_summary(snapshot)), execution_state='succeeded',
            collection_state='evaluated', evaluation_state='evaluated', created_at=WINDOWS['not_before'],
            started_authorized_at=None, finished_at=None, error_code=None, report={'nested': nested})
        job = decode_contract('JobDTO', raw(data))
        current = decode_contract('CurrentJobDTO', b'{"job":' + raw(data) + b'}')
        self.assertEqual(current.job, job)
        data['report'] = {'padding': ''}
        data['report']['padding'] = 'x' * (4194304 - len(canonical_bytes(data)))
        encoded = canonical_bytes(data)
        self.assertEqual(len(encoded), 4194304)
        self.assertEqual(decode_contract('CurrentJobDTO', b'{"job":' + encoded + b'}').job, decode_contract('JobDTO', encoded))
        with self.assertRaises(ValueError): decode_contract('CurrentJobDTO', b'{"job":' + encoded + b' }')
        data['report'] = {'nested': [nested]}
        with self.assertRaises(ValueError): decode_contract('CurrentJobDTO', raw({'job': data}))
        with self.assertRaises(ValueError): decode_contract('CurrentJobDTO', raw({'job': None, 'key': UUID}))

    def test_human_job_report_has_separate_4mib_limit_without_widening_requests(self):
        from control.execution_contracts import decode_contract, public_summary, canonical_bytes, parse_execution_request
        snapshot=decode_contract('JobApprovalSnapshotData',raw(snapshot_data()))
        data=dict(job_id=UUID,admission_blocked=True,summary=asdict(public_summary(snapshot)),execution_state='succeeded',
            collection_state='evaluated',evaluation_state='evaluated',created_at=WINDOWS['not_before'],
            started_authorized_at=None,finished_at=None,error_code=None,
            report={'synthetic_transport_padding':'x'*131072})
        encoded=raw(data)
        parsed=decode_contract('JobDTO',encoded)
        self.assertEqual(json.loads(canonical_bytes(parsed)),data)
        at_limit=encoded+b' '*(4194304-len(encoded))
        self.assertEqual(decode_contract('JobDTO',at_limit),parsed)
        with self.assertRaises(ValueError): decode_contract('JobDTO',at_limit+b' ')
        request=raw(dict(preview_id=UUID,preview_sha256=DIGEST,idempotency_key=UUID))
        with self.assertRaises(ValueError): parse_execution_request('approve',request+b' '*(65537-len(request)))
        with self.assertRaises(ValueError): decode_contract('SignedJob',raw(job_data())+b' '*65536)

    def test_snapshot_collection_window_covers_release_timeout_before_freeze_or_projection(self):
        from dataclasses import replace
        from control.execution_contracts import decode_contract, snapshot_bytes, public_summary, canonical_bytes
        # Expiry12:02 + reviewed timeout180s requires exactly12:05 or later.
        valid = decode_contract('JobApprovalSnapshotData', raw(snapshot_data()))
        snapshot_bytes(valid)
        summary = public_summary(valid)
        self.assertEqual(summary.collection_end, '2026-10-25T12:05:00Z')
        self.assertEqual(decode_contract('PublicSummary', canonical_bytes(summary)), summary)
        data = snapshot_data(); data['windows'] = data['windows'] | {'collection_end': '2026-10-25T12:04:59Z'}
        with self.assertRaises(ValueError): decode_contract('JobApprovalSnapshotData', raw(data))
        invalid = replace(valid, windows=replace(valid.windows, collection_end='2026-10-25T12:04:59Z'))
        with self.assertRaises(ValueError): snapshot_bytes(invalid)
        with self.assertRaises(ValueError): public_summary(invalid)

    def test_release_definition_has_no_self_reference_or_job_parameters(self):
        from control.execution_contracts import decode_contract, release_definition_bytes, freeze_release, snapshot_bytes, canonical_bytes
        data = snapshot_data()
        definition = {k: v for k, v in data['release'].items() if k not in ('parameters', 'release_sha256')}
        frozen = decode_contract('ReleaseDefinition', raw(definition))
        definition_bytes = release_definition_bytes(frozen)
        self.assertNotIn(b'parameters', definition_bytes)
        self.assertNotIn(b'release_sha256', definition_bytes)
        digest = hashlib.sha256(definition_bytes).hexdigest()
        snapshots, jobs = set(), set()
        for label, revision in (('A', 'baseline'), ('B', 'baseline'), ('C', 'behavioral')):
            parameters = decode_contract('Parameters', raw(dict(run_label=label, rule_revision=revision, rule_sha256=RULES[revision])))
            release = freeze_release(frozen, parameters)
            self.assertEqual(release.release_sha256, digest)
            snapshot = decode_contract('JobApprovalSnapshotData', raw(data | {'release': asdict(release)}))
            snapshot_hash = hashlib.sha256(snapshot_bytes(snapshot)).hexdigest(); snapshots.add(snapshot_hash)
            job = decode_contract('SignedJob', raw(job_data() | {'approval_snapshot_sha256': snapshot_hash, 'parameters': asdict(parameters)}))
            jobs.add(hashlib.sha256(canonical_bytes(job)).hexdigest())
        self.assertEqual(len(snapshots), 3)
        self.assertEqual(len(jobs), 3)

    def test_size_depth_and_machine_errors_are_bounded(self):
        from control.execution_contracts import load_json, parse_execution_request, ExecutionError, canonical_bytes
        poll = raw(dict(protocol=PROTOCOL, device_id=UUID, generation=1, binding_id=UUID, binding_revision=1))
        self.assertEqual(parse_execution_request('poll', poll + b' ' * (65536 - len(poll))).generation, 1)
        with self.assertRaises(ValueError): parse_execution_request('poll', poll + b' ' * (65537 - len(poll)))
        self.assertEqual(canonical_bytes(ExecutionError('start_conflict').response), b'{"error":{"code":"start_conflict"}}')
        self.assertEqual(ExecutionError('start_conflict').status, 409)
        with self.assertRaises(ValueError): ExecutionError('unreviewed_exception_text')
        nested = 0
        for _ in range(12): nested = {'nested': nested}
        load_json(raw(nested))
        with self.assertRaises(ValueError): load_json(raw({'nested': nested}))

    def test_every_wire_key_is_required_and_unknown_keys_rejected(self):
        from control.execution_contracts import decode_contract
        identity = dict(protocol=PROTOCOL, device_id=UUID, generation=1, binding_id=UUID, binding_revision=1)
        cases = dict(PollRequest=identity, SignedJob=job_data(), JobApprovalSnapshotData=snapshot_data(),
            StartRequest=identity | dict(start_request_id=UUID, job_sha256=DIGEST),
            StartAck=dict(protocol=PROTOCOL, job_id=UUID, start_request_id=UUID, job_sha256=DIGEST, authorized=True),
            ReadinessAck=dict(protocol=PROTOCOL, server_time=WINDOWS['not_before'], accepted=True),
            ReceiptAck=dict(protocol=PROTOCOL, job_id=UUID, receipt_id=UUID, job_sha256=DIGEST, accepted=True),
            BindingInput=dict(expected_revision=None, enabled=True, provider_id='reviewed-scn001-windows/1',
                runner_release_id=1, installation_profile_sha256=DIGEST, wazuh_connection_id=UUID,
                wazuh_connection_revision=1, wazuh_agent_id='901'),
            PreviewInput=dict(device_id=UUID, provider_id='reviewed-scn001-windows/1', binding_revision=1, run_label='A', rule_revision='baseline'),
            ApproveInput=dict(preview_id=UUID, preview_sha256=DIGEST, idempotency_key=UUID))
        for kind, value in cases.items():
            decode_contract(kind, raw(value))
            for key in value:
                with self.subTest(kind=kind, missing=key), self.assertRaises(ValueError):
                    decode_contract(kind, raw({k: v for k, v in value.items() if k != key}))
            with self.subTest(kind=kind, unknown=True), self.assertRaises(ValueError): decode_contract(kind, raw(value | {'unknown': None}))

    def test_report_remains_json_and_deeply_immutable(self):
        from control.execution_contracts import decode_contract, public_summary, canonical_bytes
        snapshot = decode_contract('JobApprovalSnapshotData', raw(snapshot_data()))
        data = dict(job_id=UUID,admission_blocked=True, summary=asdict(public_summary(snapshot)), execution_state='succeeded',
            collection_state='evaluated', evaluation_state='evaluated', created_at=WINDOWS['not_before'],
            started_authorized_at=None, finished_at=None, error_code=None, report={'evaluation': {'evidence_ids': ['synthetic-evidence']}})
        parsed = decode_contract('JobDTO', raw(data))
        with self.assertRaises(TypeError): parsed.report['evaluation']['evidence_ids'] = []
        self.assertEqual(json.loads(canonical_bytes(parsed)), data)
        with self.assertRaises(ValueError): decode_contract('JobDTO', raw(data).replace(b'"evaluated"', b'"incomplete"', 1))
        with self.assertRaises(ValueError): decode_contract('JobDTO', raw(data).replace(b'"synthetic-evidence"', b'1e999'))

    def test_evaluation_bindings_keep_existing_closed_scalar_contract(self):
        from control.execution_contracts import decode_contract
        for value in (42, ['one', 'two'], [1, 2], ''):
            data = snapshot_data(); data['release'] = data['release'] | {'evaluation_bindings': [dict(name='scope', value=value)]}
            definition = {k: v for k, v in data['release'].items() if k not in ('parameters', 'release_sha256')}
            data['release']['release_sha256'] = hashlib.sha256(json.dumps(definition, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            decoded = decode_contract('JobApprovalSnapshotData', raw(data))
            self.assertEqual(decoded.release.evaluation_bindings[0].value, tuple(value) if isinstance(value, list) else value)
        for value in (True, 1.5, [], ['one', 1], {'command': 'forbidden'}):
            data = snapshot_data(); data['release'] = data['release'] | {'evaluation_bindings': [dict(name='scope', value=value)]}
            with self.assertRaises(ValueError): decode_contract('JobApprovalSnapshotData', raw(data))

    def test_closed_wire_and_snapshot_contract(self):
        from control.execution_contracts import parse_execution_request, decode_contract, snapshot_bytes, public_summary
        request = dict(protocol=PROTOCOL, device_id=UUID, generation=1, binding_id=UUID, binding_revision=1)
        parsed = parse_execution_request('poll', raw(request))
        self.assertEqual(parsed.device_id, UUID)
        with self.assertRaises(FrozenInstanceError): parsed.generation = 2
        for key in request:
            with self.subTest(missing=key), self.assertRaises(ValueError):
                parse_execution_request('poll', raw({k: v for k, v in request.items() if k != key}))
        for bad in (request | {'extra': 1}, request | {'protocol': '0.1.0'}, request | {'generation': True},
                    request | {'generation': 2147483648}, request | {'generation': 0},
                    request | {'device_id': UUID.upper()}, request | {'device_id': UUID.replace('-', '')},
                    request | {'binding_revision': 1.0}):
            with self.subTest(bad=bad), self.assertRaises(ValueError): parse_execution_request('poll', raw(bad))
        for bad in (b'[]', b'{}' + b' ' * 65536, b'{"protocol":NaN}',
                    raw(request).replace(b'"generation":1', b'"generation":1,"generation":1'),
                    b'{"x":' * 13 + b'0' + b'}' * 13):
            with self.assertRaises(ValueError): parse_execution_request('poll', bad)
        snapshot = decode_contract('JobApprovalSnapshotData', raw(snapshot_data()))
        encoded = snapshot_bytes(snapshot)
        self.assertEqual(encoded, json.dumps(snapshot_data(), sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode())
        summary = asdict(public_summary(snapshot))
        self.assertFalse(summary['execution_receipt_is_detection_evidence'])
        self.assertNotIn('private/', json.dumps(summary))
        self.assertEqual(summary['collection_assurance'], 'unknown')
        with self.assertRaises(FrozenInstanceError): snapshot.identity.generation = 2

    def test_readiness_receipt_and_parameter_constraints(self):
        from control.execution_contracts import parse_execution_request, decode_contract
        identity = dict(protocol=PROTOCOL, device_id=UUID, generation=1, binding_id=UUID, binding_revision=1)
        readiness = identity | dict(installation_profile_sha256=DIGEST, artifact_set_sha256=DIGEST, ready=True, blocking_codes=[])
        self.assertTrue(parse_execution_request('readiness', raw(readiness)).ready)
        for changes in ({'ready': 1}, {'blocking_codes': ['local_not_ready']},
                        {'ready': False, 'blocking_codes': ['binding_disabled']},
                        {'ready': False, 'blocking_codes': ['local_not_ready'] * 2}):
            with self.assertRaises(ValueError): parse_execution_request('readiness', raw(readiness | changes))
        receipt = identity | dict(receipt_id=UUID, job_id=UUID, job_sha256=DIGEST, state='succeeded',
            started_at=WINDOWS['not_before'], finished_at=WINDOWS['expires_at'], exit_code=0, cleanup_succeeded=True)
        self.assertEqual(parse_execution_request('receipt', raw(receipt)).state, 'succeeded')
        for changes in ({'started_at': None}, {'exit_code': True}, {'cleanup_succeeded': False},
                        {'finished_at': '2026-10-25T11:00:00Z'}, {'finished_at': '2026-10-25T12:02:00.1Z'}):
            with self.assertRaises(ValueError): parse_execution_request('receipt', raw(receipt | changes))
        for changes in ({'run_id': '22222222-2222-4222-8222-222222222222'}, {'release_id': 2**63},
                        {'scenario_id': 'SCN-900'}, {'timeout_seconds': 179}, {'payload_sha256': DIGEST.upper()},
                        {'collection_end': '2026-10-25T12:02:01Z'}, {'expires_at': '2026-10-25T12:03:00Z'},
                        {'parameters': PARAMETERS | {'run_label': 'C'}}, {'parameters': PARAMETERS | {'unexpected': 1}}):
            with self.assertRaises(ValueError): decode_contract('SignedJob', raw(job_data() | changes))
        for changes in ({'parameters': PARAMETERS | {'run_label': 'Rehearsal'}},
                        {'parameters': PARAMETERS | {'rule_sha256': 'd' * 64}}):
            data = snapshot_data(); data['release'] = data['release'] | changes
            with self.assertRaises(ValueError): decode_contract('JobApprovalSnapshotData', raw(data))

    def test_execution_signing_and_verifying_require_exact_rsa3072(self):
        from control.execution_contracts import decode_contract
        from control.execution_signing import sign_execution_payload, verify_execution_envelope
        payload = raw(job_data())
        for size in (2048, 3072, 4096):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                key = rsa.generate_private_key(public_exponent=65537, key_size=size)
                path = Path(directory) / 'ephemeral.pem'
                path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                envelope = raw(dict(protocol='aegis-windows-execution/2', key_id='manager-execution-v2',
                    payload=base64.b64encode(payload).decode(), signature=base64.b64encode(key.sign(payload,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())).decode()))
                with override_settings(MANAGER_EXECUTION_SIGNING_KEY=str(path), MANAGER_SIGNING_KEY=None, ENROLLMENT_CA_KEY=None):
                    if size == 3072:
                        signed, _ = sign_execution_payload(decode_contract('SignedJob', payload))
                        self.assertEqual(verify_execution_envelope(signed, key.public_key()).job_id, UUID)
                        self.assertEqual(verify_execution_envelope(envelope, key.public_key()).job_id, UUID)
                    else:
                        with self.assertRaises(ValueError): sign_execution_payload(decode_contract('SignedJob', payload))
                        with self.assertRaises(ValueError): verify_execution_envelope(envelope, key.public_key())

    def test_signatures_preserve_original_bytes_and_separate_key(self):
        from control.execution_contracts import decode_contract
        from control.execution_signing import sign_execution_payload, verify_execution_envelope
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with override_settings(MANAGER_EXECUTION_SIGNING_KEY=None):
            with self.assertRaises(ValueError): sign_execution_payload(decode_contract('SignedJob', raw(job_data())))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ephemeral.pem'
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            with override_settings(MANAGER_EXECUTION_SIGNING_KEY=str(path), MANAGER_SIGNING_KEY='must-not-read'):
                envelope, digest = sign_execution_payload(decode_contract('SignedJob', raw(job_data())))
            with override_settings(MANAGER_EXECUTION_SIGNING_KEY=str(path), MANAGER_SIGNING_KEY=str(path)):
                with self.assertRaises(ValueError): sign_execution_payload(decode_contract('SignedJob', raw(job_data())))
            copy = Path(directory) / 'same-key.pem'; copy.write_bytes(path.read_bytes())
            with override_settings(MANAGER_EXECUTION_SIGNING_KEY=str(path), MANAGER_SIGNING_KEY=str(copy)):
                with self.assertRaises(ValueError): sign_execution_payload(decode_contract('SignedJob', raw(job_data())))
            self.assertEqual(verify_execution_envelope(envelope, key.public_key()).job_id, UUID)
            wire = json.loads(envelope); payload = base64.b64decode(wire['payload'])
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            self.assertNotEqual(digest, DIGEST)
            # Noncanonical JSON is signed as-is, not normalized by the verifier.
            original = raw(job_data()) + b'  '
            wire['payload'] = base64.b64encode(original).decode()
            wire['signature'] = base64.b64encode(key.sign(original, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())).decode()
            self.assertEqual(verify_execution_envelope(raw(wire), key.public_key()).job_id, UUID)
            for changed in (wire | {'payload': wire['payload'] + '\n'}, wire | {'protocol': '0.1.0'},
                            wire | {'signature': 'AA=='}, wire | {'extra': None},
                            wire | {'payload': base64.b64encode(original.replace(b'SCN-001', b'SCN-002')).decode()}):
                with self.assertRaises(ValueError): verify_execution_envelope(raw(changed), key.public_key())
