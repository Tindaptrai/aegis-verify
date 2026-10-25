import { useState, type FormEvent } from 'react';
import { ExecutionDialog } from './ExecutionPreview';
import { PROVIDER, validBinding, type BindingInput, type ExecutionDeviceDTO, type ProviderDTO, type ReleaseId } from './executionTypes';

export function ExecutionBindingEditor({ device, providers, busy, error, onSave, onClose }: { device: ExecutionDeviceDTO; providers: ProviderDTO[]; busy: boolean; error: string; onSave: (input: BindingInput) => void; onClose: () => void }) {
  const [release, setRelease] = useState<ReleaseId | ''>(device.release_id ?? ''); const [enabled, setEnabled] = useState(!device.blocking_codes.includes('binding_disabled'));
  const [profile, setProfile] = useState(''); const [connection, setConnection] = useState(device.wazuh_connection_id ?? ''); const [revision, setRevision] = useState(''); const [agent, setAgent] = useState(device.wazuh_agent_id ?? '');
  const input: BindingInput = { expected_revision: device.binding_revision, enabled, provider_id: PROVIDER, runner_release_id: release as ReleaseId, installation_profile_sha256: profile, wazuh_connection_id: connection, wazuh_connection_revision: Number(revision), wazuh_agent_id: agent };
  const valid = validBinding(input) && providers.some((p) => p.release_id === release);
  function submit(event: FormEvent) { event.preventDefault(); if (valid && !busy) onSave(input); }
  return <ExecutionDialog title="Thiết lập thực thi" onClose={onClose}><p>Liên kết máy với release và kết nối opaque đã được review. Không nhập credentials, cài adapter hoặc cài rule tại đây. Đăng ký cấu hình kết nối thuộc quyền Quản lý kết nối.</p><form onSubmit={submit}>
    <label htmlFor="binding-release">RunnerRelease đã review</label><select id="binding-release" disabled={busy} value={release} onChange={(e) => setRelease(e.target.value as ReleaseId)}><option value="">Chọn release đã review</option>{providers.map((p) => <option key={`${p.release_id}:${p.release_sha256}`} value={p.release_id}>RunnerRelease #{p.release_id} · {p.release_sha256}</option>)}</select>
    <label htmlFor="binding-enabled"><input id="binding-enabled" type="checkbox" checked={enabled} disabled={busy} onChange={(e) => setEnabled(e.target.checked)} /> Cho phép admission mới</label>
    <label htmlFor="binding-profile">Installation profile SHA-256 đã review</label><input id="binding-profile" maxLength={64} value={profile} disabled={busy} onChange={(e) => setProfile(e.target.value)} />
    <label htmlFor="binding-connection">Connection UUID đã review</label><input id="binding-connection" value={connection} disabled={busy} onChange={(e) => setConnection(e.target.value)} />
    <label htmlFor="binding-revision">Connection revision đã review</label><input id="binding-revision" inputMode="numeric" value={revision} disabled={busy} onChange={(e) => setRevision(e.target.value)} />
    <label htmlFor="binding-agent">Wazuh agent ID</label><input id="binding-agent" maxLength={64} value={agent} disabled={busy} onChange={(e) => setAgent(e.target.value)} />
    {error && <p role="alert" className="manager-alert">{error}</p>}<button className="primary" disabled={busy || !valid}>Lưu binding đã review</button>
  </form></ExecutionDialog>;
}
