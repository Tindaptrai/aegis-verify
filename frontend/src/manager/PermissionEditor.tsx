import { CAPABILITIES, type Capability, type PermissionsDTO } from './contracts';
import { roleLabels } from './AccountMenu';

export function PermissionEditor({ metadata, capabilities, inherited, onChange, disabled }: {
  metadata: PermissionsDTO; capabilities: Capability[]; inherited: Capability[];
  onChange: (capabilities: Capability[]) => void; disabled: boolean;
}) {
  const preset = (['admin', 'operator', 'viewer'] as const).find((key) => metadata.presets[key].length === capabilities.length && metadata.presets[key].every((value) => capabilities.includes(value))) ?? 'custom';
  function selectPreset(value: string) {
    if (value === 'custom') return;
    const selected = metadata.presets[value as keyof PermissionsDTO['presets']];
    onChange(CAPABILITIES.filter((key) => selected.includes(key) || inherited.includes(key)));
  }
  return <>
    <label htmlFor="user-role">Vai trò</label><select id="user-role" value={preset} onChange={(event) => selectPreset(event.target.value)} disabled={disabled}>
      {(['admin', 'operator', 'viewer'] as const).map((key) => <option key={key} value={key}>{roleLabels[key]}</option>)}<option value="custom">Tùy chỉnh</option>
    </select>
    <fieldset className="permission-fieldset" disabled={disabled}><legend>Quyền sản phẩm</legend>
      <p className="field-help">{metadata.inheritance_explanation}</p>
      <div className="permission-grid">{metadata.capabilities.map(({ key, label, description }) => {
        const locked = inherited.includes(key);
        return <label className="permission-card" key={key}>
          <input type="checkbox" checked={capabilities.includes(key)} disabled={locked || (key !== 'view' && !capabilities.includes('view') && !capabilities.includes(key))}
            onChange={(event) => onChange(CAPABILITIES.filter((value) => value === key ? event.target.checked : capabilities.includes(value)))} />
          <span><strong>{label}</strong><small>{description}</small><code>{key}</code>{locked && <small className="inherited-grant">Kế thừa · đã khóa</small>}</span>
        </label>;
      })}</div>
    </fieldset>
  </>;
}
