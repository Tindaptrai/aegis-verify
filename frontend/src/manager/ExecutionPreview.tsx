import { useEffect, useRef, type ReactNode } from 'react';
import type { ApproveInput, PreviewDTO } from './executionTypes';

export function ExecutionDialog({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const element = useRef<HTMLElement>(null); const close = useRef(onClose); close.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null; element.current?.focus();
    function keyboard(event: KeyboardEvent) {
      if (event.key === 'Escape') { event.preventDefault(); close.current(); }
      if (event.key !== 'Tab') return;
      const nodes = Array.from(element.current?.querySelectorAll<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled),a[href],summary,[tabindex="0"]') ?? []).filter((node) => !node.closest('details:not([open])') || node.tagName === 'SUMMARY');
      const first = nodes[0], last = nodes.at(-1);
      if (event.shiftKey && (document.activeElement === first || document.activeElement === element.current)) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || document.activeElement === element.current)) { event.preventDefault(); first?.focus(); }
    }
    document.addEventListener('keydown', keyboard);
    return () => { document.removeEventListener('keydown', keyboard); if (previous?.isConnected) previous.focus(); };
  }, []);
  return <div className="drawer-backdrop" onClick={onClose}><section ref={element} className="account-drawer execution-drawer" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} onClick={(e) => e.stopPropagation()}><header><h2>{title}</h2><button onClick={onClose} aria-label="Đóng cửa sổ">×</button></header><div className="drawer-body">{children}</div></section></div>;
}
export function ExecutionLimits() { return <p className="presence-help">Receipt thực thi, trạng thái sức khỏe và exit 0 không phải evidence phát hiện. Run binding: unknown · Collection assurance: unknown. Thiếu alert chưa chứng minh false negative hoặc thu thập đầy đủ.</p>; }
export function ExecutionPreview({ preview, targetName, idempotencyKey, busy, error, now, onApprove, onClose }: { preview: PreviewDTO; targetName: string; idempotencyKey: string; busy: boolean; error: string; now: number; onApprove: (input: ApproveInput) => void; onClose: () => void }) {
  const s = preview.summary; const expiring = Date.parse(preview.expires_at) - now < 30000;
  return <ExecutionDialog title="Xem trước tác vụ" onClose={onClose}>
    <h3>{targetName}</h3><dl className="execution-metadata"><dt>Máy / môi trường</dt><dd>{s.device_id} / {s.environment_id}</dd><dt>Wazuh scope</dt><dd>{s.wazuh_connection_id} / Agent {s.wazuh_agent_id}</dd><dt>Provider</dt><dd>{s.provider_id}</dd><dt>Nguồn đã review</dt><dd>RunnerRelease #{s.release_id} · {s.scenario_id} · {s.runner_id} {s.runner_version}</dd><dt>Tham số</dt><dd>{s.parameters.run_label} · {s.parameters.rule_revision}</dd><dt>Timeout</dt><dd>{s.timeout_seconds} giây</dd><dt>Cửa sổ thực thi</dt><dd><time>{s.not_before}</time> → <time>{s.expires_at}</time></dd><dt>Cửa sổ thu thập</dt><dd><time>{s.collection_start}</time> → <time>{s.collection_end}</time></dd><dt>Cleanup</dt><dd>{s.cleanup_policy}</dd></dl>
    <ExecutionLimits /><details><summary>Chi tiết kỹ thuật</summary><dl className="execution-metadata"><dt>Preview SHA-256</dt><dd><code>{preview.preview_sha256}</code></dd><dt>Release SHA-256</dt><dd><code>{s.release_sha256}</code></dd><dt>Binding</dt><dd>{s.binding_id} / revision {s.binding_revision}</dd>{Object.entries(s.artifact_pins).map(([name, value]) => <div key={name}><dt>{name}</dt><dd><code>{value}</code></dd></div>)}{Object.entries(s.rule_pins).map(([name, value]) => <div key={name}><dt>Rule {name}</dt><dd><code>{value}</code></dd></div>)}</dl></details>
    {error && <p role="alert" className="manager-alert">{error}</p>}{expiring && <p role="alert">Xem trước còn dưới 30 giây. Đóng và tạo xem trước mới.</p>}
    <p>Phê duyệt chỉ áp dụng cho snapshot này. Đóng cửa sổ không hủy tác vụ đã được server chấp nhận.</p><button className="primary" disabled={busy || expiring} onClick={() => onApprove({ preview_id: preview.preview_id, preview_sha256: preview.preview_sha256, idempotency_key: idempotencyKey })}>{busy ? 'Đang gửi phê duyệt…' : 'Xác nhận và chạy'}</button>
  </ExecutionDialog>;
}
