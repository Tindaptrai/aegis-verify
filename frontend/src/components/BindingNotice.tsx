import type { RunBinding } from '../contracts';
import { Notice } from './Feedback';

export function BindingNotice({ binding }: { binding: RunBinding | null }) {
  return (
    <Notice tone={binding?.status === 'conflict' ? 'error' : 'warn'}
      title={`Run binding: ${binding?.status ?? 'chưa có dữ liệu'}`}>
      {binding ? <>
        <p>Run: <span className="mono wrap">{binding.run_id}</span></p>
        {binding.reasons.length ? <ul>{binding.reasons.map((reason, index) =>
          <li key={index} className="mono wrap">{reason}</li>)}</ul> : <p>Report không cung cấp mã lý do.</p>}
        <p>both_sides_caller_declared: {String(binding.both_sides_caller_declared)}</p>
      </> : <p>Report không có thông tin run binding; không suy ra đã được review.</p>}
      <p>Run binding không phải xác minh độc lập hay bảo đảm collection đầy đủ.
        Trạng thái này không thay đổi kết quả detection; caller_reviewed không đồng nghĩa lab_verified.</p>
    </Notice>
  );
}
