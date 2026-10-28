import { useState } from 'react';
import { parseEvaluationReport } from '../contracts';
import { RunView, type RunTab } from '../components/RunView';
import type { JobDTO } from './executionTypes';
import { ExecutionLimits } from './ExecutionPreview';

const executionLabels = { draft: 'Bản nháp', queued: 'Đang xếp hàng', leased: 'Agent đã nhận', started: 'Đã cho phép bắt đầu', succeeded: 'Thành công', failed: 'Thực thi thất bại', execution_unknown: 'Chưa xác định thực thi', cancelled: 'Đã hủy trước khi bắt đầu', expired: 'Hết hạn' };
const collectionLabels = { pending: 'Đang chờ', collecting: 'Đang thu thập', evaluated: 'Đã xử lý thu thập', empty: 'Không có evidence', failed: 'Thu thập thất bại', reconciled: 'Đã reconcile' };
export function ExecutionJobStatus({ job, onCancel, busy = false }: { job: JobDTO; onCancel?: () => void; busy?: boolean }) {
  const [tab, setTab] = useState<RunTab>('assertions'); const parsed = job.report === null ? null : parseEvaluationReport(job.report);
  const available = job.evaluation_state === 'evaluated' && parsed?.ok;
  return <section className="panel panel-body execution-job" aria-label="Trạng thái tác vụ"><h2>Trạng thái tác vụ</h2><p>{job.job_id}</p>
    <div className="execution-stages"><article><h3>Thực thi</h3><strong>{executionLabels[job.execution_state]}</strong><p>Tạo: <time>{job.created_at}</time></p><p>Cho phép bắt đầu: {job.started_authorized_at ?? 'Chưa ghi nhận'}</p><p>Kết thúc: {job.finished_at ?? 'Chưa ghi nhận'}</p></article><article><h3>Thu thập</h3><strong>{collectionLabels[job.collection_state]}</strong><p>Cửa sổ: {job.summary.collection_start} → {job.summary.collection_end}</p><p>Assurance: unknown</p></article><article><h3>Đánh giá</h3><strong>{job.evaluation_state === 'evaluated' ? 'Đã đánh giá' : 'Chưa đánh giá'}</strong><p>Run binding: unknown</p></article></div>
    <ExecutionLimits />{job.error_code !== null && <p role="alert">Tác vụ cần kiểm tra. Không suy ra kết quả phát hiện từ lỗi thực thi/thu thập.</p>}
    {onCancel && ['queued', 'leased'].includes(job.execution_state) && <><p>Chỉ hủy trước khi bắt đầu; cần server xác nhận trạng thái.</p><button disabled={busy} onClick={onCancel}>Hủy trước khi bắt đầu</button></>}
    {available ? <><a href={`#execution-report-${job.job_id}`}>Xem report và evidence</a><section id={`execution-report-${job.job_id}`} className="execution-report" aria-label="Report và evidence"><RunView report={parsed.value} tab={tab} onTab={setTab} /></section></> : <p>Report/evidence chưa khả dụng{job.report !== null ? ' hoặc chưa đúng canonical contract' : ''}.</p>}
  </section>;
}
