import { useEffect, useState } from 'react';
import type { ManagerApi } from './api';
import type { DeviceV2DTO, DeviceHistoryDTO } from './types';
export const deviceStatusLabels = { online: 'Online', offline: 'Offline', expired: 'Đã hết hạn', revoked: 'Đã thu hồi', unknown: 'Chưa xác định (legacy)', archived: 'Đã xóa' };
export function deviceDate(value: string | null) { return value === null ? 'Chưa ghi nhận' : new Date(value).toLocaleString('vi-VN'); }
export function DeviceIPs({ device, full = false }: { device: DeviceV2DTO; full?: boolean }) {
 const [expanded, setExpanded] = useState(full);
 const ips = device.reported_ips ?? [];
 return <div className="device-ips"><strong>IP agent khai báo</strong>{device.ip_collection_status === 'unknown' ? <p>Chưa ghi nhận IP</p> : device.ip_collection_status === 'unavailable' ? <p>Không đọc được IP</p> : ips.length === 0 ? <p>Không có IP phù hợp</p> : <><ul>{(expanded ? ips : ips.slice(0, 2)).map((ip) => <li key={ip}><code>{ip}</code></li>)}</ul>{ips.length > 2 && <button onClick={() => setExpanded(!expanded)}>{expanded ? 'Thu gọn IP' : `Xem tất cả ${ips.length} IP`}</button>}</>}
 <small>Nhận báo cáo IP: {deviceDate(device.reported_ips_received_at)}</small>{device.reported_ips_truncated && <small>Danh sách bị cắt · tối đa 32 IP</small>}
 <strong>IP kết nối Manager thấy</strong><code>{device.observed_ip ?? 'Chưa ghi nhận IP quan sát'}</code><small>Nhận IP quan sát: {deviceDate(device.observed_ip_received_at)}</small>
 {device.status === 'offline' && <small>Dữ liệu cũ · snapshot cuối khi Offline</small>}{device.status === 'archived' && <small>Snapshot cuối · máy đã xóa</small>}</div>;
}
export function DeviceIdentity({ api, id, onAuthorityFailure }: { api: ManagerApi; id: string; onAuthorityFailure: (failure: unknown) => boolean }) {
  const [device, setDevice] = useState<DeviceV2DTO | null>(null);
  const [history, setHistory] = useState<DeviceHistoryDTO | null>(null);
  const [page, setPage] = useState(1);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError(''); setHistory(null);
    void Promise.all([
      api.device(id, controller.signal),
      api.deviceHistory(id, page, controller.signal),
    ]).then(([identity, rows]) => {
      if (controller.signal.aborted) return;
      if (identity.id !== id) throw new Error('Mismatched identity');
      setDevice(identity); setHistory(rows);
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return;
      setDevice(null);
      if (!onAuthorityFailure(failure)) setError('Không thể tải chi tiết hoặc lịch sử máy. Vui lòng thử lại.');
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [api, id, page]);
 return <>{loading && <p role="status">Đang tải lịch sử…</p>}{error && <p role="alert" className="manager-alert">{error}</p>}{device && <><h3>{device.hostname ?? 'Chưa ghi nhận tên máy'}</h3><p className="device-uuid">{device.id}</p><p>Trạng thái: {deviceStatusLabels[device.status]}</p><p>Môi trường: {device.environment_id} · Generation: {device.generation}</p><p>Phiên bản ghép nối: {device.agent_version ?? 'Chưa ghi nhận'} · Phiên bản báo cáo: {device.reported_agent_version ?? 'Chưa ghi nhận'}</p><p>Liên hệ cuối: {deviceDate(device.last_heartbeat_at)}</p><p>Hết hạn chứng thư: {deviceDate(device.certificate_expires_at)}</p><DeviceIPs device={device} full />{device.archived_at && <p>Đã xóa: {deviceDate(device.archived_at)} · {device.archived_by_id === null ? 'Chưa ghi nhận actor' : `Actor ID: ${device.archived_by_id}`}</p>}</>}
 <h3>Lịch sử danh tính</h3>{history && <>{history.results.length === 0 ? <p>Chưa có lịch sử danh tính.</p> : <ol className="device-history">{history.results.map((row, index) => <li key={`${page}:${index}`}><strong>{row.action}</strong><small>{deviceDate(row.created_at)}</small><span>{row.actor_id === null ? 'Chưa ghi nhận actor' : `Actor ID: ${row.actor_id}`}</span><small>Device UUID: {row.device_id ?? 'Chưa ghi nhận'}</small><small>Code UUID: {row.code_id ?? 'Chưa ghi nhận'}</small></li>)}</ol>}<div className="users-pagination"><span>Trang {history.page} · {history.count} sự kiện</span><button disabled={loading || history.page <= 1} onClick={() => setPage(page - 1)}>Lịch sử trước</button><button disabled={loading || history.page * history.page_size >= history.count} onClick={() => setPage(page + 1)}>Lịch sử sau</button></div></>}</>;
}
