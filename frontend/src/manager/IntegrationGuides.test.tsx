import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { IntegrationGuides, wazuhGuide, guideHash, parseGuideHash } from './IntegrationGuides';
describe('versioned integration guide', () => {
  it('separates submitted PEM bundle digest from each certificate DER fingerprint', () => {
    const props = { onStep: vi.fn(), onBack: vi.fn() };
    const view = render(<IntegrationGuides step="ca" {...props} />);
    const article = screen.getByRole('article');
    expect(article).toHaveTextContent('Nội dung PEM/bundle SHA-256');
    expect(article).toHaveTextContent('sha256sum <configured-public-ca.pem>');
    expect(article).toHaveTextContent('DER');
    expect(article).toHaveTextContent('từng certificate');
    expect(article).toHaveTextContent('BOM');
    expect(article).toHaveTextContent('CRLF');
    expect(article).toHaveTextContent("read_bytes().decode('utf-8-sig').encode('ascii')");
    view.rerender(<IntegrationGuides step="verify" {...props} />);
    expect(article).toHaveTextContent('Nội dung PEM/bundle SHA-256');
    expect(article).not.toHaveTextContent('CA fingerprint');
  });
  it('records deployment, docs review status and unavailable screenshot provenance', () => {
    expect(wazuhGuide).toMatchObject({ vendor: 'Wazuh', product: 'Indexer', version_range: '4.14.4', deployment: 'self-managed', guide_revision: 1, reviewed_at: '2026-10-29', validation_status: 'docs-reviewed; native lab acceptance pending', screenshot_provenance: 'unavailable' });
    render(<IntegrationGuides step="account" onStep={vi.fn()} onBack={vi.fn()} />);
    expect(screen.getByRole('heading', { name: 'Wazuh 4.14.4 · self-managed' })).toBeVisible();
    expect(screen.getByText('Chưa có ảnh minh họa được kiểm chứng cho bước này.')).toBeVisible();
    expect(screen.getByText('Hướng dẫn đang hoàn thiện; chưa kiểm chứng trên lab.')).toBeVisible();
    expect(screen.getByText(wazuhGuide.connector_release)).not.toBeVisible();
    expect(screen.getByText(/Internal users/)).toBeVisible();
    const steps = within(screen.getByRole('list', { name: 'Thiết lập tài khoản Indexer' })).getAllByRole('listitem');
    expect(steps).toHaveLength(6);
    expect(steps[0]).toHaveTextContent('Đăng nhập'); expect(steps[1]).toHaveTextContent('aegis_reader');
    expect(steps[2]).toHaveTextContent('aegis_index_reader'); expect(steps[5]).toHaveTextContent('Quay lại AEGIS');
  });
  it('uses a closed vendor/version/deployment/step hash and rejects unsupported routes', () => {
    expect(guideHash('ca')).toBe('#integration/wazuh/4.14.4/self-managed/ca');
    expect(parseGuideHash(guideHash('account'))).toEqual({ step: 'account', supported: true });
    for (const hash of ['#integration/wazuh/5/self-managed/ca', '#integration/elastic/4.14.4/cloud/account', '#integration/wazuh/4.14.4/self-managed/arbitrary']) expect(parseGuideHash(hash)?.supported).toBe(false);
    expect(parseGuideHash('')).toBeNull();
  });
  it('retains product/version while choosing account, CA and troubleshooting steps', () => {
    const step = vi.fn(); render(<IntegrationGuides step="ca" onStep={step} onBack={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Tài khoản & quyền đọc' })); expect(step).toHaveBeenCalledWith('account');
    expect(screen.getByText(/root-ca.pem/)).toBeVisible();
    expect(screen.getByText(/Không xuất private key/)).toBeVisible();
    expect(screen.getByText(/openssl x509/)).toBeVisible();
    for (const link of screen.getAllByRole('link')) expect(link).toHaveAttribute('href', expect.stringMatching(/^https:\/\/(documentation\.wazuh\.com|docs\.opensearch\.org)\//));
  });
  it('documents reviewed scroll cleanup, no least-privilege claim, rotation and future capability limits', () => {
    const props = { onStep: vi.fn(), onBack: vi.fn() }; const view = render(<IntegrationGuides step="account" {...props} />);
    for (const text of ['indices:data/read/scroll/clear', 'cluster_composite_ops_ro', 'Không chứng minh tài khoản không có quyền ghi']) expect(screen.getByRole('article')).toHaveTextContent(text);
    view.rerender(<IntegrationGuides step="troubleshooting" {...props} />);
    expect(screen.getByRole('article')).toHaveTextContent('revoke'); expect(screen.getByRole('article')).toHaveTextContent('expiry');
    view.rerender(<IntegrationGuides step="verify" {...props} />); expect(screen.getByRole('article')).toHaveTextContent('waiting_configuration');
    view.rerender(<IntegrationGuides step="overview" {...props} />);
    expect(screen.getByText(/Elastic — chỉ offline/)).toBeVisible(); expect(screen.getByText(/Splunk — planned/)).toBeVisible();
    expect(screen.queryByRole('button', { name: /Thêm Elastic|Thêm Splunk/ })).not.toBeInTheDocument();
  });
});
