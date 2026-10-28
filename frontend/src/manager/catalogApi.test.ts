import { describe, expect, it, vi } from 'vitest';
import { createManagerApi } from './api';
import { catalogDetail, catalogHash, catalogId, catalogItem, catalogList } from './catalog-test-fixtures';
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });

describe('Catalog browser API contract', () => {
  it.each([300, 512])('accepts a %s-code-point supplementary name on import, detail and list', async (count) => {
    const name = '\u{1f680}'.repeat(count);
    const detail = { ...catalogDetail, name };
    const list = { ...catalogList, results: [{ ...catalogItem, name }] };
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(detail, 201))
      .mockResolvedValueOnce(json(detail)).mockResolvedValueOnce(json(list));
    const api = createManagerApi(fetcher);
    await expect(api.importCatalog(new File(['synthetic'], 'scenario.zip'))).resolves.toEqual(detail);
    await expect(api.catalogPackage(catalogId)).resolves.toEqual(detail);
    await expect(api.listCatalog()).resolves.toEqual(list);
  });
  it('rejects a 513-code-point supplementary name on import, detail and list', async () => {
    const name = '\u{1f680}'.repeat(513);
    const detail = { ...catalogDetail, name };
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(detail, 201))
      .mockResolvedValueOnce(json(detail)).mockResolvedValueOnce(json({ ...catalogList, results: [{ ...catalogItem, name }] }));
    const api = createManagerApi(fetcher);
    for (const action of [() => api.importCatalog(new File(['synthetic'], 'scenario.zip')), () => api.catalogPackage(catalogId), () => api.listCatalog()]) {
      await expect(action()).rejects.toMatchObject({ name: 'ManagerApiError' });
    }
  });
  it('bounds file previews by UTF-8 bytes for supplementary text', async () => {
    const file = { path: 'README.md', text: '\u{1f680}'.repeat(256 * 1024) };
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(file))
      .mockResolvedValueOnce(json({ ...file, text: file.text + '\u{1f680}' }));
    const api = createManagerApi(fetcher);
    await expect(api.catalogFile(catalogId, file.path)).resolves.toEqual(file);
    await expect(api.catalogFile(catalogId, file.path)).rejects.toMatchObject({ name: 'ManagerApiError' });
  });
  it('maps list, private detail/text and hash-bound lifecycle with cookie credentials and CSRF', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json({ authenticated: false, csrf_token: 'synthetic-csrf', user: null, expires_at: null }))
      .mockResolvedValueOnce(json(catalogList)).mockResolvedValueOnce(json(catalogDetail))
      .mockResolvedValueOnce(json({ path: 'payload/a & b.ps1', text: '<script>inert</script>' }))
      .mockResolvedValueOnce(json(catalogDetail)).mockResolvedValueOnce(json(catalogDetail));
    const api = createManagerApi(fetcher); await api.session();
    await api.listCatalog({ page: 2, q: 'a & b', status: 'draft' });
    await api.catalogPackage(catalogId);
    expect(await api.catalogFile(catalogId, 'payload/a & b.ps1')).toEqual({ path: 'payload/a & b.ps1', text: '<script>inert</script>' });
    await api.publishCatalog(catalogId, catalogHash); await api.unpublishCatalog(catalogId, catalogHash);
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual(['/api/v1/auth/session', '/api/v1/catalog?page=2&q=a+%26+b&status=draft', `/api/v1/catalog/${catalogId}`, `/api/v1/catalog/${catalogId}/file?path=payload%2Fa+%26+b.ps1`, `/api/v1/catalog/${catalogId}/publish`, `/api/v1/catalog/${catalogId}/unpublish`]);
    expect(fetcher.mock.calls[4]?.[1]).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', body: JSON.stringify({ sha256: catalogHash }), headers: { 'Content-Type': 'application/json', 'X-CSRFToken': 'synthetic-csrf' } });
  });
  it.each([200, 201])('uploads multipart package with browser boundary and accepts import status %s', async (status) => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json({ authenticated: false, csrf_token: 'synthetic-csrf', user: null, expires_at: null })).mockResolvedValueOnce(json(catalogDetail, status));
    const api = createManagerApi(fetcher); await api.session();
    const file = new File(['synthetic'], 'scenario.zip', { type: 'application/zip' });
    expect(await api.importCatalog(file)).toEqual(catalogDetail);
    const [url, init] = fetcher.mock.calls[1]!;
    expect(url).toBe('/api/v1/catalog/import'); expect(init?.body).toBeInstanceOf(FormData);
    expect((init?.body as FormData).get('package')).toBe(file);
    expect(init?.headers).toEqual({ 'X-CSRFToken': 'synthetic-csrf' });
  });
  it.each([
    { ...catalogDetail, execution_supported: true },
    { ...catalogDetail, validation: { valid: false, codes: [] } },
    { ...catalogDetail, status: 'trusted' }, { ...catalogDetail, timeout_seconds: 0 },
    { ...catalogDetail, files: [{ path: '../private', size: 1, sha256: catalogHash }] },
    { ...catalogDetail, sha256: 'invalid' }, { ...catalogDetail, unexpected: 'source text' },
  ])('rejects malformed catalog details without trusting response metadata', async (body) => {
    const api = createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(json(body)));
    await expect(api.catalogPackage(catalogId)).rejects.toMatchObject({ name: 'ManagerApiError', message: 'Manager request failed' });
  });
  it.each([401, 403])('preserves denied direct read/write status %s', async (status) => {
    const api = createManagerApi(vi.fn<typeof fetch>().mockImplementation(async () => json({ error: { code: 'private diagnostic' } }, status)));
    for (const action of [() => api.listCatalog(), () => api.catalogPackage(catalogId), () => api.catalogFile(catalogId, 'README.md'), () => api.importCatalog(new File([''], 'a.zip')), () => api.publishCatalog(catalogId, catalogHash), () => api.unpublishCatalog(catalogId, catalogHash)]) {
      await expect(action()).rejects.toMatchObject({ status, code: undefined });
    }
  });
  it('rejects malformed pagination/text and unexpected success status', async () => {
    for (const response of [json({ ...catalogList, page_size: 500 }), json(catalogList, 201)]) {
      await expect(createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(response)).listCatalog()).rejects.toMatchObject({ name: 'ManagerApiError' });
    }
    await expect(createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(json({ path: 'README.md', text: {}, html: 'unsafe' }))).catalogFile(catalogId, 'README.md')).rejects.toMatchObject({ name: 'ManagerApiError' });
  });
  it('retains only bounded fixed validation codes and suppresses untrusted reports', async () => {
    const valid = { error: { code: 'invalid_metadata' }, validation: { valid: false, codes: ['invalid_metadata', 'profile_mismatch'] } };
    const api = createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(json(valid, 400)));
    await expect(api.importCatalog(new File([''], 'a.zip'))).rejects.toMatchObject({ code: 'invalid_metadata', validationCodes: ['invalid_metadata', 'profile_mismatch'] });
    for (const validation of [{ valid: false, codes: ['private script diagnostic'] }, { valid: true, codes: ['invalid_metadata'] }, { valid: false, codes: Array(50).fill('invalid_metadata') }]) {
      await expect(createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(json({ ...valid, validation }, 400))).importCatalog(new File([''], 'a.zip'))).rejects.toMatchObject({ validationCodes: [] });
    }
  });
  it('admits the latest 100 audit entries but rejects a larger history response', async () => {
    const entry = { action: 'published', actor: 'synthetic', at: '2026-10-25T00:00:00Z' };
    const detail = { ...catalogDetail, audit: Array(100).fill(entry) };
    await expect(createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(json(detail))).catalogPackage(catalogId)).resolves.toEqual(detail);
    await expect(createManagerApi(vi.fn<typeof fetch>().mockResolvedValue(json({ ...detail, audit: Array(101).fill(entry) }))).catalogPackage(catalogId)).rejects.toMatchObject({ name: 'ManagerApiError' });
  });
});
