// Synthetic catalog responses for tests only.
import type { CatalogItemDTO, CatalogListDTO, CatalogPackageDTO } from './catalogTypes';
export const catalogId = '11111111-1111-4111-8111-111111111111';
export const catalogHash = 'a'.repeat(64);
export const catalogItem: CatalogItemDTO = {
  id: catalogId, scenario_id: 'SCN-900', name: 'Synthetic catalog scenario', version: '0.1.0',
  platform: 'windows' as const, runner: 'windows-powershell-script@1' as const, timeout_seconds: 120,
  sha256: catalogHash, status: 'draft' as const, created_at: '2026-10-25T00:00:00Z', created_by: 'synthetic', published_at: null, published_by: null,
};
export const catalogDetail: CatalogPackageDTO = {
  ...catalogItem, validation: { valid: true as const, codes: [] },
  files: [{ path: 'README.md', size: 40, sha256: 'b'.repeat(64) }, { path: 'payload/demo.ps1', size: 15, sha256: 'c'.repeat(64) }],
  audit: [{ action: 'imported', actor: 'synthetic', at: '2026-10-25T00:00:00Z' }], execution_supported: false as const,
};
export const catalogList: CatalogListDTO = { results: [catalogItem], count: 1, page: 1, page_size: 50 };
