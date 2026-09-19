import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { RunCharts } from './RunCharts';

describe('Run statistics', () => {
  it('exposes every outcome and independent intake count with an accessible chart summary', () => {
    render(<RunCharts outcomes={{ satisfied: 3, false_negative: 1, missing_telemetry: 2, inconclusive: 4 }} intake={{ parsed: 12, referenced: 5, skipped: 7 }} />);
    expect(screen.getByRole('img', { name: 'Phân bố assertion: Đạt 3, False negative 1, Thiếu telemetry 2, Chưa kết luận 4' })).toBeInTheDocument();
    const evidence = screen.getByRole('region', { name: 'Evidence trong run' });
    expect(within(evidence).getByText('Đã parse').closest('li')).toHaveTextContent('12');
    expect(within(evidence).getByText('Được tham chiếu').closest('li')).toHaveTextContent('5');
    expect(within(evidence).getByText('Bị skip').closest('li')).toHaveTextContent('7');
    expect(within(evidence).getByText(/Các số đếm độc lập/)).toBeInTheDocument();
  });

  it('shows explicit empty states instead of a positive result for zero counts', () => {
    render(<RunCharts outcomes={{ satisfied: 0, false_negative: 0, missing_telemetry: 0, inconclusive: 0 }} intake={{ parsed: 0, referenced: 0, skipped: 0 }} />);
    expect(screen.getByText('Chưa có assertion')).toBeInTheDocument();
    expect(screen.getByText('Chưa có evidence được ghi nhận')).toBeInTheDocument();
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
  });
});
