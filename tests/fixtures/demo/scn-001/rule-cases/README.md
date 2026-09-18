# Synthetic-only Wazuh rule controls

`base.synthetic.json` được viết cho test, không thu từ endpoint. Generator tạo
12 biến thể đã ghi nhãn `aegis_synthetic_test_only=true`, cùng catalog kỳ vọng.
Host/path được parameterize cho logtest, không biến chúng thành evidence thật.

Không nạp các mẫu này vào production index, không dùng để chứng minh telemetry
hay đánh giá A/B/C. Không sửa field/timestamp của log thật để giống fixture.

Xem [hướng dẫn kit](../../../../../demos/scn-001/README.md) để biết matrix,
parent-dependent cases và cách phân biệt negative không khớp với lỗi decoder.
