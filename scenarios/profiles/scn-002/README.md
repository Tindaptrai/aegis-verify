# SCN-002 evaluation profile

`profile.json` là `EvaluationProfile` cho `scenarios/SCN-002-attempted-exfiltration.yaml`.
Mọi giá trị riêng của lab (IP, cổng, tracker rule chặn) đi qua bindings trong
`context.json` của từng lượt và **không** nằm trong Git. `context.example.json`
chỉ minh hoạ tên binding bằng dải địa chỉ tài liệu (RFC 5737).

Chi tiết literal, cửa sổ tương quan và giới hạn: [docs/SCN002_EVALUATION_PROFILE.md](../../../docs/SCN002_EVALUATION_PROFILE.md).
