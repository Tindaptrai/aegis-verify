# SCN-001 — Operator checklist (lặp lại được)

Checklist cho một bộ A/B/C hoàn chỉnh trên lab đã duyệt. Mỗi bước ghi rõ ai làm
và bằng chứng nào phải có. Không có bước nào tự tạo approval hay verdict.

## 0. Điều kiện vào

- [ ] Issue/scope được duyệt; scenario `SCN-001` version `0.1.0` không đổi.
- [ ] Kit sinh bằng `scripts/prepare_scn001_kit.py` với `--field-profile
      wazuh-eventchannel-4.14.4-lf-v1`, `--parent-sid` đã đối chiếu (khuyến nghị
      91802), `--occupied-ids` từ inventory thật. Ghi lại `kit.json` hashes.
- [ ] Lab directory **mới** cho bộ run mới; không ghi đè kit/evidence cũ.
- [ ] Backup ngoài `/var/ossec/etc/rules` của mọi file demo hiện có, kèm hash.

## 1. Đẩy kit

- [ ] Copy nội dung kit tới đúng `lab_directory`; xác minh SHA-256 từng file
      trên endpoint khớp `kit.json`.
- [ ] Staging rules + `logtest-cases/` + driver logtest vào thư mục riêng trên
      manager (`~/aegis-v2/`), **chưa** cài.

## 2. Baseline

- [ ] Ghi nội dung `baseline.xml` vào đúng file demo (giữ inode/owner/mode); hash.
- [ ] **Root**: `wazuh-control restart`; ghi PID analysisd mới, `Total rules enabled`.
- [ ] **Root**: `bash ~/aegis-v2/aegis_logtest_v2.sh baseline` — mọi `demo_match`/
      `not_demo` PASS; hàng `parent_dependent` chỉ ghi nhận.
- [ ] Timestamped hash observation trước Run A (`date -u` + `sha256sum`).
- [ ] Run A (`lab_update.ps1`, label A, revision baseline). Run B
      (`maintenance_check.ps1`, label B, revision baseline). Run ID riêng mỗi run.
- [ ] Timestamped hash observation sau Run B.

## 3. Behavioral

- [ ] Backup file demo đang nạp (phải bằng baseline vừa cài), rồi ghi
      `behavioral.xml`; hash.
- [ ] **Root**: restart; ghi PID, rule count.
- [ ] **Root**: logtest `behavioral` — `reworded` PASS, `env-only`/`pid-only`
      PASS (not_demo), `comment-only` ghi nhận giới hạn.
- [ ] Hash observation trước Run C; Run C (label C, revision behavioral); hash
      observation sau.

## 4. Thu bằng chứng

- [ ] Trích `archives.json` theo agent, hai loại sự kiện trong scope, cửa sổ run
      + 300 s; lưu snapshot riêng từng run, ghi sha256 và `ingested_at`.
- [ ] Lưu execution manifests, stdout/stderr từng run về nơi private ngoài Git.
- [ ] Kiểm re-delivery, multi-part, lag, manager↔snapshot set identity.

## 5. Đánh giá

- [ ] Study v2 với `command_lines`/`canonical_paths` lấy từ Sysmon 1 **đo được**,
      không gõ tay; pins đủ 8 hash.
- [ ] `evaluate_demo_run` A/B/C; `compare_demo_runs` B→C. Ghi evidence IDs và
      `raw_event_ref`.
- [ ] Nếu cần attestation cho B: `prepare_collection_request` → trình nguyên văn
      request + draft approval (health/agent, filter, rotation, backlog, native,
      time có nguồn lịch sử) → **chủ dự án** điền `confirmed_by`, `reviewed_at`.
      Không tái dùng approval của snapshot khác.

## 6. Rollback

- [ ] Ghi lại nội dung pre-lab của file demo từ backup đã đối chiếu; hash.
- [ ] **Root**: restart; xác minh PID, rule count, hash của mọi file demo.
- [ ] Chỉ xoá lab directory trên endpoint sau khi manifests/evidence đã lưu đủ.

## 7. Bàn giao

- [ ] Checkpoint ghi: hashes, run IDs, verdicts với nhãn assurance, giới hạn,
      AC còn thiếu. Sanitize trước khi đưa bất kỳ evidence nào vào Git.
