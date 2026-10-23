# AEGIS current-VM lab launcher — proposed design

Date: 2026-10-23. Status: proposed; awaiting owner review before implementation.
Branch: `codex/current-vm-lab-launcher`, based on the reviewed first-flow source
at `2df59c2b86092345967d4c75d0071042d8fb6b25`. This is a follow-up to draft
PR #152, not a declaration that #152 is merged or production accepted.

## Tóm tắt để chủ lab duyệt

**Phạm vi đã chọn:** chạy lại ba VM hiện có. Bạn bật VM và đăng nhập user Windows
đang giữ chứng thư như hiện nay. Gói này giúp vận hành lại luồng đã thử; không cài
lại hệ điều hành hoặc tạo danh tính mới.

**Cách dùng đề xuất:**

1. Cài bộ hỗ trợ một lần bằng lệnh ngắn cho từng vai trò. Manager có bản cập nhật
   tương thích cho các lệnh quản trị mới và thu evidence theo đúng UUID; bản cập
   nhật được kiểm hash, có backup và được review trước khi áp dụng.
2. Trên Windows máy thật, bấm đúp `Start-AEGIS.cmd`: kiểm lab, mở Manager/Admin và
   tunnel, chọn chuẩn bị lượt A/B/C hoặc thu/xuất evidence của UUID đã có.
3. Chọn rule Wazuh là thao tác rõ ràng, riêng biệt. Công cụ chỉ nhận hai revision
   đã duyệt, có backup/lint/restart/rollback; chặn phát job trong khi chuyển rule.
   Nếu kết quả đổi rule không rõ, giữ tạm dừng để bạn kiểm tra và khôi phục.
4. Mỗi lượt mới tạo UUID/draft mới, hạn bắt đầu 5 phút. Bạn duyệt đúng UUID trong
   Admin, rồi bấm đúp `Run-AEGIS-Agent.cmd` trên Windows Admin Soc. Shortcut dùng
   chứng thư của cùng user, chờ agent chạy xong và hiện trạng thái thực tế.
5. Công cụ tự chờ hết cửa sổ thu của UUID đó, gọi worker đúng job và xuất evidence
   cùng SHA-256/metadata. Kết quả vẫn giữ Detected/Inconclusive/failed đúng engine.

**Cấu hình:** dùng lại database, certificate, catalog và lịch sử. Địa chỉ, đường
 dẫn, mapping và hash của lab được giữ trong cấu hình private riêng. Mật khẩu SSH/
 sudo được nhập tại prompt khi cần; mật khẩu Indexer/DB và private key giữ ở nơi
 đang có. Không thêm WinRM, Windows Service/MSI hoặc chạy agent từ xa dưới user khác.

**Đóng gói:** ZIP tái sử dụng có version/hash và hướng dẫn tiếng Việt, tách khỏi
ZIP hồ sơ pilot/private config. Có test cho hành vi mới, review và một lượt lab
mới để kiểm sau khi cài hỗ trợ. B vẫn Inconclusive; hồ sơ cũ không bị đổi nhãn.

**Đề xuất của người triển khai:** dùng một gói với menu theo vai trò, thay vì một
nút chạy agent từ xa hoàn toàn; giữ ranh giới chứng thư CurrentUser đang hoạt động.
Các mục kỹ thuật bên dưới là bản thiết kế chi tiết của cùng phương án này.

## Intent and owner decisions

The owner wants the demonstrated Manager → Windows Admin Soc → Wazuh flow to
run again using a few commands or double-click entry points. The owner selected
**the existing three VMs**, rather than a fresh-machine installer. Preserve the
current identities, PostgreSQL database, enrollment, certificates and catalog.
The user should no longer paste per-job Python or calculate collection times.

The pilot dossier is closed separately as an owner-accepted single-Windows-VM
first-flow demonstration with documented limitations. Its observed sequence is
A Detected, B Inconclusive, C Detected. Its B→C comparison remains Inconclusive;
its A→C comparison is Unchanged pass. Real addresses, usernames, fingerprints,
job IDs, raw evidence and detailed acceptance records stay private, outside Git.

## Approaches

1. **Fresh-install wizard:** install OS dependencies, DB, HTTPS and enrollment
   again. The owner did not select this; it would risk replacing working state.
2. **One fully remote Windows controller:** remotely start the guest agent from
   the host. The current agent uses its existing guest user's nonexportable
   CurrentUser certificate. Fully remote execution would require a new transport
   or service identity that has not been deployed or reviewed.
3. **One package with role-specific entry points:** a host Windows menu controls
   the Manager/Wazuh owner operations over existing SSH; a guest Windows shortcut
   runs the foreground agent locally with its existing certificate. Linux support
   tools expose short, closed commands. This fits the existing deployment.

The owner's selection fixes current-VM reuse. Approach 3 and its exact file/menu
names below are the implementer's proposed choice for owner review, since the
current certificate boundary makes it the smallest practical solution.

## What the owner sees

The owner powers on the three existing VMs and signs in to the same Windows guest
user as today. Hypervisor power/snapshot control is outside this package.

- **Physical Windows host:** double-click `Start-AEGIS.cmd`. A Vietnamese menu
  offers check/open lab, prepare A/B/C, collect/export an existing job, and status.
  It opens the existing HTTPS Admin and shows the selected fresh job UUID. SSH
  and sudo passwords are entered interactively in their normal prompts when
  required; neither passwords nor session tokens are stored by the launcher.
- **Windows Admin Soc guest:** double-click `Run-AEGIS-Agent.cmd` after Admin
  approval. It checks the configured host/user/certificate/catalog, displays the
  expected wait of roughly 2–3 minutes, polls once and waits for the real process
  to finish. It shows execution/receipt state separately from the CLI exit code.
- **Manager/Wazuh Linux:** installed support tools have short status/maintenance
  commands. The Windows host menu calls the same commands over pinned SSH. A
  local Linux invocation remains available if the host menu cannot connect.

The only per-run manual approval is still the authenticated **Approve selected
bounded jobs** action in Admin. A double-click must never imply job approval.
A separate explicit selection of the Wazuh revision authorizes that rule change.

## Normal repeat flow

1. `Check/open lab` checks configured mapping, HTTPS, service state, certificate
   validity, clocks and the protected catalog. It starts the existing Manager/
   nginx services when needed and opens a visible foreground Indexer tunnel.
   The tunnel keeps loopback binding, strict SSH host verification and normal
   Indexer CA/hostname validation. Existing healthy listeners are reused only
   after verifying ownership/endpoint; an occupied unknown listener is an error.
2. `Prepare A`, `Prepare B` or `Prepare C` uses the established mapping, release
   and frozen pins. A/B select baseline; C selects behavioral. The installed
   Wazuh revision is checked against the chosen revision before creating a job.
   Rule changes use the separate reviewed maintenance operation below.
3. A new generic Manager operator creates a fresh UUID/draft with the same
   bounded policy: five-minute start window, timeout from the approved release,
   collection start 30 seconds earlier, collection end covering expiry+timeout,
   total at most 900 seconds. UTC comes from the synchronized Manager clock.
   It emits the UUID, review URL, expiry and collection-ready time as JSON.
4. The owner reviews and approves that exact UUID in Admin. The launcher shows
   queued only after checking the persisted state; it never fabricates approval.
5. On the guest, the owner double-clicks the agent shortcut. Wrong VM/user,
   expired certificate, wrong pin or clock failure stops before polling. No
   change to the signed job protocol or scenario payload is needed.
6. The owner selects `Collect/export` for that same UUID. The tool checks actual
   execution success, waits until its signed collection_end plus the normal
   settle delay, collects **only that UUID**, and checks its real terminal state.
   An evaluated result is shown with the engine's actual verdict and evidence
   references. Empty/failed/Inconclusive retain their existing meanings.
7. A new private output archive and SHA-256 are produced and downloaded to the
   configured owner output directory. A compact selected job/approval/receipt/
   audit snapshot accompanies the evidence archive, without env/reader secrets.
   The guest can separately export its selected journal/run files locally.

A small private local history maps menu operations to UUIDs and timestamps. It
is a convenience index, not an authority or a substitute for Manager records.
Every repeat run reads fresh Manager state. An unapproved untouched unexpired
matching draft may be resumed without extending its expiry. Approved, started,
failed, ambiguous or collected work is never silently reused or rerun. Expired
unstarted work is cancelled through the normal owner operation before a fresh
UUID is created. Failed/ambiguous work follows the existing explicit journal
review/reconciliation process; the launcher preserves all historical records.

## Wazuh rule maintenance

The installed pilot helper only performs one baseline→behavioral transition;
it cannot be repurposed unchanged as a repeat-cycle installer. New support must
handle both directions between the two approved revision hashes only.

- Selecting a revision is an explicit owner operation, separate from opening
  the lab or running the agent. No arbitrary XML path/content is accepted.
- Hold a Manager dispatch maintenance gate for the whole transition. Normal
  approval/claim and launcher draft creation must respect it. Before writing,
  require no queued/leased/started job, unresolved failed execution, collecting
  worker or uncollected successful job. Previously reconciled terminal work is
  historical and does not block. If Manager state cannot be checked, refuse.
- The gate is durable and visible; loss of SSH/process or an uncertain Wazuh
  result leaves dispatch paused for owner review. Normal successful postchecks
  release it. Recovery is explicit; no automatic resume after ambiguity.
- The Wazuh root-owned helper verifies private role config, exact installed
  revision/metadata, closed approved baseline/behavioral artifacts and absence
  of conflicting rule IDs. Snapshot trusted bytes into root-owned storage before
  execution. Never execute a mutable soc-owned uploaded root script directly.
- Keep a fresh protected backup before replacement; use lock+atomic replacement,
  configuration test, controlled Manager restart, active-state and hash checks.
  A post-write error attempts restoration of the exact prior bytes/metadata and
  repeats the postchecks. Report rollback failure or ambiguity explicitly.
- A healthy already-selected revision is a verified no-op. Never replace vendor
  rules or rewrite the existing historical rule backup/release metadata.

The maintenance-gate mechanism is a builder choice, but its durable semantics
and participation by Admin approval/claim are acceptance requirements. This is
narrow coordination for one owner and one lab, not a distributed campaign system.

## Implementation boundaries

Reuse the existing Django Manager/PostgreSQL, foreground self-contained Windows
agent, PowerShell 5.1, OpenSSH, systemd and Wazuh helpers. Add no dependency unless
a concrete requirement cannot be met with those runtimes.

New work is limited to:

- generic validated Manager owner commands for status/draft/selected lifecycle
  export and rule-maintenance coordination;
- a target-job option for the collection worker, retaining existing default queue
  behavior for existing callers and its DB/OS locks;
- root-owned configurable Linux wrappers and a bidirectional two-revision Wazuh
  maintenance helper;
- host/guest PowerShell entry points, private-configuration validation, process
  ownership/status handling and packaging/version/checksum instructions;
- targeted unit/integration/packaging tests and operator documentation.

Do not change scenario ground truth, canonical schema, connector parsing,
validation verdicts, mTLS/signed-job semantics or existing report assurance.
Do not reuse the one-off pilot draft helpers as a generic repeated-run path.
No Windows Service/MSI, WinRM, new remote arbitrary-shell agent, account reset,
new certificate issuance, VM creation, CA export, new fleet or unattended campaign.

## Configuration and privilege

Public source/package templates contain no real lab address, password, connector
URL, certificate, raw evidence or target identity. Use explicit user-selected
private config for Manager/Wazuh SSH aliases, HTTPS hostname, local paths,
expected guest name/user, device/release mapping, reviewed pins and output paths.
The current owner's config can be prepared locally from the already reviewed
lab values and shipped separately in a marked private folder; it is not committed.

Keep DB and Indexer credentials in their existing protected Manager files; keep
private keys in existing files/certificate stores. SSH uses existing authentication
and verified known-hosts. Do not disable TLS checks, use password command-line
arguments, store passwords in JSON, change the hosts file or import trust roots
just to open the existing installation. Log fixed diagnostics and selected safe
metadata; do not echo environment/reader configs or raw exception contents that
could contain credentials.

Install support once using a verified package manifest and a small role-specific
command. Root copies and verifies support bytes into an owned staging directory
before installation. Existing database, certificates, releases, catalog, rule
backups, journal and evidence are preserved. Updates install a versioned support
release and retain rollback information; they do not silently upgrade the working
Manager core. The new Manager commands/worker coordination require an explicitly
reviewed compatible application update to these VMs, with backup and version
checks. The initial setup step is distinct from normal double-click reuse.

Each wrapper owns only processes it starts. Closing a tunnel must not kill an
unrelated SSH process. Guest cancellation keeps existing owned-runner cleanup
and journal semantics; it is shown as interruption/failure and requires review,
not converted to success. Windows guest actions stay under its certificate user.

## Acceptance criteria

1. On these already provisioned VMs, one verified support installation per role
   leads to a host menu and guest shortcut; normal runs do not require pasted
   Python, hand-set UUIDs or manual collection timestamps.
2. Read-only preflight and error paths work with configurable paths containing
   spaces, wrong host/user, missing certificate, stale config, occupied tunnel,
   expired draft, unsynchronized clock and disconnected SSH/TLS failures.
3. Draft creation is repeatable across completed histories, uses fresh UUIDs and
   bounded windows, refuses unresolved work and never signs/approves itself.
4. Collection cannot select another pending job when an exact UUID was requested;
   early collection waits correctly and existing untargeted worker behavior stays
   compatible. Interrupted/failed work and immutable output are retained.
5. Both Wazuh revision directions and verified no-op work with protected backup,
   correct ownership, real config/service/hash postchecks and rollback. Dispatch
   is paused during changes and remains paused when the final state is unknown.
6. Packaging tests check the selected files/entry points, manifest/ZIP bytes,
   no real secrets/evidence in the reusable public package, and accurate result
   labels. Fixture tests never need the live lab; new behavior has targeted tests.
7. Human lab validation exercises one fresh owner-approved run after support
   installation, observes foreground completion and targeted collection/export,
   and can trace the new report to EIDs. It does not relabel the historical B.
8. The operator guide states what is installed once, what to click each run,
   which password prompts may appear and how to stop/recover without deleting
   journal/evidence. Release notes identify source version, test scope and pending
   live gates rather than declaring production readiness.

## Delivery and review

The private pilot dossier is delivered immediately and independently. After
approval of this design, create a focused follow-up GitHub issue using these
acceptance criteria, write the implementation plan, implement/test/review on this
focused branch, and produce a reusable versioned support ZIP plus a separate
private lab config. Keep raw pilot files outside Git and preserve the original
October21 build metadata. PR #152 and the new follow-up require their own human
review/lab gates; no automatic merge is part of this request.

## Builder decisions intentionally left open

Exact CLI/file/menu names, config model names, persistence layout of the local
UUID convenience index, implementation of the durable maintenance gate, layout
of versioned support installation and test splits are builder decisions subject
to the behavioral and privilege contracts above. No new framework is required.
