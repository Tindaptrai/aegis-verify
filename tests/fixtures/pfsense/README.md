# pfSense fixtures

Seven sanitized, single-line derivatives from a user-provided offline pfSense
filterlog export are recorded in `manifest.json`. The original stays outside Git.
The manifest records its whole-file SHA-256, each original physical line/hash,
the allowed substitutions, each derivative hash and its immutable source label.
No reverse alias map or original network identifiers are stored here.

| Original line | Derivative | Expected outcome |
| --- | --- | --- |
| 1 | `rotation.sanitized.log` | skipped: rotation_notice |
| 2 | `udp-block.sanitized.log` | parsed: IPv4 UDP blocked |
| 38 | `igmp.sanitized.log` | skipped: unsupported_protocol |
| 39 | `ipv6-options.sanitized.log` | skipped: unsupported_ip_version |
| 45 | `ipv6-udp.sanitized.log` | skipped: unsupported_ip_version |
| 726 | `tcp-block.sanitized.log` | parsed: IPv4 TCP blocked |
| 296 | `malformed-header.sanitized.log` | error: malformed_header |

Hostnames (both occurrences in the malformed record), program PIDs, tracker and
interface identifiers, and all source/destination addresses use consistent aliases.
Four distinct source interfaces require `fixture0` through `fixture3`. Address
aliases use documentation ranges and do not preserve routing, multicast, scope,
asset identity or NAT meaning. Every other byte is preserved, including timestamp,
action, ports, sequence ranges, empty cells, and the malformed header structure.
The source contains no reliable NAT correlation; the parser keeps NAT context null.

All seven files intentionally retain LF bytes. The IGMP record also retains one
space immediately before LF. The local `.gitattributes` prevents newline conversion
and exempts this intentional trailing space. Do not trim or normalize these files:
the line hashes include exact whitespace and newline bytes. Staged Git object
bytes were compared with working files and manifest hashes during preparation.

Each file is a distinct immutable artifact. Its `source_ref` includes its derivative
SHA-256; parser references end in `#L1-L1` because each derivative has one physical
line. Original line positions are lineage in the manifest, not derivative line
indexes. A changed artifact needs an updated hash/source label and explicit review.

Replay uses explicit caller year 2026 and fixed offset +07:00, with the source-clock
comparison described in the design document. Neither was present in the raw BSD
timestamp, and historical clock correctness remains unverified. `ingested_at` is
fixture replay context, not an observed source event or the original export time.

The original has 1,592 physical lines. Strict whole-file parsing rejects the
concatenated/partial header at line 296 (`malformed_header`); streaming yields 295
outcomes before the same error and the ingestion is **INCOMPLETE**. An independent
per-line coverage audit accounts for 1,402 parsed, 189 skipped (69 unsupported
protocol, 119 unsupported IPv6, one rotation), and one error. This audit is not a
successful whole-file import; the malformed line has not been repaired or salvaged.

There are no observed pass records in the supplied export. Pass coverage remains
explicitly synthetic in backend unit tests and requires separate human/lab
validation. A recorded firewall block is a source fact, not a scenario prevention
verdict. No scenario ground truth is changed by these fixtures.
