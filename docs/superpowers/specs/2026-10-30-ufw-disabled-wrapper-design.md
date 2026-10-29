# Disabled-policy UFW wrapper compatibility

Issue #163. This amends the optional HTTP operator design, not application
startup or active firewall-policy management. The owner approved the privately
reviewed amendment on 2026-10-30. Deployment facts remain outside Git.

## Approach and limits

Support one qualified Ubuntu UFW 0.36.2-6 wrapper whose policy is disabled while
its root oneshot unit remains active/enabled. Preserve UFW completely. Retaining
the old blanket refusal with a loopback tunnel remains an alternative; disabling
UFW merely to bypass admission was rejected. Existing HTTPS deployments still
skip the entire optional operator kit.

This exception requires the existing trusted-root/installed-package boundary.
Local package checksums prove consistency with local package metadata, not
independent authenticity or protection against compromised root. Unknown vendor
versions, custom wrapper behavior and active policy remain unsupported.

## Required admission

- Use bounded no-follow reads, root ownership, regular/single-link files and no
  group/world writes. Handle only explicitly allowed standard distro aliases.
- Qualify installed init scripts, unit and default configuration against the
  trusted package references and reviewed source semantics. Parse configuration
  as data; never source it. Require a closed literal/comment grammar for
  `ufw.conf`, exact `ENABLED=no`, expected keys and no duplicate assignments,
  substitutions, includes or commands. Freeze complete file hashes/metadata.
- Permit only the reviewed nonexecutable root-owned hooks; never execute hooks
  or `ufw-init status` as a probe. Unknown or executable/custom hooks refuse.
- Require exact effective root oneshot/RemainAfterExit unit semantics, normal
  `ufw-init start quiet` and `ufw-init stop`, no drop-ins, injected environment,
  pre/post commands or reload command. Omitted arrays require independent typed
  D-Bus confirmation, never missing-value inference. Refuse dirty, transient,
  reloading or pending unit work. The exception admits active/exited + enabled;
  the original inactive/disabled path remains separate.
- Require actual selected IPv4/IPv6 nf_tables backend identities and a complete
  current nft baseline. An inactive CLI message is not an empty-ruleset proof.
  After wrapper/backend qualification, require a fresh bounded complete native
  `nft --json list ruleset` observation and closed `ENABLED=no`. Initially admit
  only coherent, unique metainfo/table/chain/rule shapes; unknown object kinds,
  families, malformed identities or dangling references refuse. Reject every
  `ufw-`/`ufw6-` chain across admitted families/tables, including partial leftovers.
  Compare the same fresh foreign baseline with earlier facts and re-read static
  inputs for consistency. Never authorize from a cached caller dictionary alone.
  Do not execute `ufw status`, compatibility list/save commands, `ufw-init status`
  or a hook, and do not claim observed CLI inactivity.
  Strictly reject other conflicting active/enabled loaders. A finite inventory
  does not prove the absence of arbitrary root automation.

The original CLI-status mechanism is superseded by this stricter kernel-state
predicate. The exact Ubuntu package opens its runtime lock with write/truncate
mode even for status; its dry-run only prints planned checks. Removing that
execution preserves the owner's no-mutation requirement. This is deliberately
more restrictive than the CLI's missing-first-chain status, not an emulation of
the CLI or proof about legacy rules outside the qualified nf_tables backend.
Valid foreign ordinary policy is retained; unsupported shapes require separate
review, never automatic repair. Probe identity is exactly
`{"method":"nft-no-ufw-chains-v1"}`; old status-based records refuse without
migration or automatic refresh.

## Persistence and lifecycle

Persist a closed, versioned compatibility record at
`/etc/aegis-wazuh-https/ufw-compat.json`, root-owned 0600 under the existing root
0700 policy directory. Bind it to the installation profile and the frozen static
fingerprint. Include hashes and relevant ownership/mode/size, package references,
effective static unit facts and selected backend identities; exclude volatile
PIDs, boot times, counters and inode/device values from the persistent identity.
Still validate current file descriptors/metadata during each read.

Cover the record by check/apply digests, install it durably before arming guard,
and repeat eligibility plus fingerprint verification before guard-ensure and
every Indexer guard-verify. Missing or changed evidence refuses; never refresh
the fingerprint automatically. No exception is available from an uninstalled
or absent compatibility record during startup.

Order BOTH the owned guard and Indexer drop-in `After=ufw.service`. Keep existing
guard Requires/After and the privileged every-start verifier. Add no Wants or
Requires for UFW, so the kit never causes UFW to start. Validate ordering/cycles.
The owned table, exact source/destination/port restriction and all other rules
remain unchanged. Normal qualified disabled-wrapper operations must preserve it.

Preserve every UFW file, hook, unit, enablement state and rule. Never stop,
restart, reload, enable, disable, repair or flush UFW from the kit. Restart only
Indexer under the original reviewed maintenance flow. Rollback restores HTTP
configuration/drop-in and verifies old localhost service before removing only
the owned table; uncertainty retains guard/evidence. It never restores UFW.

Ordering and next-start checks are not continuous protection against arbitrary
root changes. Before policy/package/hook/backend changes or force-stop/flush-all,
return Indexer to the approved safe maintenance state and requalify. Do not claim
that a later refusal closes an earlier exposure created by root while serving.

## Qualification and delivery

Unit tests cover positive disabled admission and hostile config, metadata,
package, arrays, environment, backend, transient-work and drift cases. Native
Linux tests use the exact vendor wrapper in owned filesystem/network/unit
fixtures with synthetic inputs: normal stop/restart/reload, concurrent wrapper
and Indexer start, cold/active guard, deleted/modified table, fingerprint drift,
no unintended UFW start, unchanged foreign rules and verified cleanup. Never
mutate the CI host's default firewall or real UFW/Wazuh unit/configuration.

Qualified source requires all old and new native IDs, no skips/errors/failures,
canonical byte hashes and unchanged host-firewall evidence. Real vendor,
Manager/denied-source/Dashboard/readiness acceptance remains separate; reboot
still requires separate permission. Rebuild a new pinned private check ZIP from
qualified Git bytes; keep previous owner stages/evidence and never patch them
in place. No CA/key/archive/credential, account/binding, scenario or merge change.

Native fixtures with different roots, fragments or argv must not be disguised
as an admitted stock unit. Separate real vendor lifecycle/packet/ordering proof,
real adapter/D-Bus reads, and explicitly synthetic positive-admission logic.
Such fixtures correctly refuse full production classification. Declare any
namespace-scoped loader identity mappings and preserve returned facts. Full
positive vendor admission remains a mandatory owner read-only check before
apply; passing a synthetic CI gate does not establish that result.

## Primary sources

- https://archive.ubuntu.com/ubuntu/pool/main/u/ufw/ufw_0.36.2.orig.tar.gz
- https://archive.ubuntu.com/ubuntu/pool/main/u/ufw/ufw_0.36.2-6_all.deb
- https://archive.ubuntu.com/ubuntu/pool/main/u/ufw/ufw_0.36.2-6.debian.tar.xz
- https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html
- https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html
- https://netfilter.org/projects/nftables/manpage.html
- https://manpages.ubuntu.com/manpages/noble/man8/xtables-nft.8.html
