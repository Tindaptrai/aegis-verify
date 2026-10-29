"""Dedicated nft table and persistent systemd guard rendering/verification."""
from .contracts import Profile, SetupError


TABLE = "aegis_wazuh_http_v1"
PROFILE = "/etc/wazuh-indexer/aegis-http/profile.json"
ENTRYPOINT = "/usr/local/lib/aegis-wazuh-https/Setup-Wazuh-HTTPS.py"


def firewall_text(p: Profile) -> str:
    return f'''table inet {TABLE} {{
    chain input {{
        type filter hook input priority -50; policy accept;
        ip daddr {p.indexer_ip} tcp dport 9200 iifname "lo" accept
        ip daddr {p.indexer_ip} tcp dport 9200 ip saddr {p.manager_ip} accept
        ip daddr {p.indexer_ip} tcp dport 9200 drop
    }}
}}
'''


def _expected(p: Profile) -> list:
    def match(left, right):
        return {"match": {"op": "==", "left": left, "right": right}}
    def payload(protocol, field):
        return {"payload": {"protocol": protocol, "field": field}}
    dest = [match(payload("ip", "daddr"), p.indexer_ip), match(payload("tcp", "dport"), 9200)]
    base = {"family": "inet", "table": TABLE, "chain": "input"}
    return [
        {"table": {"family": "inet", "name": TABLE}},
        {"chain": {"family": "inet", "table": TABLE, "name": "input", "type": "filter", "hook": "input", "prio": -50, "policy": "accept"}},
        {"rule": dict(base, expr=dest + [match({"meta": {"key": "iifname"}}, "lo"), {"accept": None}])},
        {"rule": dict(base, expr=dest + [match(payload("ip", "saddr"), p.manager_ip), {"accept": None}])},
        {"rule": dict(base, expr=dest + [{"drop": None}])},
    ]


def verify_table(document: dict, p: Profile) -> None:
    """Compare every semantic object; ignore only nft metadata and handles."""
    try:
        if type(document) is not dict or set(document) != {"nftables"} or type(document["nftables"]) is not list:
            raise ValueError
        clean = []
        for obj in document["nftables"]:
            if type(obj) is not dict or len(obj) != 1:
                raise ValueError
            kind, body = next(iter(obj.items()))
            if kind == "metainfo":
                continue
            if kind not in {"table", "chain", "rule"} or type(body) is not dict:
                raise ValueError
            clean.append({kind: {k: v for k, v in body.items() if k != "handle"}})
        if clean != _expected(p):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        raise SetupError("firewall_mismatch") from None


def guard_unit() -> str:
    return f'''[Unit]
Description=AEGIS Wazuh HTTP firewall guard
After=network-pre.target nftables.service
Before=wazuh-indexer.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
Group=root
ExecStart=/usr/bin/python3 {ENTRYPOINT} guard-ensure --profile {PROFILE}

[Install]
WantedBy=multi-user.target
'''


def indexer_dropin() -> str:
    return f'''[Unit]
Requires=aegis-wazuh-http-guard.service
After=aegis-wazuh-http-guard.service

[Service]
ExecStartPre=+/usr/bin/python3 {ENTRYPOINT} guard-verify --profile {PROFILE}
'''
