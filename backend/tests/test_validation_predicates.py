"""Independent typed predicate and join truth tables."""
import importlib
import pytest
from pydantic import ValidationError
from validation_cases import event


def modules():
    return (importlib.import_module("aegis_verify.validation.contracts"),
            importlib.import_module("aegis_verify.validation.predicates"))


@pytest.mark.parametrize("data", [
    dict(field="event_id", op="exists"), dict(field="command_line", op="contains", value="x"),
    dict(field="hostname", op="eq"), dict(field="hostname", op="exists", value="x"),
    dict(field="hostname", op="eq", value="x", binding="x"),
    dict(field="hostname", op="in", value="x"), dict(field="hostname", op="eq", values=["x"]),
    dict(field="hostname", op="in", values=[]), dict(field="hostname", op="in", values=iter(["x"])),
    dict(field="hostname", op="eq", value=True), dict(field="hostname", op="eq", value=1.0),
    dict(field="hostname", op="eq", value=None), dict(field="hostname", op="eq", value=1),
    dict(field="src_port", op="eq", value="22"), dict(field="src_port", op="eq", value=65536),
    dict(field="src_ip", op="eq", value="bad"), dict(field="process_id", op="eq", value=-1),
    dict(field="severity", op="eq", value=-1), dict(field="event_action", op="eq", value="detected"),
    dict(field="source_type", op="eq", value="sysmon"), dict(field="hostname", op="eq", value="é" * 2049),
    dict(field="technique_ids", op="eq", value="T1000"),
])
def test_reject_invalid_operands(data):
    c, _ = modules()
    with pytest.raises(ValidationError):
        c.Predicate(**data)


def test_binding_and_operand_limits():
    c, _ = modules()
    for value in (True, 1.0, None, {"x": 1}, iter([1]), "é" * 2049, [1, "x"]):
        with pytest.raises(ValidationError):
            c.Binding(name="x", value=value)
    assert c.Binding(name="x", value=[1, 2]).value == (1, 2)
    assert c.Predicate(field="hostname", op="eq", value="é" * 2048).value == "é" * 2048
    assert len(c.Predicate(field="hostname", op="in", values=["x"]*100).values) == 100
    with pytest.raises(ValidationError):
        c.Predicate(field="hostname", op="in", values=["x"]*101)


@pytest.mark.parametrize("changes,conditions,want", [
    ({}, [dict(field="rule_id", op="eq", value="reviewed-rule")], "unknown"),
    ({}, [dict(field="rule_id", op="exists")], "false"),
    ({}, [dict(field="hostname", op="eq", value="synthetic-host")], "true"),
    ({}, [dict(field="hostname", op="eq", value="Synthetic-host")], "false"),
    ({}, [dict(field="hostname", op="eq", value="synthetic-host ")], "false"),
    ({}, [dict(field="rule_id", op="eq", value="r"), dict(field="hostname", op="eq", value="other")], "false"),
    ({"src_ip": "2001:db8::1"}, [dict(field="src_ip", op="eq", value="2001:0db8:0:0:0:0:0:1")], "true"),
    ({"technique_ids": ["T1000.001"]}, [dict(field="technique_ids", op="contains", value="T1000")], "false"),
    ({"technique_ids": ["T1000.001"]}, [dict(field="technique_ids", op="contains", value="T1000.001")], "true"),
])
def test_truth_table(changes, conditions, want):
    c, p = modules()
    assert p.evaluate_conditions(event(**changes), tuple(c.Predicate(**item) for item in conditions), {}).value == want


def test_bindings_resolve_explicitly_and_check_domain():
    c, p = modules()
    from aegis_verify.validation.errors import ValidationEngineError
    condition = c.Predicate(field="hostname", op="eq", binding="target")
    assert p.evaluate_conditions(event(), (condition,), {"target": "synthetic-host"}) is p.Truth.TRUE
    for bindings, code in (({}, "missing_binding"), ({"target": 1}, "invalid_predicate"),
                           ({"target": ["synthetic-host"]}, "invalid_predicate")):
        with pytest.raises(ValidationEngineError) as caught:
            p.evaluate_conditions(event(), (condition,), bindings)
        assert caught.value.code == code


def test_join_domains_limits_and_null_semantics():
    c, p = modules()
    for field in ("rule_id", "signature_id", "event_id", "raw_event_ref", "technique_ids", "timestamp"):
        with pytest.raises(ValidationError):
            c.JoinPair(target_field=field, anchor_field=field)
    with pytest.raises(ValidationError):
        c.JoinPair(target_field="hostname", anchor_field="src_port")
    pair = c.JoinPair(target_field="hostname", anchor_field="asset_id")
    assert p.evaluate_joins(event(), event(asset_id="synthetic-host"), (pair,)) is p.Truth.TRUE
    assert p.evaluate_joins(event(), event(), (pair,)) is p.Truth.UNKNOWN
    join = dict(target_field="hostname", anchor_field="hostname")
    for delta in (dict(min_delta_ns=True, max_delta_ns=1), dict(min_delta_ns=2, max_delta_ns=1)):
        with pytest.raises(ValidationError):
            c.Correlation(anchor_assertion_id="x", join_pairs=[join], **delta)
    assert len(c.Correlation(anchor_assertion_id="x", join_pairs=[join]*8, min_delta_ns=-1, max_delta_ns=1).join_pairs) == 8
    with pytest.raises(ValidationError):
        c.Correlation(anchor_assertion_id="x", join_pairs=[join]*9, min_delta_ns=-1, max_delta_ns=1)


def test_numeric_and_in_bindings_keep_exact_types_at_domain_edges():
    c, p = modules()
    for port in (0, 65535):
        predicate = c.Predicate(field="src_port", op="in", binding="ports")
        assert p.evaluate_conditions(event(src_port=port), (predicate,), {"ports": (port,)}) is p.Truth.TRUE
    for field in ("process_id", "severity"):
        assert p.evaluate_conditions(event(**{field: 0}), (c.Predicate(field=field, op="eq", value=0),), {}) is p.Truth.TRUE
    assert p.evaluate_conditions(event(rule_id="reviewed"), (c.Predicate(field="rule_id", op="in", values=["other", "reviewed"]),), {}) is p.Truth.TRUE
    assert p.evaluate_conditions(event(), (c.Predicate(field="rule_id", op="in", values=["reviewed"]),), {}) is p.Truth.UNKNOWN
    assert p.evaluate_conditions(event(), (c.Predicate(field="technique_ids", op="contains", value="T1000"),), {}) is p.Truth.UNKNOWN
    assert p.evaluate_conditions(event(), (), {}) is p.Truth.TRUE
    assert p.evaluate_conditions(event(), (c.Predicate(field="hostname", op="exists"),), {}) is p.Truth.TRUE


def test_false_dominates_unknown_in_both_condition_and_join_orders():
    c, p = modules()
    conditions = (c.Predicate(field="rule_id", op="eq", value="r"), c.Predicate(field="hostname", op="eq", value="other"))
    pairs = (c.JoinPair(target_field="asset_id", anchor_field="asset_id"), c.JoinPair(target_field="hostname", anchor_field="hostname"))
    for ordered in (conditions, tuple(reversed(conditions))):
        assert p.evaluate_conditions(event(), ordered, {}) is p.Truth.FALSE
    for ordered in (pairs, tuple(reversed(pairs))):
        assert p.evaluate_joins(event(), event(hostname="other"), ordered) is p.Truth.FALSE
    ip_pair = c.JoinPair(target_field="src_ip", anchor_field="dst_ip")
    assert p.evaluate_joins(event(src_ip="2001:db8::1"), event(dst_ip="2001:0db8:0:0:0:0:0:1"), (ip_pair,)) is p.Truth.TRUE
