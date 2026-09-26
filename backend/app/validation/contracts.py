"""Frozen, bounded evaluation inputs, independent of source parsing."""
from ipaddress import ip_address
from typing import Annotated, Literal

from pydantic import (AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field,
                      StrictBool, StrictInt, StrictStr, model_validator)
from pydantic_core import PydanticCustomError

from ..models.precise_timestamp import PreciseTimestamp
from .errors import ValidationEngineError

MAX_EVENTS = 10_000
MAX_COMPARISONS = 1_000_000
FILTER_FIELDS = frozenset({"source_type", "event_provider", "asset_id", "hostname", "username", "src_ip",
    "dst_ip", "src_port", "dst_port", "protocol", "process_name", "parent_process_name", "process_id",
    "command_line", "file_path", "file_hash", "rule_id", "signature_id", "event_action", "severity", "technique_ids",
    "session_key"})
TARGET_FIELDS = frozenset({"asset_id", "hostname", "username", "src_ip", "dst_ip", "src_port", "dst_port", "process_id"})
JOIN_FIELDS = FILTER_FIELDS - {"rule_id", "signature_id", "technique_ids"}
IP_FIELDS = frozenset({"src_ip", "dst_ip"})
INTEGER_FIELDS = frozenset({"src_port", "dst_port", "process_id", "severity"})
SOURCE_VALUES = frozenset({"wazuh", "suricata", "pfsense", "cowrie"})
ACTION_VALUES = frozenset({"observed", "allowed", "blocked", "redirected", "login", "command", "other"})


def bounded_text(value: str) -> str:
    if len(value.encode("utf-8")) > 4096:
        raise ValueError("text exceeds resource limit")
    return value


def ordered(value):
    if not isinstance(value, (list, tuple)):
        raise ValueError("expected list or tuple")
    return value


Text = Annotated[StrictStr, AfterValidator(bounded_text)]
NonBlank = Annotated[Text, Field(min_length=1, pattern=r"\S")]
Version = Annotated[StrictStr, Field(pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")]
Digest = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
Scalar = Text | StrictInt
ScalarList = Annotated[tuple[Scalar, ...], BeforeValidator(ordered), Field(min_length=1, max_length=100)]
Role = Literal["telemetry", "detection", "prevention"]
Outcome = Literal["satisfied", "missing_telemetry", "false_negative", "inconclusive"]
FinalStatus = Literal["Detected", "Prevented", "Missing telemetry", "False negative", "Inconclusive"]


def field_kind(field: str) -> str:
    return "ip" if field in IP_FIELDS else "integer" if field in INTEGER_FIELDS else "text"


def validate_scalar(field: str, value):
    """Validate a resolved literal; return an IP object only for IP comparisons."""
    if field in INTEGER_FIELDS:
        if type(value) is not int or value < 0 or (field in {"src_port", "dst_port"} and value > 65535):
            raise ValueError("invalid integer operand")
        return value
    if type(value) is not str:
        raise ValueError("expected text operand")
    bounded_text(value)
    if field == "source_type" and value not in SOURCE_VALUES:
        raise ValueError("invalid source operand")
    if field == "event_action" and value not in ACTION_VALUES:
        raise ValueError("invalid action operand")
    return ip_address(value) if field in IP_FIELDS else value


class FrozenContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True, revalidate_instances="always")


class Predicate(FrozenContract):
    field: NonBlank
    op: Literal["eq", "in", "exists", "contains"]
    value: Scalar | None = None
    values: ScalarList | None = None
    binding: NonBlank | None = None

    @model_validator(mode="after")
    def operands(self):
        if self.field not in FILTER_FIELDS:
            raise ValueError("unsupported predicate field")
        present = sum(x is not None for x in (self.value, self.values, self.binding))
        if self.op == "exists":
            if present:
                raise ValueError("exists has no operands")
        elif present != 1 or (self.op == "in" and self.value is not None) or (self.op != "in" and self.values is not None):
            raise ValueError("invalid operand combination")
        if self.op == "contains" and self.field != "technique_ids":
            raise ValueError("contains requires technique_ids")
        if self.field == "technique_ids" and self.op not in {"contains", "exists"}:
            raise ValueError("technique_ids requires contains or exists")
        for value in self.values if self.values is not None else (() if self.value is None else (self.value,)):
            validate_scalar(self.field, value)
        return self


class Binding(FrozenContract):
    name: NonBlank
    value: Scalar | ScalarList

    @model_validator(mode="after")
    def homogeneous(self):
        if isinstance(self.value, tuple) and len({type(v) for v in self.value}) != 1:
            raise ValueError("binding list must have one scalar type")
        return self


class JoinPair(FrozenContract):
    target_field: NonBlank
    anchor_field: NonBlank

    @model_validator(mode="after")
    def compatible(self):
        if self.target_field not in JOIN_FIELDS or self.anchor_field not in JOIN_FIELDS:
            raise ValueError("unsupported join field")
        if field_kind(self.target_field) != field_kind(self.anchor_field):
            raise ValueError("join fields must have the same scalar type")
        return self


class Correlation(FrozenContract):
    anchor_assertion_id: NonBlank
    join_pairs: Annotated[tuple[JoinPair, ...], BeforeValidator(ordered), Field(min_length=1, max_length=8)]
    min_delta_ns: StrictInt
    max_delta_ns: StrictInt

    @model_validator(mode="after")
    def interval(self):
        if self.min_delta_ns > self.max_delta_ns:
            raise ValueError("invalid correlation interval")
        return self


Conditions = Annotated[tuple[Predicate, ...], BeforeValidator(ordered), Field(max_length=16)]


class AssertionRule(FrozenContract):
    assertion_id: NonBlank
    role: Role
    capability: Literal["supported", "unsupported"]
    reason_code: NonBlank | None = None
    source_type: Literal["wazuh", "suricata", "pfsense", "cowrie"] | None = None
    scope: Conditions = ()
    match: Conditions = ()
    correlation: Correlation | None = None

    @model_validator(mode="after")
    def obligations(self):
        if self.capability == "unsupported":
            if self.reason_code is None or self.source_type is not None or self.scope or self.match or self.correlation is not None:
                raise ValueError("unsupported requires only role and reason")
            return self
        if self.reason_code is not None or self.source_type is None:
            raise ValueError("supported requires source and no unsupported reason")
        if not any(p.field in TARGET_FIELDS and p.op in {"eq", "in"} and p.binding is not None for p in self.scope):
            raise ValueError("scope requires explicit target binding")
        if (self.role == "telemetry") != (self.correlation is None):
            raise ValueError("only detection and prevention require correlation")
        conditions = self.scope + self.match
        if self.role == "detection" and not any(
            p.field in {"rule_id", "signature_id"} and p.op in {"eq", "in"}
            and p.binding is None and (p.value is not None or p.values is not None)
            for p in conditions
        ):
            raise ValueError("detection requires reviewed rule or signature IDs")
        if self.role == "prevention" and not any(p.field == "event_action" and p.op == "eq" and p.value == "blocked" for p in conditions):
            raise ValueError("prevention requires explicit blocked action")
        return self


class EvaluationProfile(FrozenContract):
    profile_schema_version: Literal["0.1.0"] = "0.1.0"
    profile_id: NonBlank
    profile_version: Version
    scenario_id: NonBlank
    scenario_version: Version
    scenario_fingerprint: Digest
    rules: Annotated[tuple[AssertionRule, ...], BeforeValidator(ordered), Field(min_length=1, max_length=100)]

    @model_validator(mode="after")
    def anchors(self):
        by_id = {rule.assertion_id: rule for rule in self.rules}
        if len(by_id) != len(self.rules):
            raise PydanticCustomError("assertion_binding", "duplicate assertion rule")
        for rule in self.rules:
            if rule.correlation is not None:
                anchor = by_id.get(rule.correlation.anchor_assertion_id)
                if anchor is None or anchor.role != "telemetry" or anchor.capability != "supported":
                    raise PydanticCustomError("invalid_correlation", "anchor must be a supported telemetry root")
        return self


def validate_rule_source(rule: AssertionRule, source: str) -> None:
    """Check declared canonical mapping; correctness of the provider literal needs review."""
    if rule.capability == "unsupported":
        return
    if source in {"sysmon", "powershell"}:
        valid = rule.source_type == "wazuh" and any(
            p.field == "event_provider" and p.op == "eq" and p.value is not None for p in rule.scope)
    else:
        valid = source in SOURCE_VALUES and rule.source_type == source
    if not valid:
        raise ValidationEngineError("assertion_binding", ("rules", "source_type"))


class CollectionDeclaration(FrozenContract):
    assertion_id: NonBlank
    status: Literal["unknown", "complete_for_scope"] = "unknown"
    confirmed_by: NonBlank | None = None
    reference: NonBlank | None = None
    coverage_start: PreciseTimestamp | None = None
    coverage_end: PreciseTimestamp | None = None
    no_sampling_or_truncation: StrictBool | None = None
    no_parse_errors_or_gaps: StrictBool | None = None
    clocks_adequate: StrictBool | None = None
    profile_fingerprint: Digest | None = None
    scope_fingerprint: Digest | None = None
    event_set_fingerprint: Digest | None = None

    @model_validator(mode="after")
    def assurance(self):
        confirmations = (self.no_sampling_or_truncation, self.no_parse_errors_or_gaps, self.clocks_adequate)
        if self.status == "complete_for_scope":
            if not all(v is True for v in confirmations) or any(getattr(self, field) is None for field in
                    ("confirmed_by", "reference", "coverage_start", "coverage_end", "profile_fingerprint", "scope_fingerprint", "event_set_fingerprint")):
                raise ValueError("complete collection requires all metadata and confirmations")
        if self.coverage_start is not None and self.coverage_end is not None and self.coverage_start > self.coverage_end:
            raise ValueError("invalid coverage interval")
        return self


class EvaluationContext(FrozenContract):
    run_id: NonBlank
    environment_id: NonBlank
    start: PreciseTimestamp
    end: PreciseTimestamp
    bindings: Annotated[tuple[Binding, ...], BeforeValidator(ordered), Field(max_length=100)] = ()
    declarations: Annotated[tuple[CollectionDeclaration, ...], BeforeValidator(ordered), Field(max_length=100)] = ()

    @model_validator(mode="after")
    def scope_valid(self):
        if self.start > self.end:
            raise ValueError("invalid evaluation interval")
        for values, key in ((self.bindings, "name"), (self.declarations, "assertion_id")):
            if len({getattr(value, key) for value in values}) != len(values):
                raise ValueError("duplicate context key")
        return self
