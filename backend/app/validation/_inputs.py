"""Public evaluator trust boundary; no evidence reference is dereferenced."""
from pydantic import ValidationError

from ..models.canonical_event import CanonicalEvent
from ..models.canonical_event_v2 import CanonicalEventV2
from ..models.scenario import ScenarioManifest
from .contracts import EvaluationContext, EvaluationProfile, validate_rule_source
from .errors import ValidationEngineError
from .predicates import resolve_operand
from .results import (_plain_fields, event_set_fingerprint, fingerprint, profile_fingerprint,
                      scenario_fingerprint, scope_fingerprint, validated_events)


def _budgets(value, path=()):
    limits = {"rules": 100, "assertions": 100, "scope": 16, "match": 16,
              "join_pairs": 8, "bindings": 100, "declarations": 100, "values": 100, "value": 100}
    if isinstance(value, dict):
        for key, item in value.items():
            if key in limits and isinstance(item, (tuple, list)) and len(item) > limits[key]:
                raise ValidationEngineError("resource_limit", path + (key,))
            _budgets(item, path + (key,))
    elif isinstance(value, (tuple, list)):
        for index, item in enumerate(value):
            _budgets(item, path + (index,))
    elif path[0] != "manifest" and isinstance(value, str) and len(value.encode("utf-8")) > 4096:
        raise ValidationEngineError("resource_limit", path)


def _contract(value, model_type, path):
    if type(value) is not model_type:
        raise ValidationEngineError("invalid_input", (path,))
    try:
        plain = _plain_fields(value)
        _budgets(plain, (path,))
        if model_type is EvaluationProfile and plain.get("profile_schema_version") != "0.1.0":
            raise ValidationEngineError("unsupported_version", (path, "profile_schema_version"))
        return model_type.model_validate(plain)
    except ValidationEngineError:
        raise
    except ValidationError as exc:
        errors = exc.errors(include_input=False, include_context=False)
        locations = [error["loc"] for error in errors]
        code = "invalid_input"
        if any(error["type"] == "too_long" for error in errors):
            code = "resource_limit"
        elif path == "context" and any("declarations" in loc for loc in locations):
            code = "invalid_collection_declaration"
        elif path == "profile":
            if any(error["type"] == "assertion_binding" for error in errors):
                code = "assertion_binding"
            elif any(error["type"] == "invalid_correlation" for error in errors) or any("correlation" in loc for loc in locations):
                code = "invalid_correlation"
            elif any("scope" in loc or "match" in loc for loc in locations):
                code = "invalid_predicate"
        raise ValidationEngineError(code, (path,) + locations[0]) from None
    except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
        raise ValidationEngineError("invalid_input", (path,)) from None


def _profile_relations(manifest, profile, manifest_fingerprint):
    if (profile.scenario_id != manifest.id or profile.scenario_version != manifest.version or
            profile.scenario_fingerprint != manifest_fingerprint):
        raise ValidationEngineError("profile_binding", ("profile",))
    rules = {rule.assertion_id: rule for rule in profile.rules}
    if set(rules) != {assertion.id for assertion in manifest.assertions}:
        raise ValidationEngineError("assertion_binding", ("rules",))
    required_role = "detection" if manifest.expected_outcome == "detected" else "prevention"
    if not any(rule.role == required_role for rule in profile.rules):
        raise ValidationEngineError("assertion_binding", ("rules",))
    return rules


def validate_manifest_profile(manifest, profile):
    """Check static compatibility without evidence, run bindings or evaluation."""
    manifest = _contract(manifest, ScenarioManifest, "manifest")
    profile = _contract(profile, EvaluationProfile, "profile")
    rules = _profile_relations(manifest, profile, scenario_fingerprint(manifest))
    for assertion in manifest.assertions:
        validate_rule_source(rules[assertion.id], assertion.source)
    return manifest, profile


def validate_inputs(manifest, events, profile, context):
    manifest = _contract(manifest, ScenarioManifest, "manifest")
    profile = _contract(profile, EvaluationProfile, "profile")
    context = _contract(context, EvaluationContext, "context")
    if type(events) in (list, tuple):
        for index, event in enumerate(events):
            if type(event) is CanonicalEventV2 and "schema_version" not in event.__dict__:
                raise ValidationEngineError("invalid_input", ("events", index, "schema_version"))
            if type(event) is CanonicalEvent or (type(event) is CanonicalEventV2 and event.__dict__["schema_version"] != "2.0"):
                raise ValidationEngineError("unsupported_version", ("events", index, "schema_version"))
    events = validated_events(events)
    hashes = dict(scenario_fingerprint=scenario_fingerprint(manifest), profile_fingerprint=profile_fingerprint(profile),
                  scope_fingerprint=scope_fingerprint(context), context_fingerprint=fingerprint(context),
                  event_set_fingerprint=event_set_fingerprint(events))
    rules = _profile_relations(manifest, profile, hashes["scenario_fingerprint"])
    bindings = {binding.name: binding.value for binding in context.bindings}
    for assertion in manifest.assertions:
        rule = rules[assertion.id]
        validate_rule_source(rule, assertion.source)
        for predicate in rule.scope + rule.match:
            resolve_operand(predicate, bindings)
    for declaration in context.declarations:
        rule = rules.get(declaration.assertion_id)
        if rule is None or rule.role != "detection" or rule.capability != "supported":
            raise ValidationEngineError("invalid_collection_declaration", ("declarations",))
        for field in ("profile_fingerprint", "scope_fingerprint", "event_set_fingerprint"):
            provided = getattr(declaration, field)
            if provided is not None and provided != hashes[field]:
                raise ValidationEngineError("invalid_collection_declaration", ("declarations", field))
        if declaration.status == "complete_for_scope" and (
                declaration.coverage_start > context.start or declaration.coverage_end < context.end):
            raise ValidationEngineError("invalid_collection_declaration", ("declarations",))
    return manifest, events, profile, context, hashes
