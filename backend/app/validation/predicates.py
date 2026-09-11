"""Exact, three-valued predicates over canonical events only."""
from enum import StrEnum
from .contracts import validate_scalar
from .errors import ValidationEngineError


class Truth(StrEnum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


def all_of(values):
    unknown = False
    for value in values:
        if value is Truth.FALSE:
            return Truth.FALSE
        unknown |= value is Truth.UNKNOWN
    return Truth.UNKNOWN if unknown else Truth.TRUE


def resolve_operand(predicate, bindings):
    if predicate.op == "exists":
        return None
    if predicate.binding is not None:
        if predicate.binding not in bindings:
            raise ValidationEngineError("missing_binding", ("bindings",))
        value = bindings[predicate.binding]
    else:
        value = predicate.values if predicate.op == "in" else predicate.value
    try:
        if predicate.op == "in":
            if type(value) is not tuple or not 1 <= len(value) <= 100:
                raise ValueError
            return tuple(validate_scalar(predicate.field, item) for item in value)
        return validate_scalar(predicate.field, value)
    except (TypeError, ValueError, UnicodeError):
        raise ValidationEngineError("invalid_predicate", ("bindings",)) from None


def evaluate_conditions(event, conditions, bindings):
    outcomes = []
    for predicate in conditions:
        operand = resolve_operand(predicate, bindings)
        actual = getattr(event, predicate.field)
        if predicate.op == "exists":
            outcomes.append(Truth.FALSE if actual is None else Truth.TRUE)
        elif actual is None:
            outcomes.append(Truth.UNKNOWN)
        else:
            matched = (operand in actual if predicate.op == "contains" else
                       actual in operand if predicate.op == "in" else actual == operand)
            outcomes.append(Truth.TRUE if matched else Truth.FALSE)
    return all_of(outcomes)


def evaluate_joins(target, anchor, pairs):
    outcomes = []
    for pair in pairs:
        left, right = getattr(target, pair.target_field), getattr(anchor, pair.anchor_field)
        outcomes.append(Truth.UNKNOWN if left is None or right is None else
                        Truth.TRUE if left == right else Truth.FALSE)
    return all_of(outcomes)
