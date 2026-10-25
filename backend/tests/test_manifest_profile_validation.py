"""Catalog compatibility checks do not need run context or evidence."""
import pytest

from aegis_verify.validation import _inputs
from aegis_verify.validation.errors import ValidationEngineError
from test_validation_boundaries import inputs


def structural(manifest, profile):
    validator = getattr(_inputs, "validate_manifest_profile", None)
    assert validator is not None, "reusable structural compatibility validation is missing"
    return validator(manifest, profile)


def test_structural_validation_accepts_runtime_binding_without_resolving_it():
    manifest, _, profile, _ = inputs()
    checked_manifest, checked_profile = structural(manifest, profile)
    assert checked_manifest.id == "SCN-999"
    assert checked_profile.rules[0].scope[0].binding == "target"


@pytest.mark.parametrize("change,code", [
    ({"scenario_fingerprint": "0" * 64}, "profile_binding"),
    ({"rules": ()}, "invalid_input"),
])
def test_structural_validation_preserves_engine_rejections(change, code):
    manifest, _, profile, _ = inputs()
    with pytest.raises(ValidationEngineError) as caught:
        structural(manifest, profile.model_copy(update=change))
    assert caught.value.code == code
