"""Read-only scenario loading; public errors omit raw input and parser snippets."""

from dataclasses import dataclass
from pathlib import Path
import re

from pydantic import ValidationError
import yaml

from ._scenario_yaml import MAX_BYTES, YamlPolicyError, read_yaml_data
from .models import ScenarioManifest


_FIELD_NAMES = frozenset({
    "id", "name", "version", "status", "description", "safety", "destructive",
    "authorization_required", "notes", "expected_sources", "expected_outcome",
    "assertions", "tags", "source",
})


@dataclass(frozen=True)
class ScenarioDiagnostic:
    code: str
    field: tuple[str | int, ...] = ()
    line: int | None = None
    column: int | None = None


class ScenarioLoadError(ValueError):
    """Safe-to-format diagnostics; the caller still owns source-name privacy."""

    def __init__(
        self, source_name: str, scenario_id: str | None,
        diagnostics: tuple[ScenarioDiagnostic, ...],
    ):
        self.source_name = source_name
        self.scenario_id = scenario_id
        self.diagnostics = diagnostics
        label = f"{source_name} ({scenario_id})" if scenario_id else source_name
        details = []
        for issue in diagnostics:
            field = ".".join(str(part) for part in issue.field) or "<document>"
            position = f" at {issue.line}:{issue.column}" if issue.line is not None else ""
            details.append(f"{field}: {issue.code}{position}")
        super().__init__(label + ": " + "; ".join(details))


def _input_error(source_name: str, code: str) -> ScenarioLoadError:
    return ScenarioLoadError(source_name, None, (ScenarioDiagnostic(code),))


def parse_scenario_yaml(text: str, *, source_name: str) -> ScenarioManifest:
    """Validate a single manifest, without execution, inference, or file writes."""
    if not isinstance(text, str):
        raise _input_error(source_name, "input_type")
    # Avoid copying arbitrarily large strings just to encode/count them.
    if len(text) > MAX_BYTES:
        raise _input_error(source_name, "input_size")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError:
        raise _input_error(source_name, "input_encoding") from None
    if size > MAX_BYTES:
        raise _input_error(source_name, "input_size")
    if text.startswith("\ufeff"):
        text = text[1:]

    try:
        data = read_yaml_data(text)
    except YamlPolicyError as error:
        diagnostic = ScenarioDiagnostic(error.code, line=error.line, column=error.column)
        raise ScenarioLoadError(source_name, None, (diagnostic,)) from None
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        diagnostic = ScenarioDiagnostic(
            "yaml_syntax", line=mark.line + 1 if mark else None,
            column=mark.column + 1 if mark else None,
        )
        raise ScenarioLoadError(source_name, None, (diagnostic,)) from None
    except (ValueError, OverflowError, RecursionError):
        # Bad explicit numeric tags and interpreter scalar conversion limits.
        raise _input_error(source_name, "yaml_scalar") from None

    identifier = data.get("id")
    scenario_id = identifier if (
        isinstance(identifier, str) and re.fullmatch(r"SCN-[0-9]{3}", identifier)
    ) else None
    try:
        return ScenarioManifest.model_validate(data)
    except ValidationError as error:
        diagnostics = tuple(
            ScenarioDiagnostic(
                issue["type"], tuple(
                    part if isinstance(part, int) or part in _FIELD_NAMES else "<unknown>"
                    for part in issue["loc"]
                ),
            )
            for issue in error.errors(include_input=False, include_context=False, include_url=False)
        )
        raise ScenarioLoadError(source_name, scenario_id, diagnostics) from None


def load_scenario(path: str | Path) -> ScenarioManifest:
    """Read at most MAX_BYTES+1 from the caller's path; never follow YAML references."""
    source_name = str(path)
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except (OSError, ValueError):
        raise _input_error(source_name, "input_io") from None
    if len(raw) > MAX_BYTES:
        raise _input_error(source_name, "input_size")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _input_error(source_name, "input_encoding") from None
    return parse_scenario_yaml(text, source_name=source_name)
