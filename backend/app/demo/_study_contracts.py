"""Closed review declarations. They are not authenticated remote receipts."""

import json
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StrictBool, StrictInt, model_validator

from ..models import PreciseTimestamp
from ..validation.contracts import Digest, NonBlank


class StudyRunError(ValueError):
    def __init__(self):
        super().__init__('invalid_study_run')


MEASURED_WIRE_PROFILE = 'wazuh-eventchannel-4.14.4-lf-v1'


def wire_text(value: str) -> str:
    """Return the value as one measured field profile presents it after decoding.

    Scope, deliberately narrow: measured on 2026-09-17 against Wazuh 4.14.4 with
    field profile ``wazuh-eventchannel-4.14.4-lf-v1``, on ``data.win.eventdata``
    strings of Sysmon Event 1 and PowerShell 4104 (image, parentImage,
    commandLine, path). Those arrive as the JSON-escaped form of the native value.

    This is **not** a general rule about Wazuh. Another version, another decoder,
    another channel or a source field outside that object must be measured before
    this function is applied to it.

    Do not reimplement by counting backslashes: ``\\"`` carries a single
    backslash, so an "every backslash is doubled" rule rejects real command lines.

    ``ensure_ascii`` is off deliberately, but that is a scoping decision, not a
    claim: no non-ASCII value was measured, so neither the literal UTF-8 form nor
    ``\\uXXXX`` is asserted to be what Wazuh sends. ``is_wire_text`` refuses
    non-ASCII rather than pick one, and it must be measured before it is used.
    """
    return json.dumps(value, ensure_ascii=False)[1:-1]


def is_wire_text(value: str) -> bool:
    """True when the value already is a well-formed escaped representation.

    Non-ASCII is refused rather than guessed: the representation was measured on
    ASCII values only, so anything outside that range must be measured before it
    is pinned into a study. Refusing is not a statement about what Wazuh emits.
    """
    try:
        return (type(value) is str and value.isascii()
                and wire_text(json.loads('"' + value + '"')) == value)
    except (ValueError, TypeError):
        return False


class Closed(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True, hide_input_in_errors=True)


def pair(value):
    if type(value) is not list or len(value) != 2:
        raise ValueError('expected two reviewed literals')
    return tuple(value)


Pair = Annotated[tuple[NonBlank, NonBlank], BeforeValidator(pair)]


class Pins(Closed):
    scenario: Digest
    profile: Digest
    kit: Digest
    runner: Digest
    payload: Digest
    baseline: Digest
    fixed: Digest


class Target(Closed):
    environment_id: Annotated[NonBlank, Field(max_length=128)]
    hostname: Annotated[NonBlank, Field(max_length=255)]
    agent_id: Annotated[NonBlank, Field(max_length=128)]
    account: NonBlank
    elevated: StrictBool
    executable: NonBlank
    canonical_executable: NonBlank
    collection_mode: Literal['direct']
    native_directory: NonBlank
    canonical_paths: Pair
    command_lines: Pair
    rule_id: Annotated[StrictInt, Field(ge=100000, le=120000)]
    parent_sid: Annotated[StrictInt, Field(ge=1, le=999999)]
    field_profile: Literal['wazuh-eventchannel-4.14.4-lf-v1']

    @model_validator(mode='after')
    def consistent(self):
        if self.rule_id == self.parent_sid:
            raise ValueError('same parent rule')
        # Canonical values are compared against decoded EventChannel fields, so
        # they must use the representation measured for this field profile.
        # Mixing native and wire forms across one eventdata object is what made
        # SCN-001-A01 unable to match real telemetry. The rule is keyed on the
        # profile on purpose: a new profile must be measured before it inherits
        # this, rather than silently picking up a convention from another version.
        if self.field_profile != MEASURED_WIRE_PROFILE:
            raise ValueError('field profile has no measured field representation')
        for value in (self.canonical_executable, *self.canonical_paths, *self.command_lines):
            if not is_wire_text(value):
                raise ValueError('canonical values must use the measured wire representation')
        if self.canonical_executable != wire_text(self.executable):
            raise ValueError('canonical executable must be the wire form of the native executable')
        # Anchor the other two groups to the reviewed native values as well.
        # Checking only the executable would leave the fields that actually drive
        # A02/A03 matching and the payload_variant_mismatch check free-form, so a
        # canonical path pointing somewhere else entirely would still validate.
        prefix = self.native_directory + '\\'
        natives = [json.loads('"' + value + '"') for value in self.canonical_paths]
        if any(not native.startswith(prefix) or '\\' in native[len(prefix):] for native in natives):
            raise ValueError('canonical paths must sit directly in the reviewed lab directory')
        for native, command in zip(natives, self.command_lines):
            if native not in json.loads('"' + command + '"'):
                raise ValueError('each command line must reference its own reviewed payload path')
        for first, second in (self.canonical_paths, self.command_lines):
            if (first.count('lab_update.ps1') != 1 or 'maintenance_check.ps1' in first
                    or second.count('maintenance_check.ps1') != 1 or 'lab_update.ps1' in second
                    or first.replace('lab_update.ps1', 'maintenance_check.ps1') != second):
                raise ValueError('reviewed variants must differ only in filename')
        return self


class Study(Closed):
    kind: Literal['scn001_study']
    version: Literal['0.1.0']
    study_id: NonBlank
    pins: Pins
    target: Target
    collection_reference: NonBlank
    time_reference: NonBlank


class RuleReceipt(Closed):
    kind: Literal['scn001_rule_receipt']
    version: Literal['0.1.0']
    run_id: NonBlank
    study_sha256: Digest
    execution_sha256: Digest
    account: NonBlank
    elevated: StrictBool
    before_rule_sha256: Digest
    after_rule_sha256: Digest
    before_utc: PreciseTimestamp
    after_utc: PreciseTimestamp
    confirmed_by: NonBlank
    before_reference: NonBlank
    after_reference: NonBlank
