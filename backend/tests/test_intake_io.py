from dataclasses import FrozenInstanceError
from contextlib import contextmanager
import os
from pathlib import Path

import pytest


def test_intake_error_exposes_only_allowlisted_diagnostics():
    from aegis_verify.intake.errors import IntakeError

    error = IntakeError(
        "invalid_json", stage="profile", file_index=2, field="files", line=7
    )

    assert error.code == "invalid_json"
    assert error.stage == "profile"
    assert error.file_index == 2
    assert error.field == "files"
    assert error.line == 7
    assert error.hint
    assert "invalid_json" in str(error)


def test_intake_error_sanitizes_unknown_diagnostic_values():
    from aegis_verify.intake.errors import IntakeError

    secret = "private-source-value"
    error = IntakeError(secret, stage=secret, file_index=-1, field=secret, line=False)

    assert error.code == "invalid_input"
    assert error.stage == "inputs"
    assert error.file_index is None
    assert error.field is None
    assert error.line is None
    assert secret not in str(error)
    assert secret not in error.hint


def test_intake_error_is_frozen():
    from aegis_verify.intake.errors import IntakeError

    error = IntakeError("invalid_json")

    with pytest.raises(FrozenInstanceError):
        error.code = "input_io"


def test_intake_error_allows_python_to_attach_traceback_state():
    from aegis_verify.intake.errors import IntakeError

    @contextmanager
    def passthrough():
        yield

    with pytest.raises(IntakeError):
        with passthrough():
            raise IntakeError("invalid_json")


def test_duplicate_keys_never_select_last_value():
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import decode_config

    with pytest.raises(IntakeError) as caught:
        decode_config(b'{"files":[],"files":["private-value"]}', stage="inputs")
    assert caught.value.code == "invalid_json"
    assert "private-value" not in str(caught.value)


def test_decode_config_accepts_one_bom_and_unicode_object():
    from aegis_verify.intake.io import decode_config

    data = decode_config(
        b"\xef\xbb\xbf" + '{"name":"Nh\u1eadt k\u00fd"}'.encode(), stage="profile"
    )

    assert data == {"name": "Nh\u1eadt k\u00fd"}


@pytest.mark.parametrize("raw", [b"null", b"[]", b'"value"', b"true", b"1"])
def test_decode_config_requires_an_object(raw):
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import decode_config

    with pytest.raises(IntakeError) as caught:
        decode_config(raw, stage="context")

    assert caught.value.code == "invalid_json"
    assert caught.value.stage == "context"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"value":1.0}',
        b'{"value":1e2}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
    ],
)
def test_decode_config_rejects_floating_and_non_finite_numbers(raw):
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import decode_config

    with pytest.raises(IntakeError) as caught:
        decode_config(raw, stage="inputs")

    assert caught.value.code == "invalid_number"


def test_decode_config_enforces_integer_token_limit():
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import decode_config

    accepted = b'{"value":' + (b"9" * 128) + b"}"
    rejected = b'{"value":' + (b"9" * 129) + b"}"

    assert decode_config(accepted, stage="inputs")["value"] == int(b"9" * 128)
    with pytest.raises(IntakeError) as caught:
        decode_config(rejected, stage="inputs")
    assert caught.value.code == "invalid_number"


def test_decode_config_enforces_container_depth_limit():
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import decode_config

    accepted = b'{"value":' + (b"[" * 31) + b"0" + (b"]" * 31) + b"}"
    rejected = b'{"value":' + (b"[" * 32) + b"0" + (b"]" * 32) + b"}"

    assert decode_config(accepted, stage="inputs")["value"]
    with pytest.raises(IntakeError) as caught:
        decode_config(rejected, stage="inputs")
    assert caught.value.code == "input_too_deep"


def test_decode_config_enforces_structural_node_limit():
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import decode_config

    accepted = b'{"items":[' + (b"0," * 49_997) + b"0]}"
    rejected = b'{"items":[' + (b"0," * 49_998) + b"0]}"

    assert len(decode_config(accepted, stage="inputs")["items"]) == 49_998
    with pytest.raises(IntakeError) as caught:
        decode_config(rejected, stage="inputs")
    assert caught.value.code == "resource_limit"


def test_decode_config_enforces_byte_limit_before_parsing():
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import MAX_CONFIG_BYTES, decode_config

    raw = b'{"value":"' + (b"x" * MAX_CONFIG_BYTES) + b'"}'

    with pytest.raises(IntakeError) as caught:
        decode_config(raw, stage="inputs")
    assert caught.value.code == "input_too_large"


@pytest.mark.parametrize("raw", [b"{", b"\xff", b"\xef\xbb\xbf\xef\xbb\xbf{}", b'{"x":"\\ud800"}'])
def test_decode_config_rejects_invalid_json_encoding_or_surrogates(raw):
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import decode_config

    with pytest.raises(IntakeError) as caught:
        decode_config(raw, stage="inputs")

    assert caught.value.code == "invalid_json"


def test_decode_config_rejects_non_bytes_without_echoing_value():
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import decode_config

    with pytest.raises(IntakeError) as caught:
        decode_config("private-value", stage="inputs")

    assert caught.value.code == "invalid_json"
    assert "private-value" not in str(caught.value)


def test_bundle_path_cannot_leave_root(tmp_path):
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import bundle_path

    with pytest.raises(IntakeError):
        bundle_path(tmp_path, "../outside.json")


@pytest.mark.parametrize(
    "relative",
    [
        "",
        ".",
        "./event.json",
        "folder//event.json",
        "/event.json",
        "C:/event.json",
        "C:event.json",
        "\\\\server\\share\\event.json",
        "folder\\event.json",
        "folder/event.json:stream",
        "https://example.invalid/event.json",
        "*.json",
        "event?.json",
        "event[0].json",
        "event\x00.json",
        "event\x1f.json",
        "event.json.",
        "event.json ",
        "CON",
        "nul.json",
        "COM1.log",
        "LPT\u00b2.txt",
    ],
)
def test_bundle_path_rejects_ambiguous_or_unsafe_names(tmp_path, relative):
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import bundle_path

    with pytest.raises(IntakeError) as caught:
        bundle_path(tmp_path, relative)

    assert caught.value.code == "invalid_path"


def test_bundle_path_accepts_existing_unicode_and_space_components(tmp_path):
    from aegis_verify.intake.io import bundle_path

    directory = tmp_path / "nh\u1eadt k\u00fd"
    directory.mkdir()
    evidence = directory / "event log.json"
    evidence.write_bytes(b"{}")

    assert bundle_path(tmp_path, "nh\u1eadt k\u00fd/event log.json") == evidence.resolve()


def test_local_path_accepts_explicit_relative_file(tmp_path, monkeypatch):
    from aegis_verify.intake.io import local_path

    monkeypatch.chdir(tmp_path)
    selected = Path("profile file.json")
    selected.write_bytes(b"{}")

    assert local_path(selected, stage="profile") == selected.resolve()


def test_local_path_accepts_an_explicit_absolute_root_directory(tmp_path):
    from aegis_verify.intake.io import local_path

    root = Path(tmp_path.anchor)

    assert local_path(root, directory=True, stage="inputs") == root.resolve()


@pytest.mark.parametrize(
    "path",
    [
        "https://example.invalid/config.json",
        "\\\\server\\share\\config.json",
        "\\\\?\\C:\\config.json",
        "\\\\.\\PhysicalDrive0",
        "C:config.json",
        "config.json:stream",
        "*.json",
        "NUL.txt",
    ],
)
def test_local_path_rejects_non_local_or_ambiguous_paths(path):
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import local_path

    with pytest.raises(IntakeError) as caught:
        local_path(path, stage="profile")

    assert caught.value.code == "invalid_path"
    assert caught.value.stage == "profile"
    assert path not in str(caught.value)


def test_local_path_rejects_missing_and_wrong_file_types(tmp_path):
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import local_path

    with pytest.raises(IntakeError) as missing:
        local_path(tmp_path / "missing.json", stage="context")
    assert missing.value.code == "input_io"

    with pytest.raises(IntakeError) as directory:
        local_path(tmp_path, stage="context")
    assert directory.value.code == "invalid_path"

    regular = tmp_path / "regular.json"
    regular.write_bytes(b"{}")
    with pytest.raises(IntakeError) as file_as_directory:
        local_path(regular, directory=True, stage="inputs")
    assert file_as_directory.value.code == "invalid_path"


def test_local_path_rejects_symlink_component_when_supported(tmp_path):
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import local_path

    target = tmp_path / "target"
    target.mkdir()
    (target / "event.json").write_bytes(b"{}")
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable on this platform")

    with pytest.raises(IntakeError) as caught:
        local_path(link / "event.json", stage="evidence")
    assert caught.value.code == "invalid_path"


def test_read_local_returns_exact_bytes_at_limit(tmp_path):
    from aegis_verify.intake.io import read_local

    selected = tmp_path / "evidence.bin"
    selected.write_bytes(b"a\r\nb\x00")

    assert read_local(selected, limit=5, stage="evidence") == b"a\r\nb\x00"


def test_read_local_rejects_one_byte_over_limit(tmp_path):
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import read_local

    selected = tmp_path / "evidence.bin"
    selected.write_bytes(b"123456")

    with pytest.raises(IntakeError) as caught:
        read_local(selected, limit=5, stage="evidence")
    assert caught.value.code == "input_too_large"


def test_read_local_normalizes_open_failure_without_path_or_os_message(tmp_path, monkeypatch):
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake import io

    selected = tmp_path / "private-name.json"
    selected.write_bytes(b"{}")

    def denied(*args, **kwargs):
        raise PermissionError("private operating-system detail")

    monkeypatch.setattr(io.os, "open", denied)
    with pytest.raises(IntakeError) as caught:
        io.read_local(selected, limit=16, stage="profile")
    assert caught.value.code == "input_io"
    assert "private" not in str(caught.value)


def test_read_local_accepts_a_single_regular_hardlink_when_supported(tmp_path):
    from aegis_verify.intake.io import read_local

    original = tmp_path / "original.json"
    alias = tmp_path / "alias.json"
    original.write_bytes(b'{"kind":"test-only"}')
    try:
        os.link(original, alias)
    except (NotImplementedError, OSError):
        pytest.skip("hardlinks are unavailable on this platform")

    assert read_local(alias, limit=64, stage="evidence") == b'{"kind":"test-only"}'


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO is unavailable on this platform")
def test_read_local_rejects_fifo_without_opening_it(tmp_path):
    from aegis_verify.intake.errors import IntakeError
    from aegis_verify.intake.io import read_local

    fifo = tmp_path / "events.pipe"
    os.mkfifo(fifo)

    with pytest.raises(IntakeError) as caught:
        read_local(fifo, limit=64, stage="evidence")
    assert caught.value.code == "invalid_path"
