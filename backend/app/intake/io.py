"""Strict JSON decoding and bounded, local-only filesystem reads."""

import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import unicodedata

from .errors import IntakeError


MAX_CONFIG_BYTES = 1024 * 1024
MAX_CONFIG_DEPTH = 32
MAX_CONFIG_NODES = 50_000
MAX_INTEGER_CHARS = 128

_UTF8_BOM = b"\xef\xbb\xbf"
_DOS_DEVICE = re.compile(
    r"(?:CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(?:\..*)?",
    re.IGNORECASE,
)
_WINDOWS_DRIVE_ABSOLUTE = re.compile(r"^[A-Za-z]:/")
_GLOB_CHARS = frozenset("*?[]")
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _error(code: str, stage: str) -> IntakeError:
    return IntakeError(code, stage=stage)


def unique_object(pairs):
    """Build a JSON object while rejecting duplicate keys."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntakeError("invalid_json")
        result[key] = value
    return result


def _integer(token: str) -> int:
    if len(token) > MAX_INTEGER_CHARS:
        raise IntakeError("invalid_number")
    return int(token)


def _unsupported_number(_token: str):
    raise IntakeError("invalid_number")


def _preflight_depth(text: str, *, stage: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_CONFIG_DEPTH:
                raise _error("input_too_deep", stage)
        elif character in "]}":
            depth -= 1


def _validate_tree(data: dict, *, stage: str) -> None:
    nodes = 0
    stack: list[object] = [data]
    while stack:
        value = stack.pop()
        nodes += 1
        if nodes > MAX_CONFIG_NODES:
            raise _error("resource_limit", stage)
        if type(value) is str:
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                raise _error("invalid_json", stage) from None
        elif type(value) is dict:
            for key, item in value.items():
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError:
                    raise _error("invalid_json", stage) from None
                stack.append(item)
        elif type(value) is list:
            stack.extend(value)


def decode_config(raw: bytes, *, stage: str) -> dict:
    """Decode one bounded UTF-8 JSON object without permissive number handling."""
    if type(raw) is not bytes:
        raise _error("invalid_json", stage)
    if len(raw) > MAX_CONFIG_BYTES:
        raise _error("input_too_large", stage)
    if raw.startswith(_UTF8_BOM):
        raw = raw[len(_UTF8_BOM):]
    try:
        text = raw.decode("utf-8")
        _preflight_depth(text, stage=stage)
        data = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_int=_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except IntakeError as error:
        raise _error(error.code, stage) from None
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError, OverflowError):
        raise _error("invalid_json", stage) from None
    if type(data) is not dict:
        raise _error("invalid_json", stage)
    _validate_tree(data, stage=stage)
    return data


def _unsafe_component(component: str) -> bool:
    if not component or component.endswith((".", " ")):
        return True
    if component not in {".", ".."} and _DOS_DEVICE.fullmatch(component):
        return True
    if any(character in _GLOB_CHARS for character in component):
        return True
    return any(unicodedata.category(character) == "Cc" for character in component)


def _path_text(path: str | Path, *, stage: str) -> str:
    if not isinstance(path, (str, Path)):
        raise _error("invalid_path", stage)
    raw = os.fspath(path)
    if not raw:
        raise _error("invalid_path", stage)
    normalized = raw.replace("\\", "/")
    if normalized.startswith("//"):
        raise _error("invalid_path", stage)

    windows_path = PureWindowsPath(raw)
    has_drive = bool(windows_path.drive)
    has_absolute_drive = bool(_WINDOWS_DRIVE_ABSOLUTE.match(normalized))
    if has_drive and not has_absolute_drive:
        raise _error("invalid_path", stage)
    colon_start = 2 if has_absolute_drive else 0
    if ":" in normalized[colon_start:]:
        raise _error("invalid_path", stage)
    if os.name == "nt" and normalized.startswith("/") and not has_absolute_drive:
        raise _error("invalid_path", stage)

    component_text = normalized[3:] if has_absolute_drive else normalized.lstrip("/")
    components = component_text.split("/") if component_text else ()
    if any(_unsafe_component(component) for component in components):
        raise _error("invalid_path", stage)
    return raw


def _is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    )


def _checked_lstat(path: Path, *, stage: str) -> os.stat_result:
    try:
        info = path.lstat()
    except (OSError, ValueError):
        raise _error("input_io", stage) from None
    if _is_reparse(info):
        raise _error("invalid_path", stage)
    return info


def _check_ancestors(path: Path, *, stage: str) -> os.stat_result:
    current = Path(path.anchor)
    final_info = None
    for component in path.parts[1:]:
        current /= component
        final_info = _checked_lstat(current, stage=stage)
    if final_info is None:
        final_info = _checked_lstat(path, stage=stage)
    return final_info


def local_path(
    path: str | Path, *, directory: bool = False, stage: str = "inputs"
) -> Path:
    """Resolve an existing local path after rejecting aliases and reparse points."""
    raw = _path_text(path, stage=stage)
    if type(directory) is not bool:
        raise _error("invalid_input", stage)
    try:
        absolute = Path(os.path.abspath(raw))
    except (OSError, ValueError):
        raise _error("invalid_path", stage) from None
    info = _check_ancestors(absolute, stage=stage)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(info.st_mode):
        raise _error("invalid_path", stage)
    try:
        resolved = absolute.resolve(strict=True)
    except (OSError, ValueError):
        raise _error("input_io", stage) from None
    resolved_info = _check_ancestors(resolved, stage=stage)
    if not expected_type(resolved_info.st_mode):
        raise _error("invalid_path", stage)
    return resolved


def _bundle_relative(relative: str | Path, *, stage: str) -> str:
    if not isinstance(relative, (str, Path)):
        raise _error("invalid_path", stage)
    raw = os.fspath(relative)
    if not raw or "\\" in raw or raw.startswith("/"):
        raise _error("invalid_path", stage)
    if PureWindowsPath(raw).drive or ":" in raw:
        raise _error("invalid_path", stage)
    components = raw.split("/")
    if any(component in {"", ".", ".."} or _unsafe_component(component) for component in components):
        raise _error("invalid_path", stage)
    return raw


def bundle_path(root: Path, relative: str | Path) -> Path:
    """Return one existing regular bundle file proven to stay under its root."""
    safe_relative = _bundle_relative(relative, stage="inputs")
    safe_root = local_path(root, directory=True, stage="inputs")
    selected = local_path(safe_root / Path(*safe_relative.split("/")), stage="evidence")
    try:
        selected.relative_to(safe_root)
    except ValueError:
        raise _error("invalid_path", "inputs") from None
    return selected


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _same_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return _same_identity(left, right) and (
        left.st_size,
        getattr(left, "st_mtime_ns", int(left.st_mtime * 1_000_000_000)),
    ) == (
        right.st_size,
        getattr(right, "st_mtime_ns", int(right.st_mtime * 1_000_000_000)),
    )


def read_local(path: str | Path, *, limit: int, stage: str) -> bytes:
    """Read exact bytes once from a stable, bounded local regular file."""
    if type(limit) is not int or limit < 0:
        raise _error("resource_limit", stage)
    selected = local_path(path, stage=stage)
    before = _checked_lstat(selected, stage=stage)
    if not stat.S_ISREG(before.st_mode):
        raise _error("invalid_path", stage)
    if before.st_size > limit:
        raise _error("input_too_large", stage)

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(selected, flags)
        opened = os.fstat(descriptor)
        if _is_reparse(opened) or not stat.S_ISREG(opened.st_mode):
            raise _error("invalid_path", stage)
        if not _same_snapshot(before, opened):
            raise _error("input_io", stage)
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = None
            raw = stream.read(limit + 1)
            after_read = os.fstat(stream.fileno())
    except IntakeError:
        raise
    except (OSError, ValueError, OverflowError):
        raise _error("input_io", stage) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    if len(raw) > limit:
        raise _error("input_too_large", stage)
    after_path = _checked_lstat(selected, stage=stage)
    if not _same_snapshot(opened, after_read) or not _same_snapshot(after_read, after_path):
        raise _error("input_io", stage)
    _check_ancestors(selected, stage=stage)
    return raw
