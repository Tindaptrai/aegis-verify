"""Read-only Manager shell and shared, dependency-free public-build validation.

The build directory is trusted, administrator-controlled and read-only at runtime.
Validation never executes build content or reads asset bytes in the HTTP handler.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
import stat

MAX_ASSET_BYTES = 4 * 1024 * 1024
MAX_BUILD_BYTES = 8 * 1024 * 1024
MAX_HTML_BYTES = 64 * 1024
MAX_ASSETS = 128
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.(?:js|css|png|svg|webp|jpg|jpeg|ico|woff2?)\Z")
ASSET_PREFIX = "/static/manager/assets/"


def checked_path(value):
    """Reject redirected roots and ancestors, including Windows junctions."""
    path = Path(value).absolute()
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("manager_ui_unavailable")
        # Python 3.11 lacks is_junction. Inspect reparse metadata rather than
        # comparing resolved spellings: valid Windows 8.3 names also expand.
        try:
            attributes = getattr(part.lstat(), "st_file_attributes", 0)
        except FileNotFoundError:
            continue
        if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ValueError("manager_ui_unavailable")
    if ".." in path.parts:
        raise ValueError("manager_ui_unavailable")
    return path


class _References(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references = []
        self.script = False

    def handle_starttag(self, tag, attrs):
        if len({key for key, _ in attrs}) != len(attrs):
            raise ValueError("manager_ui_unavailable")
        attrs = dict(attrs)
        if tag == "base" or "srcset" in attrs or (tag == "script" and not attrs.get("src")):
            raise ValueError("manager_ui_unavailable")
        for key in ("src", "href"):
            if key in attrs:
                value = attrs[key] or ""
                name = value.removeprefix(ASSET_PREFIX)
                if not value.startswith(ASSET_PREFIX) or not ASSET_NAME.fullmatch(name):
                    raise ValueError("manager_ui_unavailable")
                self.references.append(name)
                if tag == "script" and key == "src" and name.endswith(".js"):
                    self.script = True


def validate_public_build(value):
    """Return the UTF-8 entry and flat public assets, or fail closed.

    Manager output must never be merged with the core dashboard distribution.
    Unknown files, source maps, private formats and nested directories are invalid.
    """
    if value is None:
        raise ValueError("manager_ui_unavailable")
    root = checked_path(value)
    if not root.is_dir() or {p.name for p in root.iterdir()} != {"manager.html", "assets"}:
        raise ValueError("manager_ui_unavailable")
    entry, assets = checked_path(root / "manager.html"), checked_path(root / "assets")
    if not entry.is_file() or not assets.is_dir() or entry.stat().st_size > MAX_HTML_BYTES:
        raise ValueError("manager_ui_unavailable")
    paths = {}
    size = entry.stat().st_size
    for child in assets.iterdir():
        child = checked_path(child)
        if not child.is_file() or not ASSET_NAME.fullmatch(child.name):
            raise ValueError("manager_ui_unavailable")
        length = child.stat().st_size
        if length > MAX_ASSET_BYTES:
            raise ValueError("manager_ui_unavailable")
        size += length
        paths[child.name] = child
        if len(paths) > MAX_ASSETS or size > MAX_BUILD_BYTES:
            raise ValueError("manager_ui_unavailable")
    html = entry.read_bytes().decode("utf-8")
    parser = _References()
    parser.feed(html)
    parser.close()
    if not parser.script or not set(parser.references).issubset(paths):
        raise ValueError("manager_ui_unavailable")
    return html, paths


def manager_shell(request):
    from django.conf import settings
    from django.http import HttpResponse, HttpResponseNotAllowed, JsonResponse

    if request.method not in ("GET", "HEAD"):
        response = HttpResponseNotAllowed(["GET", "HEAD"])
    else:
        try:
            html, _ = validate_public_build(getattr(settings, "MANAGER_UI_ROOT", None))
            response = HttpResponse(html, content_type="text/html; charset=utf-8")
        except (OSError, ValueError, TypeError):
            response = JsonResponse({"error": {"code": "manager_ui_unavailable"}}, status=503)
    response["Cache-Control"] = "no-store"
    return response
